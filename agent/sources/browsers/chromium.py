"""Chromium-family readers.

Every database is copied out of the live profile before it is opened. A running
browser holds a lock on the original and keeps the newest rows in a ``-wal``
sidecar, so the copy carries the sidecars with it and the copy is what gets read.

Key material has two sources and they are not interchangeable:

- ``os_crypt.encrypted_key`` in ``Local State`` is base64 with a ``DPAPI`` prefix.
  Strip the prefix, unwrap under the current user, and the result is the AES-256 key
  for ``v10`` and ``v11`` rows.
- ``os_crypt.app_bound_encrypted_key`` is base64 with an ``APPB`` prefix and is
  wrapped under SYSTEM. Chrome 133+ writes ``v20`` rows against it. The unwrap has to
  leave the process, which is what ``abe.unwrap`` is for.

Row decryption is AES-256-GCM: 12-byte nonce, then ciphertext, then a 16-byte tag.
The per-row binding Chrome adds for cookies is the 32-byte SHA-256 of the row's
``host_key``, carried as a prefix of the plaintext rather than as a GCM AAD — the
cipher itself uses no AAD, so passing one here would fail every tag check. That
prefix is verified and stripped after the tag passes, and a row without it is an
older row and is returned as-is.

DPAPI rows still exist on machines upgraded from an older build, so a failed GCM
open falls back to a DPAPI unwrap of the same payload before the row is dropped.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Final, NamedTuple

from ... import abe, log, util, winapi

_PREFIX_V10: Final[bytes] = b"v10"
_PREFIX_V11: Final[bytes] = b"v11"
_PREFIX_V20: Final[bytes] = b"v20"
_DPAPI_PREFIX: Final[bytes] = b"DPAPI"
_APP_BOUND_PREFIX: Final[bytes] = b"APPB"

_NONCE_SIZE: Final[int] = 12
_TAG_SIZE: Final[int] = 16
_KEY_BYTES: Final[int] = 32

_MAX_PASSWORDS: Final[int] = 2000
_MAX_COOKIES: Final[int] = 5000
_MAX_HISTORY: Final[int] = 2000
_MAX_DOWNLOADS: Final[int] = 1000
_MAX_BOOKMARKS: Final[int] = 2000
_MAX_BOOKMARK_DEPTH: Final[int] = 8

_WANTED_PASSWORDS: Final[tuple[str, ...]] = (
    "origin_url",
    "signon_realm",
    "username_value",
    "password_value",
    "date_created",
    "date_last_used",
    "times_used",
)

_WANTED_COOKIES: Final[tuple[str, ...]] = (
    "host_key",
    "name",
    "value",
    "encrypted_value",
    "path",
    "expires_utc",
    "last_access_utc",
    "is_secure",
    "is_httponly",
    "samesite",
)

_WANTED_HISTORY: Final[tuple[str, ...]] = (
    "url",
    "title",
    "visit_count",
    "typed_count",
    "last_visit_time",
)

_WANTED_DOWNLOADS: Final[tuple[str, ...]] = (
    "target_path",
    "tab_url",
    "total_bytes",
    "start_time",
    "state",
)


class Keys(NamedTuple):
    """The two AES keys a profile can have. Either may be absent."""

    user: bytes | None
    app_bound: bytes | None


# One unwrap per ``Local State`` per process. The app-bound key is per user, not per
# profile, and the unwrap is a scheduled-task round trip: without this, twelve
# profiles mean twelve launches, and a failing unwrap costs its full timeout twelve
# times over. A None result is cached too, for exactly that reason.
_APP_BOUND_CACHE: Final[dict[str, bytes | None]] = {}


# --- key material -------------------------------------------------------------


def _local_state(profile: Path) -> tuple[Path, dict[str, Any]] | None:
    """``Local State`` beside the profile, then inside it (Opera's layout)."""
    for candidate in (profile / "Local State", profile.parent / "Local State"):
        if not candidate.is_file():
            continue
        data = util.read_json(candidate)
        if isinstance(data, dict):
            return candidate, data
    return None


def _b64(text: str) -> bytes | None:
    try:
        return base64.b64decode(text, validate=False)
    except (ValueError, TypeError):
        return None


def _user_key(crypt: dict[str, Any]) -> bytes | None:
    if "encrypted_key" not in crypt:
        return None
    text = crypt["encrypted_key"]
    if not isinstance(text, str):
        return None
    raw = _b64(text)
    if raw is None:
        return None
    blob = abe.strip_prefix(raw, _DPAPI_PREFIX)
    if blob is None:
        return None
    key = winapi.crypt_unprotect(blob)
    if key is None or len(key) != _KEY_BYTES:
        return None
    return key


def _app_bound_key(crypt: dict[str, Any], cache_key: str) -> bytes | None:
    if cache_key in _APP_BOUND_CACHE:
        return _APP_BOUND_CACHE[cache_key]

    key: bytes | None = None
    if "app_bound_encrypted_key" in crypt:
        text = crypt["app_bound_encrypted_key"]
        if isinstance(text, str):
            raw = _b64(text)
            if raw is not None:
                blob = abe.strip_prefix(raw, _APP_BOUND_PREFIX)
                if blob is not None:
                    key = abe.unwrap(blob)

    _APP_BOUND_CACHE[cache_key] = key
    return key


def profile_keys(profile: Path) -> Keys:
    """Both keys for a profile. Absent keys stay None; a broken state is no keys."""
    found = _local_state(profile)
    if found is None:
        return Keys(user=None, app_bound=None)

    state_path, state = found

    try:
        crypt = state["os_crypt"]
    except (KeyError, TypeError):
        return Keys(user=None, app_bound=None)
    if not isinstance(crypt, dict):
        return Keys(user=None, app_bound=None)

    return Keys(
        user=_user_key(crypt),
        app_bound=_app_bound_key(crypt, str(state_path)),
    )


# --- row decryption -----------------------------------------------------------


def _aes_gcm(key: bytes, payload: bytes) -> bytes | None:
    # Imported here so this module stays importable without pycryptodome, which is
    # what the Linux import test needs.
    from Crypto.Cipher import AES

    nonce = payload[:_NONCE_SIZE]
    tag = payload[-_TAG_SIZE:]
    ciphertext = payload[_NONCE_SIZE:-_TAG_SIZE]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return None


def decrypt_value(encrypted_value: bytes, key: bytes | None, aad: bytes = b"") -> bytes | None:
    """Plaintext for one encrypted row, or None.

    ``aad`` is the per-row binding, not a GCM associated-data argument: Chrome
    prefixes the cookie plaintext with ``SHA256(host_key)`` and uses no AAD, so the
    value is verified and stripped after the tag check instead of being fed to the
    cipher. Passwords pass ``b""``.
    """
    if not encrypted_value:
        return None

    if encrypted_value[:3] in (_PREFIX_V10, _PREFIX_V11, _PREFIX_V20):
        payload = encrypted_value[3:]
    else:
        payload = encrypted_value

    if len(payload) < _NONCE_SIZE + _TAG_SIZE:
        return winapi.crypt_unprotect(payload)

    plaintext: bytes | None = None
    if key is not None:
        plaintext = _aes_gcm(key, payload)
    if plaintext is None:
        plaintext = winapi.crypt_unprotect(payload)
    if plaintext is None:
        return None

    if aad:
        if plaintext.startswith(aad):
            return plaintext[len(aad):]
        # Rows written before the host-key binding existed carry no prefix.
        return plaintext
    return plaintext


def secret_value(blob: Any, keys: Keys, aad: bytes) -> bytes | None:
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return None
    raw = bytes(blob)
    key = keys.app_bound if raw[:3] == _PREFIX_V20 else keys.user
    return decrypt_value(raw, key, aad)


# --- database access ----------------------------------------------------------


def copy_database(source: Path, scratch: Path) -> Path | None:
    """Copy a live database and its WAL siblings into ``scratch``."""
    target = scratch / source.name
    if not util.copy_with_sidecars(source, target):
        return None
    return target


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        log.logger.debug("chromium: table_info failed for %s", table, exc_info=True)
        return set()
    return {str(row[1]) for row in rows}


def read_table(
    path: Path,
    table: str,
    wanted: tuple[str, ...],
    limit: int,
    order: str = "",
) -> list[dict[str, Any]]:
    """Rows as dicts, with absent columns projected as NULL.

    Every wanted name is present in every returned row, so callers index directly.
    Chrome adds and removes columns between releases, and a missing one must cost
    that field, not the whole table.
    """
    try:
        connection = sqlite3.connect(str(path))
    except sqlite3.Error:
        log.logger.debug("chromium: cannot open %s", path, exc_info=True)
        return []

    try:
        available = _columns(connection, table)
        if not available:
            return []

        projection = ", ".join(
            name if name in available else f"NULL AS {name}" for name in wanted
        )
        statement = f"SELECT {projection} FROM {table}"
        if order:
            # Ordering on a column that does not exist fails the whole query, and
            # the projection above cannot rescue it. Order only when it is real.
            column = order.split(" ", 1)[0]
            if column in available:
                statement += f" ORDER BY {order}"
        statement += f" LIMIT {int(limit)}"

        cursor = connection.execute(statement)
        names = [str(column[0]) for column in cursor.description or ()]

        rows: list[dict[str, Any]] = []
        for row in cursor:
            rows.append({names[index]: row[index] for index in range(len(names))})
            if len(rows) >= limit:
                break
        return rows
    except sqlite3.Error:
        log.logger.debug("chromium: query failed on %s", path, exc_info=True)
        return []
    finally:
        connection.close()


def text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return ""


def int_value(value: Any) -> int:
    if isinstance(value, int):
        return int(value)
    return 0


def _first_existing(profile: Path, relatives: tuple[str, ...]) -> Path | None:
    for relative in relatives:
        candidate = profile / relative
        if candidate.is_file():
            return candidate
    return None


# --- artifacts ----------------------------------------------------------------


def _passwords(profile: Path, scratch: Path, target: Path, keys: Keys) -> int:
    source = profile / "Login Data"
    if not source.is_file():
        return 0
    copy = copy_database(source, scratch)
    if copy is None:
        return 0

    rows = read_table(copy, "logins", _WANTED_PASSWORDS, _MAX_PASSWORDS, "date_last_used DESC")
    entries: list[dict[str, Any]] = []

    for row in rows:
        secret = secret_value(row["password_value"], keys, b"")
        if secret is None:
            continue
        username = text_value(row["username_value"])
        password = secret.decode("utf-8", "replace")
        if not username and not password:
            continue
        entries.append(
            {
                "origin": text_value(row["origin_url"]),
                "realm": text_value(row["signon_realm"]),
                "username": username,
                "password": password,
                "created": util.chrome_time(int_value(row["date_created"])),
                "last_used": util.chrome_time(int_value(row["date_last_used"])),
                "times_used": int_value(row["times_used"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "passwords.json", entries):
        return 0
    return len(entries)


def _cookies(profile: Path, scratch: Path, target: Path, keys: Keys) -> int:
    source = _first_existing(profile, ("Network/Cookies", "Cookies"))
    if source is None:
        return 0
    copy = copy_database(source, scratch)
    if copy is None:
        return 0

    rows = read_table(copy, "cookies", _WANTED_COOKIES, _MAX_COOKIES, "last_access_utc DESC")
    entries: list[dict[str, Any]] = []

    for row in rows:
        host = text_value(row["host_key"])
        binding = hashlib.sha256(host.encode("utf-8")).digest()
        secret = secret_value(row["encrypted_value"], keys, binding)

        if secret is None:
            value = text_value(row["value"])
            if not value:
                continue
        else:
            value = secret.decode("utf-8", "replace")

        entries.append(
            {
                "host": host,
                "name": text_value(row["name"]),
                "value": value,
                "path": text_value(row["path"]),
                "expires": util.chrome_time(int_value(row["expires_utc"])),
                "secure": bool(int_value(row["is_secure"])),
                "http_only": bool(int_value(row["is_httponly"])),
                "samesite": int_value(row["samesite"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "cookies.json", entries):
        return 0
    return len(entries)


def _history(profile: Path, scratch: Path, target: Path) -> int:
    source = profile / "History"
    if not source.is_file():
        return 0
    copy = copy_database(source, scratch)
    if copy is None:
        return 0

    rows = read_table(copy, "urls", _WANTED_HISTORY, _MAX_HISTORY, "last_visit_time DESC")
    entries: list[dict[str, Any]] = []

    for row in rows:
        url = text_value(row["url"])
        if not url:
            continue
        entries.append(
            {
                "url": url,
                "title": text_value(row["title"]),
                "visits": int_value(row["visit_count"]),
                "typed": int_value(row["typed_count"]),
                "last_visit": util.chrome_time(int_value(row["last_visit_time"])),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "history.json", entries):
        return 0
    return len(entries)


def _downloads(profile: Path, scratch: Path, target: Path) -> int:
    source = profile / "History"
    if not source.is_file():
        return 0
    copy = copy_database(source, scratch)
    if copy is None:
        return 0

    rows = read_table(copy, "downloads", _WANTED_DOWNLOADS, _MAX_DOWNLOADS, "start_time DESC")
    entries: list[dict[str, Any]] = []

    for row in rows:
        path = text_value(row["target_path"])
        if not path:
            continue
        entries.append(
            {
                "path": path,
                "url": text_value(row["tab_url"]),
                "bytes": int_value(row["total_bytes"]),
                "started": util.chrome_time(int_value(row["start_time"])),
                "state": int_value(row["state"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "downloads.json", entries):
        return 0
    return len(entries)


def _walk_bookmarks(
    node: dict[str, Any],
    folder: str,
    out: list[dict[str, Any]],
    depth: int,
) -> None:
    if depth > _MAX_BOOKMARK_DEPTH or len(out) >= _MAX_BOOKMARKS:
        return
    if "children" not in node:
        return
    children = node["children"]
    if not isinstance(children, list):
        return

    name = folder
    if "name" in node:
        name = text_value(node["name"]) or folder

    for child in children:
        if len(out) >= _MAX_BOOKMARKS:
            return
        if not isinstance(child, dict):
            continue
        if "children" in child:
            _walk_bookmarks(child, name, out, depth + 1)
            continue
        if "url" not in child:
            continue
        url = text_value(child["url"])
        if not url:
            continue
        title = ""
        if "name" in child:
            title = text_value(child["name"])
        out.append({"folder": name, "title": title, "url": url})


def _bookmarks(profile: Path, target: Path) -> int:
    document = util.read_json(profile / "Bookmarks")
    if not isinstance(document, dict):
        return 0
    if "roots" not in document:
        return 0
    roots = document["roots"]
    if not isinstance(roots, dict):
        return 0

    entries: list[dict[str, Any]] = []
    for key in roots:
        if len(entries) >= _MAX_BOOKMARKS:
            break
        node = roots[key]
        if isinstance(node, dict):
            _walk_bookmarks(node, str(key), entries, 0)

    if not entries:
        return 0
    if not util.write_json(target / "bookmarks.json", entries):
        return 0
    return len(entries)


def run_profile(profile: Path, target: Path) -> int:
    """Collect every artifact for one profile. Returns the number of items written."""
    if not profile.is_dir():
        return 0

    keys = profile_keys(profile)
    written = 0

    with util.temp_workspace("sable-chromium-") as scratch:
        written += _passwords(profile, scratch, target, keys)
        written += _cookies(profile, scratch, target, keys)
        written += _history(profile, scratch, target)
        written += _downloads(profile, scratch, target)
        written += _bookmarks(profile, target)

    log.logger.debug("chromium: %s wrote %d", profile.name, written)
    return written


__all__ = [
    "Keys",
    "copy_database",
    "decrypt_value",
    "int_value",
    "profile_keys",
    "read_table",
    "run_profile",
    "secret_value",
    "text_value",
]
