"""Browser root discovery and routing.

This module knows where browsers keep their data and which profile directories are
real. It does not open a database. Each profile is handed to ``chromium.run_profile``
or ``gecko.run_profile`` with a resolved target directory, so the readers never carry
a path convention and this file never carries a decryption detail.

Roots, confirmed against the source repository and against the installed layouts:

- Chromium family: ``%LOCALAPPDATA%\\<vendor>\\<product>\\User Data``, where profiles
  are child directories (``Default``, ``Profile 1``, ``Guest Profile``).
- Opera: ``%APPDATA%\\Opera Software\\Opera Stable`` and ``Opera GX Stable``, where
  the root itself is the profile and ``Local State`` sits beside ``Login Data``.
- Firefox: ``%APPDATA%\\Mozilla\\Firefox``, with profiles under ``Profiles\\`` and
  absolute overrides listed in ``profiles.ini``.

A profile is recognised by the files it must contain, not by its name. A directory
named ``Default`` with no database in it is not a profile, and a renamed profile that
does have one still is.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Final, NamedTuple

from ... import log
from . import chromium, gecko

_MAX_PROFILES: Final[int] = 32
_MAX_INI_BYTES: Final[int] = 1024 * 1024

_CHROMIUM_LOCAL: Final[tuple[tuple[str, str], ...]] = (
    ("chrome", r"Google\Chrome\User Data"),
    ("chrome_beta", r"Google\Chrome Beta\User Data"),
    ("chrome_dev", r"Google\Chrome Dev\User Data"),
    ("chrome_sxs", r"Google\Chrome SxS\User Data"),
    ("edge", r"Microsoft\Edge\User Data"),
    ("edge_beta", r"Microsoft\Edge Beta\User Data"),
    ("edge_dev", r"Microsoft\Edge Dev\User Data"),
    ("edge_sxs", r"Microsoft\Edge SxS\User Data"),
    ("brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("brave_beta", r"BraveSoftware\Brave-Browser-Beta\User Data"),
    ("brave_nightly", r"BraveSoftware\Brave-Browser-Nightly\User Data"),
    ("vivaldi", r"Vivaldi\User Data"),
    ("vivaldi_snapshot", r"Vivaldi Snapshot\User Data"),
    ("yandex", r"Yandex\YandexBrowser\User Data"),
    ("chromium", r"Chromium\User Data"),
    ("iridium", r"Iridium\User Data"),
    ("thorium", r"Thorium\User Data"),
    ("supermium", r"Supermium\User Data"),
)

# Root is the profile itself, and it carries its own Local State. Opera ships the same
# product under two folder names depending on the build: ``Opera GX Stable`` and, on
# newer releases, ``Opera GX``. Both are listed under one label because they are one
# browser; the profile slug keeps their output directories apart.
_CHROMIUM_ROAMING: Final[tuple[tuple[str, str], ...]] = (
    ("opera", r"Opera Software\Opera Stable"),
    ("opera_gx", r"Opera Software\Opera GX Stable"),
    ("opera_gx", r"Opera Software\Opera GX"),
    ("opera_next", r"Opera Software\Opera Next"),
    ("opera_developer", r"Opera Software\Opera Developer"),
    ("opera_air", r"Opera Software\Opera Air Stable"),
)

_GECKO_ROAMING: Final[str] = r"Mozilla\Firefox"

_CHROMIUM_MARKERS: Final[tuple[str, ...]] = (
    "Preferences",
    "History",
    "Login Data",
    "Cookies",
    "Bookmarks",
    "Web Data",
)

_GECKO_MARKERS: Final[tuple[str, ...]] = (
    "key4.db",
    "logins.json",
    "cookies.sqlite",
    "places.sqlite",
)


class Root(NamedTuple):
    name: str
    path: Path
    profile_is_root: bool


def slug(text: str) -> str:
    """A directory-safe profile name. ``Profile 1`` becomes ``Profile_1``."""
    cleaned = "".join(
        character if character.isalnum() or character in "-_" else "_" for character in text
    )
    return cleaned.strip("_") or "profile"


def _local_appdata() -> Path | None:
    try:
        return Path(os.environ["LOCALAPPDATA"])
    except KeyError:
        return None


def _roaming_appdata() -> Path | None:
    try:
        return Path(os.environ["APPDATA"])
    except KeyError:
        return None


def chromium_roots() -> list[Root]:
    roots: list[Root] = []

    local = _local_appdata()
    if local is not None:
        for name, relative in _CHROMIUM_LOCAL:
            roots.append(Root(name, local / relative, False))

    roaming = _roaming_appdata()
    if roaming is not None:
        for name, relative in _CHROMIUM_ROAMING:
            roots.append(Root(name, roaming / relative, True))

    return roots


def gecko_roots() -> list[Root]:
    roots: list[Root] = []
    roaming = _roaming_appdata()
    if roaming is not None:
        roots.append(Root("firefox", roaming / _GECKO_ROAMING, False))
    return roots


def _has_marker(directory: Path, markers: tuple[str, ...]) -> bool:
    return any((directory / marker).is_file() for marker in markers)


def _natural_key(text: str) -> tuple[tuple[int, int | str], ...]:
    """Sort ``Profile 2`` before ``Profile 10``. Lexical order puts ten first.

    Each chunk is tagged with 0 for text and 1 for a number, so the sort never
    compares an int against a str.
    """
    parts: list[tuple[int, int | str]] = []
    for chunk in re.split(r"(\d+)", text):
        if not chunk:
            continue
        if chunk.isdigit():
            parts.append((1, int(chunk)))
        else:
            parts.append((0, chunk.lower()))
    return tuple(parts)


def profile_dirs(user_data: Path) -> list[Path]:
    """Profile directories under a ``User Data`` root, capped and name-ordered."""
    found: list[Path] = []
    try:
        entries = sorted(user_data.iterdir(), key=lambda item: _natural_key(item.name))
    except OSError:
        log.logger.debug("browsers: cannot list %s", user_data, exc_info=True)
        return found

    for entry in entries:
        if len(found) >= _MAX_PROFILES:
            break
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        if _has_marker(entry, _CHROMIUM_MARKERS):
            found.append(entry)

    return found


def _ini_paths(root: Path) -> list[Path]:
    """Profile paths declared in ``profiles.ini``, relative or absolute."""
    ini = root / "profiles.ini"
    try:
        if ini.stat().st_size > _MAX_INI_BYTES:
            log.logger.debug("browsers: %s is oversized", ini)
            return []
        text = ini.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    paths: list[Path] = []
    relative = True

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("["):
            # IsRelative is per-section; a new section resets it to the default.
            relative = True
            continue
        lowered = stripped.lower()
        if lowered.startswith("isrelative="):
            relative = stripped.split("=", 1)[1].strip() != "0"
            continue
        if not lowered.startswith("path="):
            continue
        value = stripped.split("=", 1)[1].strip()
        if not value:
            continue
        paths.append(root / value if relative else Path(value))
        if len(paths) >= _MAX_PROFILES:
            break

    return paths


def _firefox_profiles(root: Path) -> list[Path]:
    """Directory scan plus the ini overrides, deduplicated and marker-checked."""
    candidates: list[Path] = []

    profiles_dir = root / "Profiles"
    try:
        candidates.extend(sorted(profiles_dir.iterdir(), key=lambda item: _natural_key(item.name)))
    except OSError:
        # No Profiles directory is the normal case for a Firefox that has never
        # been launched; the ini overrides are still worth checking.
        log.logger.debug("browsers: no Profiles directory under %s", root)
    candidates.extend(_ini_paths(root))

    found: list[Path] = []
    seen: set[Path] = set()

    for candidate in candidates:
        if len(found) >= _MAX_PROFILES:
            break
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            if not resolved.is_dir():
                continue
        except OSError:
            continue
        if _has_marker(resolved, _GECKO_MARKERS):
            found.append(resolved)

    return found


def _chromium_profile(profile: Path, browser: str, out_dir: Path) -> int:
    target = out_dir / "browsers" / browser / slug(profile.name)
    try:
        return chromium.run_profile(profile, target)
    except Exception:
        log.logger.exception("browsers: chromium %s/%s raised", browser, profile.name)
        return 0


def _gecko_profile(profile: Path, browser: str, out_dir: Path) -> int:
    target = out_dir / "browsers" / browser / slug(profile.name)
    try:
        return gecko.run_profile(profile, target)
    except Exception:
        log.logger.exception("browsers: gecko %s/%s raised", browser, profile.name)
        return 0


def run(out_dir: Path, cfg: Any) -> int:
    """Walk every known browser and profile. Returns the number of items written.

    Per-profile failures are contained: one unreadable database does not cost the
    other nine browsers their collection.
    """
    total = 0

    for root in chromium_roots():
        if not root.path.is_dir():
            continue
        if root.profile_is_root:
            total += _chromium_profile(root.path, root.name, out_dir)
            continue
        for profile in profile_dirs(root.path):
            total += _chromium_profile(profile, root.name, out_dir)

    for root in gecko_roots():
        if not root.path.is_dir():
            continue
        for profile in _firefox_profiles(root.path):
            total += _gecko_profile(profile, root.name, out_dir)

    return total


__all__ = ["Root", "chromium_roots", "gecko_roots", "profile_dirs", "run", "slug"]
