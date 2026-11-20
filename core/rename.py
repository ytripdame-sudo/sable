"""Rename the finished artifact, with Windows filename rules enforced.

The build writes to a working name and this module gives the file the name it ships
under. Windows rejects names for reasons that are not obvious from the string:
reserved device names, trailing dots and spaces, characters that are legal on other
platforms, and the length ceiling. Every one of those is checked here, because a
rename that fails at the end of a build is the worst possible place to find out.

``generate`` produces a plausible name rather than a random hex string. A file called
``quiet_ledger_4182.exe`` is a file someone might have downloaded; a file called
``a7f3c9d1.exe`` is a file that announces itself.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Final

MAX_NAME_LENGTH: Final[int] = 120
MAX_SUFFIX_ATTEMPTS: Final[int] = 100

_FORBIDDEN: Final[str] = '<>:"/\\|?*'
_RESERVED: Final[frozenset[str]] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)

_ADJECTIVES: Final[tuple[str, ...]] = (
    "quiet",
    "amber",
    "harbor",
    "north",
    "plain",
    "solid",
    "bright",
    "copper",
    "silver",
    "rapid",
)

_NOUNS: Final[tuple[str, ...]] = (
    "ledger",
    "notes",
    "report",
    "sheet",
    "invoice",
    "summary",
    "draft",
    "record",
    "packet",
    "brief",
)


class RenameError(RuntimeError):
    """The target name is not a legal Windows filename, or the move failed."""


def sanitize(name: str) -> str:
    """Make ``name`` legal on Windows. Raises RenameError when nothing is left."""
    if not name:
        raise RenameError("target name is empty")

    cleaned = "".join(
        "_" if (character in _FORBIDDEN or ord(character) < 32) else character
        for character in name
    )
    cleaned = cleaned.strip(" .")

    if not cleaned:
        raise RenameError(f"{name!r} has no legal characters left")

    stem = cleaned.split(".", 1)[0].strip().lower()
    if stem in _RESERVED:
        # CON.exe is still CON as far as the filesystem is concerned.
        cleaned = "_" + cleaned

    if len(cleaned) > MAX_NAME_LENGTH:
        cleaned = cleaned[:MAX_NAME_LENGTH].rstrip(" .")

    if not cleaned:
        raise RenameError(f"{name!r} collapsed to nothing after truncation")
    return cleaned


def generate(extension: str = ".exe") -> str:
    """A plausible, legal filename with ``extension``."""
    suffix = extension if extension.startswith(".") else "." + extension
    digits = secrets.randbelow(9000) + 1000
    stem = f"{secrets.choice(_ADJECTIVES)}_{secrets.choice(_NOUNS)}_{digits}"
    return sanitize(stem) + sanitize_suffix(suffix)


def sanitize_suffix(extension: str) -> str:
    """Validate an extension. A dot in a suffix is a path separator problem."""
    if not extension.startswith(".") or len(extension) < 2:
        raise RenameError(f"{extension!r} is not an extension")
    body = extension[1:]
    if any(character in _FORBIDDEN or ord(character) < 32 for character in body):
        raise RenameError(f"{extension!r} contains an illegal character")
    if "." in body or body.strip(" .") != body:
        raise RenameError(f"{extension!r} is not a single suffix")
    return "." + body.lower()


def _unique(destination: Path) -> Path:
    """First free ``name_2.ext``, ``name_3.ext`` and so on, bounded."""
    stem = destination.stem
    suffix = destination.suffix
    for index in range(2, MAX_SUFFIX_ATTEMPTS + 2):
        candidate = destination.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RenameError(f"{destination.name}: no free name after {MAX_SUFFIX_ATTEMPTS} tries")


def rename(path: Path, name: str | None = None, directory: Path | None = None) -> Path:
    """Move ``path`` to ``name`` in ``directory``. Returns the new path.

    ``name`` is sanitised; when it is None a name is generated from the file's own
    suffix. An existing destination is never overwritten — the move lands on the
    first free ``_2``, ``_3`` variant instead.

    The move is ``os.rename`` and not ``os.replace``: on Windows the first refuses an
    occupied name and the second silently discards the file that was there. Checking
    ``exists()`` first and then replacing is a race with anything else writing to the
    folder, and the loser is somebody's file.
    """
    if not path.is_file():
        raise RenameError(f"{path}: not a file")

    target_name = generate(path.suffix or ".exe") if name is None else sanitize(name)
    target_dir = path.parent if directory is None else directory
    destination = target_dir / target_name

    if destination == path:
        return path

    for _ in range(MAX_SUFFIX_ATTEMPTS + 1):
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.rename(path, destination)
        except FileExistsError:
            destination = _unique(destination)
            continue
        except OSError as exc:
            raise RenameError(f"{path} -> {destination}: {exc.strerror}") from exc
        return destination

    raise RenameError(f"{destination.name}: no free name after {MAX_SUFFIX_ATTEMPTS} tries")


__all__ = [
    "MAX_NAME_LENGTH",
    "RenameError",
    "generate",
    "rename",
    "sanitize",
    "sanitize_suffix",
]
