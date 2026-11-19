"""Document inventory.

Names, sizes and timestamps for the folders a person actually uses, plus the shell's
recent-items list. No file contents are read and nothing is copied: this is an
inventory, and an inventory that copies is a different, much larger artifact.

The walk is breadth-first with a hard depth and a hard per-folder cap. A desktop with
forty thousand files in one tree is common, and a collector that recurses without a
ceiling is a collector that hangs on somebody's photo library.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from .. import util

_MAX_PER_FOLDER: Final[int] = 500
_MAX_DEPTH: Final[int] = 2
_MAX_RECENT: Final[int] = 200

_FOLDERS: Final[tuple[str, ...]] = (
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Videos",
    "Music",
)


def _home() -> Path | None:
    try:
        return Path(os.environ["USERPROFILE"])
    except KeyError:
        pass
    try:
        return Path.home()
    except (RuntimeError, OSError):
        return None


def _stamp(seconds: float) -> str | None:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _walk(folder: Path, limit: int) -> list[dict[str, Any]]:
    """Breadth-first file listing, capped and depth-limited."""
    entries: list[dict[str, Any]] = []
    pending: list[tuple[Path, int]] = [(folder, 0)]

    while pending and len(entries) < limit:
        current, depth = pending.pop(0)
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue

        for child in children:
            if len(entries) >= limit:
                break
            try:
                if child.is_dir():
                    if depth < _MAX_DEPTH:
                        pending.append((child, depth + 1))
                    continue
                stat = child.stat()
            except OSError:
                continue

            entries.append(
                {
                    "path": str(child),
                    "bytes": stat.st_size,
                    "modified": _stamp(stat.st_mtime),
                }
            )

    return entries


def _recent(appdata: Path | None) -> list[dict[str, Any]]:
    if appdata is None:
        return []

    folder = appdata / "Microsoft" / "Windows" / "Recent"
    if not folder.is_dir():
        return []

    entries: list[dict[str, Any]] = []

    try:
        children = sorted(folder.iterdir(), key=lambda item: item.name)
    except OSError:
        return entries

    for child in children:
        if len(entries) >= _MAX_RECENT:
            break
        try:
            if not child.is_file():
                continue
            stat = child.stat()
        except OSError:
            continue
        entries.append({"name": child.name, "modified": _stamp(stat.st_mtime)})

    return entries


def run(out_dir: Path, cfg: Any) -> int:
    """Write ``documents.json``. Returns the number of entries written."""
    home = _home()
    if home is None:
        return 0

    appdata: Path | None = None
    try:
        appdata = Path(os.environ["APPDATA"])
    except KeyError:
        appdata = None

    folders: list[dict[str, Any]] = []
    written = 0

    for name in _FOLDERS:
        folder = home / name
        if not folder.is_dir():
            continue
        entries = _walk(folder, _MAX_PER_FOLDER)
        if not entries:
            continue
        folders.append({"name": name, "path": str(folder), "count": len(entries), "entries": entries})
        written += len(entries)

    recent = _recent(appdata)
    written += len(recent)

    if written == 0:
        return 0

    payload: dict[str, Any] = {
        "root": str(home),
        "folders": folders,
        "recent": recent,
    }

    if not util.write_json(out_dir / "documents.json", payload):
        return 0
    return written


__all__ = ["run"]
