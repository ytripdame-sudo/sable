"""Filesystem and shell helpers shared by every collector.

Live browser databases are never opened in place. They are copied, together with
their ``-wal`` and ``-shm`` siblings, and the copy is what gets read. A profile that
is open in a running browser holds a lock on the original, and the write-ahead log
holds the rows the main file does not have yet.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from . import log

_MAX_JSON_BYTES: Final[int] = 32 * 1024 * 1024
_MAX_ARCHIVE_FILES: Final[int] = 50_000
_SIDECARS: Final[tuple[str, ...]] = ("-wal", "-shm")

# Chrome stores microseconds since 1601-01-01; Unix epoch is 11644473600 s later.
_CHROME_EPOCH_OFFSET: Final[int] = 11_644_473_600

# The earliest timestamp a zip entry can carry. Anything older raises inside zipfile,
# and a copied profile is full of 1601-epoch files.
_ZIP_EPOCH: Final[tuple[int, int, int, int, int, int]] = (1980, 1, 1, 0, 0, 0)

_DETACHED_PROCESS: Final[int] = 0x00000008
_CREATE_NEW_PROCESS_GROUP: Final[int] = 0x00000200


def executable_path() -> Path:
    """The file to delete when self-remove runs: the frozen exe, or the script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(sys.argv[0]).resolve()


def copy_with_sidecars(source: Path, destination: Path) -> bool:
    """Copy a live database and its WAL siblings. False if the source is absent."""
    if not source.is_file():
        return False
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    except OSError:
        log.logger.debug("copy failed: %s", source, exc_info=True)
        return False

    for suffix in _SIDECARS:
        sidecar = source.with_name(source.name + suffix)
        if not sidecar.is_file():
            continue
        try:
            shutil.copy2(sidecar, destination.with_name(destination.name + suffix))
        except OSError:
            # A missing sidecar costs recent rows, not the whole copy.
            log.logger.debug("sidecar copy failed: %s", sidecar, exc_info=True)
    return True


def read_json(path: Path) -> Any | None:
    """Parsed JSON, or None on absence, oversize or malformed content."""
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            log.logger.debug("json too large: %s", path)
            return None
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        log.logger.debug("json read failed: %s", path, exc_info=True)
        return None


def write_json(path: Path, payload: Any) -> bool:
    """Write UTF-8 JSON with parents created. False on any failure."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
    except (OSError, TypeError, ValueError):
        log.logger.debug("json write failed: %s", path, exc_info=True)
        return False
    return True


def chrome_time(value: int) -> str | None:
    """Chrome's microseconds-since-1601 as an ISO 8601 UTC string."""
    if value <= 0:
        return None
    try:
        stamp = datetime.fromtimestamp(value / 1_000_000 - _CHROME_EPOCH_OFFSET, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return stamp.isoformat()


def unix_time(value: int) -> str | None:
    """Seconds since the Unix epoch as an ISO 8601 UTC string."""
    if value <= 0:
        return None
    try:
        stamp = datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return stamp.isoformat()


@contextmanager
def temp_workspace(prefix: str = "sable-") -> Iterator[Path]:
    """A temp directory that is removed even when the body raises."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _iter_files(root: Path, limit: int = _MAX_ARCHIVE_FILES) -> Iterator[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= limit:
            log.logger.debug("archive file cap reached at %d", limit)
            return
        if not path.is_file():
            continue
        count += 1
        yield path


def make_archive(source: Path, destination: Path) -> Path | None:
    """Zip the collected tree. None when the source is gone or the zip cannot open.

    Members are written through an explicit ``ZipInfo`` rather than
    ``ZipFile.write``. ``write`` copies each file's mtime into the entry, and the zip
    format cannot represent anything before 1980 — it raises ``ValueError`` and takes
    the whole archive with it. Copied browser profiles contain exactly those
    timestamps: LevelDB and SQLite files written by an installer or unpacked from an
    image carry a 1601 epoch, which is Windows' zero and well before the format's
    floor. A fixed epoch also makes two runs over the same tree produce comparable
    members instead of recording when the copy happened.
    """
    if not source.is_dir():
        log.logger.debug("archive source is not a directory: %s", source)
        return None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in _iter_files(source):
                if path == destination:
                    continue
                try:
                    data = path.read_bytes()
                except OSError:
                    log.logger.debug("archive skipped: %s", path, exc_info=True)
                    continue

                info = zipfile.ZipInfo(path.relative_to(source).as_posix(), _ZIP_EPOCH)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                try:
                    archive.writestr(info, data)
                except (OSError, ValueError):
                    log.logger.debug("archive member refused: %s", path, exc_info=True)
    except OSError:
        log.logger.debug("archive creation failed: %s", destination, exc_info=True)
        return None
    return destination


def self_remove(executable: Path) -> None:
    """Detach a cmd that waits for this process to die, then deletes it.

    The path is quoted because a username with a space in it is not an edge case.
    """
    if sys.platform != "win32":
        return
    target = str(executable)
    if '"' in target:
        log.logger.warning("self-remove skipped: path contains a quote")
        return
    command = f'ping -n 4 127.0.0.1 >nul & del /f /q "{target}"'
    try:
        subprocess.Popen(
            ["cmd", "/c", command],
            creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        log.logger.debug("self-remove failed to spawn", exc_info=True)


__all__ = [
    "chrome_time",
    "copy_with_sidecars",
    "executable_path",
    "make_archive",
    "read_json",
    "self_remove",
    "temp_workspace",
    "unix_time",
    "write_json",
]
