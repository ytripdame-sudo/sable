"""Assemble the shipping artifact: payload, seal, ballast, trailer, footer.

Four things are owned here and nowhere else:

1. The payload archive. ``agent/`` verbatim, ``core/schema.py`` copied in as
   ``sable_schema.py``, and ``cfg.json`` written from the validated ``RunConfig``.
   One archive, one config, one schema, and ``agent/config.py`` reads the copy that
   is inside the file it is running from.
2. The trailer. The seal key and the mutex name must exist before anything is
   decrypted, so they cannot live in ``cfg.json`` — that file is inside the archive
   those two unlock. They cannot live in the launcher either, or every build would
   need its own fresh freeze. So both travel in a fixed-width block welded between
   the sealed blob and the footer, and one launcher opens any artifact.
3. The container. ``[ stub ][ ballast ][ sealed ][ trailer 868 ][ footer 12 ]``, with
   the footer last so ``agent/loader.py`` finds the sealed blob with one seek.
4. The two output modes. ``exe`` is the shipping artifact: a frozen launcher with the
   sealed payload welded behind it. ``py`` is the inspectable one: a single runnable
   script carrying the sealed blob as base64, for a machine with an interpreter and
   no frozen launcher. Both run the same ``agent.entry`` and both carry the same key;
   the script mode just spells it out in text instead of hiding it in a binary.

The footer is ``b"SBLT"`` and the little-endian 64-bit offset of the sealed blob.
The offset is measured from the start of the file, which is why ballast sits before
the sealed blob rather than after the footer: appending ballast at the end would
push the footer out of position, and the loader would have to scan.
"""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Final, Literal

from .schema import MAX_BALLAST_MB, RunConfig, to_dict
from .seal import MIN_SEALED_BYTES

OutputMode = Literal["exe", "py"]

OUTPUT_EXE: Final[str] = "exe"
OUTPUT_PY: Final[str] = "py"
OUTPUT_MODES: Final[tuple[str, ...]] = (OUTPUT_EXE, OUTPUT_PY)

FOOTER_MAGIC: Final[bytes] = b"SBLT"
FOOTER_SIZE: Final[int] = 12

# The trailer sits between the sealed blob and the footer and carries the two values a
# launcher needs before it can decrypt anything: the seal key and the mutex name.
#
# Fixed-width slots, so a reader computes the position instead of parsing a length
# prefix, and so a key of any length up to the slot costs the same bytes on disk.
TRAILER_MAGIC: Final[bytes] = b"SBLK"

# The seal key is a passphrase, capped in bytes because the slot is bytes. Twelve
# characters is the floor over in ``core/validate.py``; sixty-four bytes is where a
# PBKDF2 passphrase stops gaining anything and starts costing trailer space.
KEY_SLOT: Final[int] = 64

# A kernel object name is capped at 260 WCHARs. Two hundred leaves room for the
# ``Global\`` prefix and still fails loudly well before the kernel does. Four bytes
# per WCHAR is the widest UTF-8 can get, so the slot holds any name validate accepts.
MUTEX_SLOT: Final[int] = 200 * 4

TRAILER_SIZE: Final[int] = len(TRAILER_MAGIC) + KEY_SLOT + MUTEX_SLOT

SCHEMA_MEMBER: Final[str] = "sable_schema.py"
CONFIG_MEMBER: Final[str] = "cfg.json"

_MIB: Final[int] = 1024 * 1024
_COPY_CHUNK: Final[int] = 1024 * 1024
_OFFSET_BYTES: Final[int] = 8
_EXTENSIONS: Final[dict[str, str]] = {OUTPUT_EXE: ".exe", OUTPUT_PY: ".py"}

# Fixed timestamp on every member so two builds of the same tree produce the same
# payload bytes. The seal is randomised per artifact, so this only makes the zip
# comparable; it is not an attempt at a reproducible binary.
_ZIP_DATE: Final[tuple[int, int, int, int, int, int]] = (1980, 1, 1, 0, 0, 0)

_REQUIRED_MEMBERS: Final[tuple[str, ...]] = (
    "agent/__init__.py",
    "agent/entry.py",
    "agent/loader.py",
)


class ForgeError(RuntimeError):
    """The artifact could not be assembled. Raised, never returned."""


# --- payload ------------------------------------------------------------------


def _agent_members(root: Path) -> list[tuple[str, bytes]]:
    base = root / "agent"
    if not base.is_dir():
        raise ForgeError(f"{base}: agent package not found")

    members: list[tuple[str, bytes]] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            members.append((relative, path.read_bytes()))
        except OSError as exc:
            raise ForgeError(f"{path}: cannot read ({exc.strerror})") from exc

    present = {name for name, _ in members}
    for required in _REQUIRED_MEMBERS:
        if required not in present:
            raise ForgeError(f"{required}: required module missing from the payload")
    return members


def _config_bytes(cfg: RunConfig) -> bytes:
    # to_dict is the inverse of the reader the agent will use, so the archive cannot
    # carry a shape that from_dict would reject.
    return json.dumps(to_dict(cfg), indent=2, ensure_ascii=True).encode("utf-8")


def payload(root: Path, cfg: RunConfig) -> bytes:
    """The decrypted archive: agent tree, shipped schema, and cfg.json.

    The tree is shipped verbatim. Nothing is rewritten on the way in: the two values
    that used to be patched into ``agent/loader.py`` now travel in the trailer, so the
    source in the archive is byte-identical to the source on disk and a build cannot
    mutate the repository it was run from.
    """
    schema_path = root / "core" / "schema.py"
    try:
        schema = schema_path.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{schema_path}: cannot read ({exc.strerror})") from exc

    members: list[tuple[str, bytes]] = _agent_members(root)
    members.append((SCHEMA_MEMBER, schema))
    members.append((CONFIG_MEMBER, _config_bytes(cfg)))
    members.sort(key=lambda item: item[0])

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


# --- container ----------------------------------------------------------------


def _ballast(megabytes: int) -> int:
    if megabytes < 0 or megabytes > MAX_BALLAST_MB:
        raise ForgeError(f"ballast_mb {megabytes} is outside 0..{MAX_BALLAST_MB}")
    return megabytes


def expected_offset(stub_size: int, ballast_mb: int) -> int:
    """Where the sealed blob starts, and therefore what the footer records."""
    if stub_size <= 0:
        raise ForgeError(f"stub is {stub_size} bytes")
    return stub_size + _ballast(ballast_mb) * _MIB


def _slot(text: str, width: int, name: str) -> bytes:
    """One NUL-padded fixed-width slot. Length is position, not a prefix."""
    encoded = text.encode("utf-8")
    if not text.strip():
        # Whitespace-only would encrypt fine and produce a mutex nobody can name and a
        # key nobody can retype. validate rejects it; the write path must agree.
        raise ForgeError(f"{name} is empty")
    if b"\x00" in encoded:
        raise ForgeError(f"{name} contains a NUL byte")
    if len(encoded) > width:
        raise ForgeError(f"{name} is {len(encoded)} bytes, the container carries {width}")
    return encoded.ljust(width, b"\x00")


def trailer(cfg: RunConfig) -> bytes:
    """The bytes a launcher reads before it can decrypt anything."""
    return (
        TRAILER_MAGIC
        + _slot(cfg.seal_key, KEY_SLOT, "seal key")
        + _slot(cfg.mutex, MUTEX_SLOT, "mutex")
    )


def _write_ballast(handle: object, megabytes: int) -> None:
    # Streamed in chunks: ballast_mb can legitimately reach 4096, and holding that
    # as one bytes object would fail before it finished allocating.
    remaining = _ballast(megabytes) * _MIB
    while remaining:
        chunk = min(remaining, _COPY_CHUNK)
        handle.write(os.urandom(chunk))  # type: ignore[attr-defined]
        remaining -= chunk


def _write_exe(
    destination: Path, stub: Path, sealed: bytes, ballast_mb: int, cfg: RunConfig
) -> Path:
    try:
        stub_size = stub.stat().st_size
    except OSError as exc:
        raise ForgeError(f"{stub}: cannot stat ({exc.strerror})") from exc
    if stub_size <= 0:
        raise ForgeError(f"{stub}: stub is empty")

    offset = expected_offset(stub_size, ballast_mb)
    block = trailer(cfg)
    staging = destination.with_name(destination.name + ".part")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with staging.open("wb") as handle:
            with stub.open("rb") as source:
                shutil.copyfileobj(source, handle, _COPY_CHUNK)
            _write_ballast(handle, ballast_mb)
            handle.write(sealed)
            handle.write(block)
            handle.write(FOOTER_MAGIC + offset.to_bytes(_OFFSET_BYTES, "little"))
        # Same directory, so a half-written artifact is never visible under the
        # shipping name.
        os.replace(staging, destination)
    except OSError as exc:
        # A failed write leaves a full-size ``.part`` in the output folder. Nothing
        # will ever look at it again, and at 4 GB of ballast it is the largest file
        # the folder will hold.
        _discard(staging)
        raise ForgeError(f"{destination}: cannot write ({exc.strerror})") from exc

    return destination


def _write_script(destination: Path, sealed: bytes, cfg: RunConfig) -> Path:
    text = script_text(sealed, cfg.seal_key, cfg.mutex)
    staging = destination.with_name(destination.name + ".part")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with staging.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(staging, destination)
    except OSError as exc:
        _discard(staging)
        raise ForgeError(f"{destination}: cannot write ({exc.strerror})") from exc

    return destination


def _discard(path: Path) -> None:
    """Remove a staging file. Cleanup that fails is not worth a second exception."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


_SCRIPT_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""SABLE payload script.

Generated by core/forge.py. The archive is sealed with AES-256-GCM under a key
derived from the literal below. The frozen container carries the same two values in
a trailer behind the sealed blob; a text file has nowhere to put one, so they are
spelled out here instead. Running this file takes the mutex, decrypts to a temporary
directory, hands the archive to the loader, and runs the entry point the launcher runs.
"""

from __future__ import annotations

import base64
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

MUTEX = {mutex}
SEAL_KEY = {key}
SEALED = base64.b64decode({blob})

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_BYTES = 32
KDF_ITERATIONS = 200_000


def _open_sealed(blob: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    minimum = SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1
    if len(blob) < minimum:
        raise SystemExit(f"sealed payload is {{len(blob)}} bytes, needs {{minimum}}")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    key = PBKDF2(
        SEAL_KEY.encode("utf-8"),
        salt,
        dkLen=KEY_BYTES,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise SystemExit("seal key rejected the payload") from exc


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="sable-"))
    target = workspace / "payload.zip"
    target.write_bytes(_open_sealed(SEALED))

    sys.path.insert(0, str(target))
    try:
        from agent import entry, loader

        if not loader.acquire(MUTEX):
            return 0

        loader.adopt(zipfile.ZipFile(target), workspace, target)
        # argv is forwarded, not dropped: the retry task re-runs this image with
        # ``--retry`` and the SYSTEM unwrap helper re-runs it with ``--abe-unwrap``.
        # A bootstrap that called ``main([])`` started the agent normally both times.
        return int(entry.main(sys.argv[1:]))
    finally:
        try:
            sys.path.remove(str(target))
        except ValueError:
            pass
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def script_text(sealed: bytes, seal_key: str, mutex: str) -> str:
    """The ``.py`` artifact as text. Deterministic for a given seal."""
    if not seal_key.strip():
        raise ForgeError("seal key is empty")
    if not mutex.strip():
        raise ForgeError("mutex is empty")

    encoded = base64.b64encode(sealed).decode("ascii")
    lines = "\n".join(f'    b"{encoded[index:index + 76]}"' for index in range(0, len(encoded), 76))
    return _SCRIPT_TEMPLATE.format(
        mutex=repr(mutex), key=repr(seal_key), blob="\n" + lines + "\n"
    )


def build(
    cfg: RunConfig,
    sealed: bytes,
    destination: Path,
    *,
    mode: str = OUTPUT_EXE,
    stub: Path | None = None,
) -> Path:
    """Write the finished artifact. Returns ``destination``."""
    if mode not in OUTPUT_MODES:
        raise ForgeError(f"{mode!r}: expected one of {', '.join(OUTPUT_MODES)}")
    if len(sealed) < MIN_SEALED_BYTES:
        raise ForgeError(f"sealed payload is {len(sealed)} bytes, needs {MIN_SEALED_BYTES}")

    expected = _EXTENSIONS[mode]
    if destination.suffix.lower() != expected:
        raise ForgeError(f"{destination.name}: {mode} output must end {expected}")

    if mode == OUTPUT_EXE:
        if stub is None:
            raise ForgeError("exe output needs a frozen stub")
        return _write_exe(destination, stub, sealed, _ballast(cfg.ballast_mb), cfg)

    # Script output carries no ballast. The pad exists to change the size of a
    # binary; padding a text file with comment lines would only make the build
    # slower to read for the same number. Recorded in DECISIONS.md.
    return _write_script(destination, sealed, cfg)


__all__ = [
    "CONFIG_MEMBER",
    "FOOTER_MAGIC",
    "FOOTER_SIZE",
    "KEY_SLOT",
    "MUTEX_SLOT",
    "OUTPUT_EXE",
    "OUTPUT_MODES",
    "OUTPUT_PY",
    "SCHEMA_MEMBER",
    "TRAILER_MAGIC",
    "TRAILER_SIZE",
    "ForgeError",
    "OutputMode",
    "build",
    "expected_offset",
    "payload",
    "script_text",
    "trailer",
]
