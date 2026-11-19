"""Assemble the shipping artifact: payload, seal, ballast, footer.

Three things are owned here and nowhere else:

1. The payload archive. ``agent/`` verbatim, ``core/schema.py`` copied in as
   ``sable_schema.py``, and ``cfg.json`` written from the validated ``RunConfig``.
   One archive, one config, one schema, and ``agent/config.py`` reads the copy that
   is inside the file it is running from.
2. The two loader literals. ``MUTEX_NAME`` and ``SEAL_KEY`` must exist before
   anything is decrypted, so they cannot live in ``cfg.json`` — which is inside the
   archive those two unlock. The rewrite happens on the archived bytes, never on the
   working tree: the source file keeps its stub literals and a build never mutates
   the repository it was run from.
3. The container. ``[ stub ][ ballast ][ sealed ][ footer 12 ]``, with the footer
   last so ``agent/loader.py`` finds the sealed blob with one seek from EOF.

The footer is ``b"SBLT"`` and the little-endian 64-bit offset of the sealed blob.
The offset is measured from the start of the file, which is why ballast sits before
the sealed blob rather than after the footer: appending ballast at the end would
push the footer out of position, and the loader would have to scan.

Two output modes exist because they answer different questions. ``exe`` is the
shipping artifact: a frozen stub with the sealed payload welded behind it. ``py`` is
the inspectable one: a single runnable script carrying the sealed blob as base64,
for a machine with an interpreter and no frozen stub. Both run the same
``agent.entry`` and both carry the same key; the script mode just spells it out in
text instead of hiding it in a binary.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
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

SCHEMA_MEMBER: Final[str] = "sable_schema.py"
CONFIG_MEMBER: Final[str] = "cfg.json"
LOADER_MEMBER: Final[str] = "agent/loader.py"

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

_MUTEX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(MUTEX_NAME: Final\[str\] = ).*$", re.MULTILINE
)
_SEAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(SEAL_KEY: Final\[str\] = ).*$", re.MULTILINE
)


class ForgeError(RuntimeError):
    """The artifact could not be assembled. Raised, never returned."""


# --- loader literals ----------------------------------------------------------


def rewrite_literals(source: str, mutex: str, seal_key: str) -> str:
    """Replace the two stub literals in ``agent/loader.py`` source text.

    ``repr`` is used rather than quote-stuffing so a mutex name with a backslash or
    an apostrophe still produces a legal Python literal.
    """
    if not mutex.strip():
        raise ForgeError("mutex is empty")
    if not seal_key.strip():
        raise ForgeError("seal key is empty")

    rewritten, mutex_hits = _MUTEX_PATTERN.subn(lambda match: match.group(1) + repr(mutex), source)
    rewritten, seal_hits = _SEAL_PATTERN.subn(
        lambda match: match.group(1) + repr(seal_key), rewritten
    )

    if mutex_hits != 1 or seal_hits != 1:
        raise ForgeError(
            f"{LOADER_MEMBER}: {mutex_hits} MUTEX_NAME and {seal_hits} SEAL_KEY matches, "
            "expected exactly one of each"
        )
    return rewritten


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
    """The decrypted archive: agent tree, shipped schema, and cfg.json."""
    schema_path = root / "core" / "schema.py"
    try:
        schema = schema_path.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{schema_path}: cannot read ({exc.strerror})") from exc

    members: list[tuple[str, bytes]] = []
    for name, data in _agent_members(root):
        if name == LOADER_MEMBER:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ForgeError(f"{LOADER_MEMBER}: not UTF-8 ({exc.reason})") from exc
            data = rewrite_literals(text, cfg.mutex, cfg.seal_key).encode("utf-8")
        members.append((name, data))

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


def _write_ballast(handle: object, megabytes: int) -> None:
    # Streamed in chunks: ballast_mb can legitimately reach 4096, and holding that
    # as one bytes object would fail before it finished allocating.
    remaining = _ballast(megabytes) * _MIB
    while remaining:
        chunk = min(remaining, _COPY_CHUNK)
        handle.write(os.urandom(chunk))  # type: ignore[attr-defined]
        remaining -= chunk


def _write_exe(destination: Path, stub: Path, sealed: bytes, ballast_mb: int) -> Path:
    try:
        stub_size = stub.stat().st_size
    except OSError as exc:
        raise ForgeError(f"{stub}: cannot stat ({exc.strerror})") from exc
    if stub_size <= 0:
        raise ForgeError(f"{stub}: stub is empty")

    offset = expected_offset(stub_size, ballast_mb)
    staging = destination.with_name(destination.name + ".part")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with staging.open("wb") as handle:
            with stub.open("rb") as source:
                shutil.copyfileobj(source, handle, _COPY_CHUNK)
            _write_ballast(handle, ballast_mb)
            handle.write(sealed)
            handle.write(FOOTER_MAGIC + offset.to_bytes(_OFFSET_BYTES, "little"))
        # Same directory, so a half-written artifact is never visible under the
        # shipping name.
        os.replace(staging, destination)
    except OSError as exc:
        raise ForgeError(f"{destination}: cannot write ({exc.strerror})") from exc

    return destination


def _write_script(destination: Path, sealed: bytes, seal_key: str) -> Path:
    text = script_text(sealed, seal_key)
    staging = destination.with_name(destination.name + ".part")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with staging.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(staging, destination)
    except OSError as exc:
        raise ForgeError(f"{destination}: cannot write ({exc.strerror})") from exc

    return destination


_SCRIPT_TEMPLATE: Final[str] = '''#!/usr/bin/env python3
"""SABLE payload script.

Generated by core/forge.py. The archive is sealed with AES-256-GCM under a key
derived from the literal below, the same way the frozen stub carries it. Running
this file decrypts to a temporary directory, hands the archive to the loader, and
runs the entry point the stub runs.
"""

from __future__ import annotations

import base64
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

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

        loader.adopt(zipfile.ZipFile(target), workspace, target)
        return int(entry.main([]))
    finally:
        try:
            sys.path.remove(str(target))
        except ValueError:
            pass
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
'''


def script_text(sealed: bytes, seal_key: str) -> str:
    """The ``.py`` artifact as text. Deterministic for a given seal."""
    if not seal_key:
        raise ForgeError("seal key is empty")

    encoded = base64.b64encode(sealed).decode("ascii")
    lines = "\n".join(f'    b"{encoded[index:index + 76]}"' for index in range(0, len(encoded), 76))
    return _SCRIPT_TEMPLATE.format(key=repr(seal_key), blob="\n" + lines + "\n")


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
        return _write_exe(destination, stub, sealed, _ballast(cfg.ballast_mb))

    # Script output carries no ballast. The pad exists to change the size of a
    # binary; padding a text file with comment lines would only make the build
    # slower to read for the same number. Recorded in DECISIONS.md.
    return _write_script(destination, sealed, cfg.seal_key)


__all__ = [
    "CONFIG_MEMBER",
    "FOOTER_MAGIC",
    "FOOTER_SIZE",
    "ForgeError",
    "OUTPUT_EXE",
    "OUTPUT_MODES",
    "OUTPUT_PY",
    "OutputMode",
    "SCHEMA_MEMBER",
    "build",
    "expected_offset",
    "payload",
    "rewrite_literals",
    "script_text",
]
