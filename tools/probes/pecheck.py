"""Independent readers for the finished artifact.

Nothing here imports ``sable``. That is the point: the audit has to read the file the
way Explorer and the loader read it, not by asking the builder whether it did its job.

Three readers live here:

``seal_open``      PBKDF2-HMAC-SHA256 200k, AES-256-GCM, salt|nonce|ciphertext|tag.
``pe_resources``   the PE resource tree, parsed from the section table up.
``version_strings`` the ``VS_VERSION_INFO`` block, parsed as the length-prefixed tree
                   it is, including the 4-byte alignment that is counted from each
                   node's own start.

``info`` composes them into one record for a built artifact.
"""

from __future__ import annotations

import base64
import io
import ast
import json
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_BYTES = 32
KDF_ITERATIONS = 200_000

FOOTER_SIZE = 8
KEY_SLOT = 64
MUTEX_SLOT = 200 * 4
TRAILER_SIZE = KEY_SLOT + MUTEX_SLOT

RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16

_FIXED_SIGNATURE = 0xFEEF04BD


# --- the seal -----------------------------------------------------------------


def seal_open(blob: bytes, key_text: str) -> bytes:
    """Decrypt a sealed payload. Raises ValueError on a wrong key or a bad tag."""
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    if len(blob) < SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1:
        raise ValueError(f"sealed blob is {len(blob)} bytes, too short")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    key = PBKDF2(
        key_text.encode("utf-8"),
        salt,
        dkLen=KEY_BYTES,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# --- the container ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Container:
    """Where each part of the executable container starts and stops."""

    size: int
    offset: int
    sealed: bytes
    key: str
    mutex: str
    footer_ok: bool
    trailer_ok: bool

    @property
    def tail(self) -> int:
        return self.offset + len(self.sealed) + TRAILER_SIZE + FOOTER_SIZE


def container(path: Path) -> Container:
    """Read footer, trailer and sealed blob out of a finished ``.exe``.

    Everything is position: the footer is the last eight bytes, the trailer the fixed
    width before it. Nothing is searched for, so a payload that happens to contain the old
    markers' bytes cannot confuse the reader — and no artifact carries a marker to find.
    """
    raw = path.read_bytes()
    footer = raw[-FOOTER_SIZE:]
    footer_ok = len(footer) == FOOTER_SIZE
    offset = int.from_bytes(footer, "little") if footer_ok else -1

    block_at = len(raw) - FOOTER_SIZE - TRAILER_SIZE
    block = raw[block_at:block_at + TRAILER_SIZE] if block_at >= 0 else b""
    trailer_ok = len(block) == TRAILER_SIZE and b"\x00" in block

    key = ""
    mutex = ""
    if trailer_ok:
        key = block[:KEY_SLOT].split(b"\x00", 1)[0].decode("utf-8", "replace")
        mutex = block[KEY_SLOT:].split(b"\x00", 1)[0].decode("utf-8", "replace")

    sealed = raw[offset:block_at] if footer_ok and offset >= 0 else b""
    return Container(
        size=len(raw),
        offset=offset,
        sealed=sealed,
        key=key,
        mutex=mutex,
        footer_ok=footer_ok,
        trailer_ok=trailer_ok,
    )


def script_parts(path: Path) -> tuple[bytes, str, str]:
    """Pull ``SEALED``, ``SEAL_KEY`` and ``MUTEX`` out of a generated ``.py``."""
    text = path.read_text(encoding="utf-8")
    sealed = b""
    key = ""
    mutex = ""

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("MUTEX = ") and not mutex:
            mutex = _literal(stripped[len("MUTEX = "):])
        elif stripped.startswith("SEAL_KEY = ") and not key:
            key = _literal(stripped[len("SEAL_KEY = "):])
        elif stripped.startswith('b"') and stripped.endswith('"'):
            sealed += base64.b64decode(stripped[2:-1])

    return sealed, key, mutex


def _literal(text: str) -> str:
    # The generator writes ``repr()`` of a Python string, so the exact inverse is
    # literal_eval; swapping quote styles around would mangle an escaped apostrophe.
    try:
        return str(ast.literal_eval(text.strip()))
    except (ValueError, SyntaxError):
        return text.strip().strip("'").strip('"')


# --- the PE resource table ----------------------------------------------------


def _u16(raw: bytes, at: int) -> int:
    return struct.unpack_from("<H", raw, at)[0]


def _u32(raw: bytes, at: int) -> int:
    return struct.unpack_from("<I", raw, at)[0]


def _sections(raw: bytes) -> tuple[list[tuple[int, int, int, int]], int]:
    """``(virtual, virtual_size, raw_offset, raw_size)`` per section, plus RSDS rva."""
    pe = _u32(raw, 0x3C)
    if raw[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image")

    coff = pe + 4
    count = _u16(raw, coff + 2)
    optional_size = _u16(raw, coff + 16)
    optional = coff + 20
    magic = _u16(raw, optional)
    directories = optional + (112 if magic == 0x20B else 96)
    rsrc = _u32(raw, directories + 2 * 8)

    table = optional + optional_size
    out: list[tuple[int, int, int, int]] = []
    for index in range(count):
        base = table + index * 40
        virtual_size = _u32(raw, base + 8)
        virtual = _u32(raw, base + 12)
        raw_size = _u32(raw, base + 16)
        raw_offset = _u32(raw, base + 20)
        out.append((virtual, max(virtual_size, 1), raw_offset, raw_size))
    return out, rsrc


def _offset(raw: bytes, sections: list[tuple[int, int, int, int]], rva: int) -> int:
    for virtual, size, raw_offset, raw_size in sections:
        if virtual <= rva < virtual + max(size, raw_size):
            return raw_offset + (rva - virtual)
    raise ValueError(f"rva {rva:#x} is in no section")


def pe_resources(raw: bytes) -> dict[tuple[int, int, int], bytes]:
    """``{(type, id, language): payload}`` for every integer-named resource."""
    sections, rsrc = _sections(raw)
    if rsrc == 0:
        return {}
    root = _offset(raw, sections, rsrc)
    found: dict[tuple[int, int, int], bytes] = {}

    def entries(directory: int) -> list[tuple[int, int]]:
        named = _u16(raw, directory + 12)
        ids = _u16(raw, directory + 14)
        rows: list[tuple[int, int]] = []
        for index in range(named + ids):
            entry = directory + 16 + index * 8
            rows.append((_u32(raw, entry), _u32(raw, entry + 4)))
        return rows

    for kind, kind_target in entries(root):
        if kind & 0x80000000:
            continue
        for identifier, id_target in entries(root + (kind_target & 0x7FFFFFFF)):
            if identifier & 0x80000000:
                continue
            for language, leaf in entries(root + (id_target & 0x7FFFFFFF)):
                if language & 0x80000000:
                    continue
                data = root + leaf
                where = _offset(raw, sections, _u32(raw, data))
                size = _u32(raw, data + 4)
                found[(kind, identifier, language)] = raw[where:where + size]
    return found


def icon_ids(raw: bytes) -> tuple[list[int], list[int]]:
    """``(RT_ICON ids, RT_GROUP_ICON ids)`` present in the image."""
    refs = pe_resources(raw)
    images = sorted(identifier for (kind, identifier, _) in refs if kind == RT_ICON)
    groups = sorted(identifier for (kind, identifier, _) in refs if kind == RT_GROUP_ICON)
    return images, groups


def group_images(blob: bytes) -> list[tuple[int, int, int, int]]:
    """``(width, height, bit_count, bytes)`` per row of an ``RT_GROUP_ICON`` body."""
    reserved, kind, count = struct.unpack_from("<HHH", blob, 0)
    if reserved != 0 or kind != 1:
        raise ValueError("not a group icon")
    rows: list[tuple[int, int, int, int]] = []
    for index in range(count):
        base = 6 + index * 14
        width, height, _colors, _res, _planes, bits, size, _id = struct.unpack_from(
            "<BBBBHHIH", blob, base
        )
        rows.append((width, height, bits, size))
    return rows


# --- RT_VERSION ---------------------------------------------------------------


def _align(value: int) -> int:
    return (value + 3) & ~3


def _node(raw: bytes, start: int) -> tuple[str, int, int, int, int, list[tuple[str, int]]]:
    """Parse one node: ``(key, length, value_length, value_type, value_at, children)``."""
    length, value_length, value_type = struct.unpack_from("<HHH", raw, start)
    end = start + length

    cursor = start + 6
    while cursor + 1 < end and raw[cursor:cursor + 2] != b"\x00\x00":
        cursor += 2
    key = raw[start + 6:cursor].decode("utf-16le", "replace")

    after_key = start + _align(cursor + 2 - start)
    value_at = after_key
    value_bytes = value_length * 2 if value_type == 1 else value_length
    children_at = start + _align((value_at + value_bytes) - start)

    kids: list[tuple[str, int]] = []
    position = children_at
    while position + 6 <= end:
        child_length = _u16(raw, position)
        if child_length < 6 or position + child_length > end:
            break
        child_end = position + child_length
        child_cursor = position + 6
        while child_cursor + 1 < child_end:
            if raw[child_cursor:child_cursor + 2] == b"\x00\x00":
                break
            child_cursor += 2
        kids.append((raw[position + 6:child_cursor].decode("utf-16le", "replace"), position))
        position += _align(child_length)

    return key, length, value_length, value_type, value_at, kids


def version_strings(blob: bytes) -> tuple[dict[str, str], dict[str, int]]:
    """Every string in the version block, plus the four fixed version numbers."""
    key, _length, value_length, value_type, value_at, children = _node(blob, 0)
    if key != "VS_VERSION_INFO":
        raise ValueError(f"version block starts with {key!r}")

    fixed = blob[value_at:value_at + value_length]
    signature = struct.unpack_from("<I", fixed, 0)[0] if len(fixed) >= 4 else 0
    if signature != _FIXED_SIGNATURE:
        raise ValueError("version block has no VS_FIXEDFILEINFO")

    file_ms, file_ls, product_ms, product_ls = struct.unpack_from("<IIII", fixed, 8)
    numbers = {
        "file": ((file_ms >> 16) & 0xFFFF, file_ms & 0xFFFF, (file_ls >> 16) & 0xFFFF, file_ls & 0xFFFF),
        "product": (
            (product_ms >> 16) & 0xFFFF,
            product_ms & 0xFFFF,
            (product_ls >> 16) & 0xFFFF,
            product_ls & 0xFFFF,
        ),
    }

    strings: dict[str, str] = {}

    def walk(start: int) -> None:
        name, _l, vlen, vtype, at, kids = _node(blob, start)
        if vtype == 1 and vlen > 0 and not kids:
            strings[name] = blob[at:at + vlen * 2].decode("utf-16le", "replace").rstrip("\x00")
        for _child_name, child_at in kids:
            walk(child_at)

    for _child_name, child_at in children:
        walk(child_at)
    return strings, numbers


# --- the payload archive ------------------------------------------------------


@dataclass(slots=True)
class Artifact:
    """Everything the audit can read out of one finished artifact."""

    path: Path
    mode: str
    size: int
    members: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    fused: dict[str, int] = field(default_factory=dict)
    key: str = ""
    mutex: str = ""
    sealed_size: int = 0
    offset: int = -1
    footer_ok: bool = False
    trailer_ok: bool = False
    images: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    group_rows: list[tuple[int, int, int, int]] = field(default_factory=list)
    version: dict[str, str] = field(default_factory=dict)
    numbers: dict[str, tuple[int, int, int, int]] = field(default_factory=dict)
    icon_payloads: dict[int, bytes] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def read(path: Path, mode: str, key_hint: str = "") -> Artifact:
    """Open a built artifact of either mode and describe it."""
    record = Artifact(path=path, mode=mode, size=path.stat().st_size)

    if mode == "py":
        sealed, record.key, record.mutex = script_parts(path)
    else:
        box = container(path)
        sealed = box.sealed
        record.key = box.key
        record.mutex = box.mutex
        record.offset = box.offset
        record.footer_ok = box.footer_ok
        record.trailer_ok = box.trailer_ok

    key = record.key or key_hint
    if not key:
        record.problems.append("no seal key in the artifact")
        return record

    try:
        payload = seal_open(sealed, key)
    except Exception as exc:
        record.problems.append(f"seal would not open: {exc}")
        return record

    record.sealed_size = len(sealed)

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        record.members = sorted(archive.namelist())
        record.config = json.loads(archive.read("cfg.json"))
        for name in record.members:
            if name.startswith("fused/"):
                record.fused[name] = len(archive.read(name))

    if mode == "exe":
        raw = path.read_bytes()
        refs = pe_resources(raw)
        record.images = sorted(identifier for (kind, identifier, _) in refs if kind == RT_ICON)
        record.groups = sorted(identifier for (kind, identifier, _) in refs if kind == RT_GROUP_ICON)
        record.icon_payloads = {
            identifier: data for (kind, identifier, _), data in refs.items() if kind == RT_ICON
        }
        for (kind, _identifier, _language), data in refs.items():
            if kind == RT_GROUP_ICON and not record.group_rows:
                try:
                    record.group_rows = group_images(data)
                except ValueError as exc:
                    record.problems.append(f"group icon unreadable: {exc}")
            if kind == RT_VERSION and not record.version:
                try:
                    record.version, record.numbers = version_strings(data)
                except ValueError as exc:
                    record.problems.append(f"version block unreadable: {exc}")
    return record
