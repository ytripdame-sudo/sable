"""Fixture builders shared by more than one test module.

Not shipping source and deliberately not in ``MANIFEST.txt``: nothing here runs on a host.
The only entry is a synthetic PE image.

Why a synthetic image exists at all
-----------------------------------
``forge._patched_stub`` patches the stub on every build, unconditionally — the per-build
nonce is the one resource that has to land or the artifact is the single file worth
clustering. That means every build path now touches ``BeginUpdateResource``, and a random
4096-byte fixture is not an executable image, so the call refuses it and the test fails for
a reason that has nothing to do with what it was testing.

Copying ``tools/dist/sable-launcher.exe`` into each test would work and costs 10 MB and a
disk write per case. This builds the smallest image Windows will accept as a resource
update target instead: DOS header, ``PE\\0\\0``, one COFF section header, a PE32+ optional
header with a sane ``SizeOfHeaders``/``SizeOfImage``, and 512 bytes of ``int3`` in a
``.text`` section. Measured: ``BeginUpdateResource`` accepts it, ``EndUpdateResource``
writes a ``.rsrc`` section, and the result grows from 1024 to 1536 bytes.

None of that makes it bootable, and it is not used where booting matters.
"""

from __future__ import annotations

import struct
from typing import Final

# Offset of the PE signature, the value at ``0x3C``. Anything past the DOS stub works;
# 0x80 leaves room for a plausible header without a real DOS program behind it.
_E_LFANEW: Final[int] = 0x80
# One file-alignment unit of headers, one more for the section body.
_SIZE_OF_HEADERS: Final[int] = 0x200
_SECTION_RAW: Final[int] = 0x200


def pe_stub(*, overlay: bytes = b"") -> bytes:
    """A minimal, resource-patchable PE32+ image, optionally with bytes welded after it.

    ``overlay`` exists so a test can prove the image boundary: ``forge.image_end`` must
    stop where the section table stops, and everything after it is the launcher's archive.
    """
    dos = bytearray(_E_LFANEW)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, _E_LFANEW)

    # Machine x64, one section, optional header 0xF0 bytes, characteristics EXECUTABLE |
    # LARGE_ADDRESS_AWARE — the two flags a launcher carries.
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)

    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)  # PE32+
    struct.pack_into("<I", optional, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", optional, 20, 0x1000)  # BaseOfCode
    struct.pack_into("<I", optional, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", optional, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", optional, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", optional, 60, _SIZE_OF_HEADERS)
    struct.pack_into("<I", optional, 108, 16)  # NumberOfRvaAndSizes; the array stays zero

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        _SECTION_RAW,  # VirtualSize
        0x1000,  # VirtualAddress
        _SECTION_RAW,  # SizeOfRawData
        _SIZE_OF_HEADERS,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )

    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    return head.ljust(_SIZE_OF_HEADERS, b"\x00") + b"\xcc" * _SECTION_RAW + overlay


__all__ = ["pe_stub"]
