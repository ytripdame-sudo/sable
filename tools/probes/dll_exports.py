"""Read a PE's export table, forwarders included. Static: the file is never loaded.

Written for the sideload unit, where the artifact is a DLL whose whole job is to be
indistinguishable from a system one. Two questions get asked of it, and both are answered by
the export directory alone:

1. **Does it export what the host will import?** A proxy that is missing one name makes the
   host fail to load, which is loud, and a proxy that exports an extra name is a signature,
   which is quiet. The set has to match exactly, so it is compared rather than eyeballed.
2. **Are the exports forwarders?** A forwarder is a string the loader resolves,
   ``MODULE.Function``. A stub that returns success is a function with a body; a forwarder has
   no body at all, and the difference is visible in the directory: the function's RVA points
   inside the export directory instead of into a section's code.

Usage:
    python tools/probes/dll_exports.py C:\\Windows\\System32\\version.dll
    python tools/probes/dll_exports.py build\\version.dll --expect C:\\Windows\\System32\\version.dll
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from pathlib import Path

EXPORT_DIRECTORY = 0


@dataclass(frozen=True)
class Export:
    """One name in the export table. ``forwarder`` is None for a real function."""

    name: str
    rva: int
    forwarder: str | None


@dataclass(frozen=True)
class Pe:
    """The bytes and the two numbers every read below needs."""

    data: bytes
    image_base: int
    directory: tuple[int, int]  # (rva, size), zeroed when the PE has no exports
    name: str = ""  # the file it came from, for messages
    entry: int = 0  # AddressOfEntryPoint, the RVA the loader calls on attach


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def load(path: Path) -> Pe:
    """Parse just enough of the headers to find the export directory."""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path.name}: not a PE (no MZ)")
    pe = _u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError(f"{path.name}: no PE signature at 0x{pe:X}")

    coff = pe + 4
    sections = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    magic = _u16(data, optional)
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        count_offset = optional + 108
    elif magic == 0x10B:
        image_base = _u32(data, optional + 28)
        count_offset = optional + 92
    else:
        raise ValueError(f"{path.name}: unknown optional header magic 0x{magic:X}")

    count = _u32(data, count_offset)
    directory = (0, 0)
    if count > EXPORT_DIRECTORY:
        # Export directory is entry 0 in both layouts, right after the count.
        directory = (_u32(data, count_offset + 4), _u32(data, count_offset + 8))

    entry = _u32(data, optional + 16)

    # Section table, for rva -> file offset.
    table = optional + optional_size
    pe_obj = Pe(
        data=data,
        image_base=image_base,
        directory=directory,
        name=path.name,
        entry=entry,
    )
    object.__setattr__(pe_obj, "_sections", _sections(data, table, sections))
    return pe_obj


def _sections(data: bytes, table: int, count: int) -> tuple[tuple[int, int, int], ...]:
    """(virtual address, virtual size, raw offset) per section."""
    out = []
    for index in range(count):
        base = table + index * 40
        virtual_size = _u32(data, base + 8)
        virtual_address = _u32(data, base + 12)
        raw_size = _u32(data, base + 16)
        raw_offset = _u32(data, base + 20)
        out.append((virtual_address, max(virtual_size, raw_size), raw_offset))
    return tuple(out)


def offset_of(pe: Pe, rva: int) -> int:
    """Map an RVA to a file offset, or raise. A corrupt table must not read a wrong byte."""
    sections = getattr(pe, "_sections", ())
    for virtual_address, size, raw_offset in sections:
        if virtual_address <= rva < virtual_address + size:
            return raw_offset + (rva - virtual_address)
    raise ValueError(f"rva 0x{rva:X} is in no section")


def _cstring(data: bytes, offset: int) -> str:
    end = data.index(b"\0", offset)
    return data[offset:end].decode("ascii", "replace")


def exports(pe: Pe) -> list[Export]:
    """Every named export, sorted. Unnamed ordinals are not part of the contract."""
    directory_rva, directory_size = pe.directory
    if not directory_rva or not directory_size:
        return []

    directory = offset_of(pe, directory_rva)
    name_count = _u32(pe.data, directory + 24)
    functions_rva = _u32(pe.data, directory + 28)
    names_rva = _u32(pe.data, directory + 32)
    ordinals_rva = _u32(pe.data, directory + 36)
    limit = min(directory_size, 4096)

    out: list[Export] = []
    for index in range(min(name_count, 4096)):
        name_rva = _u32(pe.data, offset_of(pe, names_rva) + index * 4)
        function_rva = _u32(pe.data, offset_of(pe, functions_rva) + _u16(
            pe.data, offset_of(pe, ordinals_rva) + index * 2
        ) * 4)
        forwarder = None
        # A forwarder's RVA lands inside the export directory itself: the "function body" is
        # a string, and the loader resolves it instead of jumping to it.
        if directory_rva <= function_rva < directory_rva + limit:
            forwarder = _cstring(pe.data, offset_of(pe, function_rva))
        out.append(Export((_cstring(pe.data, offset_of(pe, name_rva))), function_rva, forwarder))
    return sorted(out, key=lambda export: export.name)


def entry_description(pe: Pe) -> str:
    """What the loader does on attach, read out of the image instead of assumed.

    The entry point is the half of this artifact that does not show up in the export table, so it
    gets read the same way the exports do. A `jmp rel32` as the first instruction is a
    trampoline: the loader lands on the jump and the real function is wherever it points. Any
    other prologue means the CRT startup is in the way, which is the configuration where
    `DllMain` is reached through a weak symbol and can be silently skipped.
    """
    if not pe.entry:
        return "entry point rva 0: nothing runs on attach"
    offset = offset_of(pe, pe.entry)
    first = pe.data[offset]
    if first != 0xE9:
        return f"entry point rva 0x{pe.entry:X}: not a jump (first byte 0x{first:02X})"
    relative = struct.unpack_from("<i", pe.data, offset + 1)[0]
    target = pe.entry + 5 + relative
    return f"entry point rva 0x{pe.entry:X}: jmp 0x{target:X}"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2

    path = Path(argv[0])
    pe = load(path)
    found = exports(pe)

    print(f"{path.name}: {len(found)} named exports, image base 0x{pe.image_base:X}")
    print(f"  {entry_description(pe)}")
    width = max((len(export.name) for export in found), default=10)
    for export in found:
        if export.forwarder:
            print(f"  {export.name:<{width}}  -> {export.forwarder}")
        else:
            print(f"  {export.name:<{width}}  (code at rva 0x{export.rva:X})")

    expected_name = None
    if "--expect" in argv:
        expected_name = Path(argv[argv.index("--expect") + 1])
        reference = load(expected_name)
        wanted = {export.name: export.forwarder for export in exports(reference)}
        got = {export.name: export.forwarder for export in found}

        problems: list[str] = []
        notes: list[str] = []
        for name in sorted(set(wanted) - set(got)):
            problems.append(f"missing    {name}")
        for name in sorted(set(got) - set(wanted)):
            problems.append(f"extra      {name}")
        for name in sorted(set(wanted) & set(got)):
            mine, theirs = got[name], wanted[name]
            if mine is None and theirs is None:
                continue
            if mine is not None and theirs is not None:
                if mine.split(".")[-1] != theirs.split(".")[-1]:
                    problems.append(f"target     {name}: {mine} vs {theirs}")
                continue
            # A code thunk where the reference forwards (or the reverse) is not a defect: the
            # name resolves and the call reaches the real function either way. It is worth
            # printing, because it is the one place this artifact differs from the system copy.
            notes.append(
                f"shape      {name}: {'code' if mine is None else 'forwarder'} here, "
                f"{'forwarder' if theirs is not None else 'code'} in {reference.name}"
            )

        if notes:
            print(f"\nNotes against {reference.name}:")
            for note in notes:
                print(f"  {note}")

        if problems:
            print(f"\nFAIL against {reference.name}:")
            for problem in problems:
                print(f"  {problem}")
            return 1
        print(f"\nPASS  every name matches {reference.name}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
