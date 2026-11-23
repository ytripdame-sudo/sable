"""Prove the binder on inert executables: icon preserved, name preserved.

Run it against a launcher or against whatever Windows ships. ``notepad.exe`` is the
useful case: it files its group icons at ids 2, 300, 301 and 302, so a patch that
assumes id 1 adds a group and leaves four beside it. The assertions below are what a
shell sees, not what the write call returned.

    python binder_check.py                      # notepad.exe and the launcher
    python binder_check.py <stub> [<stub> ...]  # named files only
"""

from __future__ import annotations

import ctypes
import hashlib
import struct
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sable"))

from core import forge  # noqa: E402

DEFAULT_STUBS = (
    Path(r"C:\Windows\System32\notepad.exe"),
    ROOT / "sable" / "tools" / "dist" / "sable-launcher.exe",
)

# --- what the shell draws -----------------------------------------------------

SHGFI_ICON = 0x00000100
SHGFI_SMALLICON = 0x00000001
SHGFI_LARGEICON = 0x00000000


class SHFILEINFOW(ctypes.Structure):
    _fields_ = [
        ("hIcon", wintypes.HICON),
        ("iIcon", ctypes.c_int),
        ("dwAttributes", wintypes.DWORD),
        ("szDisplayName", wintypes.WCHAR * 260),
        ("szTypeName", wintypes.WCHAR * 80),
    ]


class ICONINFO(ctypes.Structure):
    _fields_ = [
        ("fIcon", wintypes.BOOL),
        ("xHotspot", wintypes.DWORD),
        ("yHotspot", wintypes.DWORD),
        ("hbmMask", wintypes.HBITMAP),
        ("hbmColor", wintypes.HBITMAP),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_user32 = ctypes.WinDLL("user32", use_last_error=True)
_gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

_shell32.SHGetFileInfoW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(SHFILEINFOW),
    wintypes.UINT,
    wintypes.UINT,
]
_shell32.SHGetFileInfoW.restype = ctypes.c_void_p
_user32.GetIconInfo.argtypes = [wintypes.HICON, ctypes.POINTER(ICONINFO)]
_user32.GetIconInfo.restype = wintypes.BOOL
_user32.GetDC.restype = wintypes.HDC
_user32.DestroyIcon.argtypes = [wintypes.HICON]
_gdi32.GetDIBits.argtypes = [
    wintypes.HDC,
    wintypes.HBITMAP,
    wintypes.UINT,
    wintypes.UINT,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.UINT,
]
_gdi32.GetDIBits.restype = ctypes.c_int
_gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]


def shell_icon(path: Path, small: bool = True) -> str:
    """SHA-256 of the pixels the shell draws for ``path``. What Explorer shows."""
    info = SHFILEINFOW()
    flags = SHGFI_ICON | (SHGFI_SMALLICON if small else SHGFI_LARGEICON)
    if not _shell32.SHGetFileInfoW(
        str(path), 0, ctypes.byref(info), ctypes.sizeof(info), flags
    ):
        return f"no-icon({ctypes.get_last_error()})"

    details = ICONINFO()
    if not _user32.GetIconInfo(info.hIcon, ctypes.byref(details)):
        _user32.DestroyIcon(info.hIcon)
        return f"no-info({ctypes.get_last_error()})"

    side = 16 if small else 32
    header = BITMAPINFOHEADER()
    header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    header.biWidth = side
    header.biHeight = -side
    header.biPlanes = 1
    header.biBitCount = 32
    pixels = ctypes.create_string_buffer(side * side * 4)
    drawn = _gdi32.GetDIBits(
        _user32.GetDC(None), details.hbmColor, 0, side, pixels, ctypes.byref(header), 0
    )
    for handle in (details.hbmColor, details.hbmMask):
        if handle:
            _gdi32.DeleteObject(handle)
    _user32.DestroyIcon(info.hIcon)
    if not drawn:
        return f"no-bits({ctypes.get_last_error()})"
    return hashlib.sha256(pixels.raw).hexdigest()[:16]


# --- a marker icon ------------------------------------------------------------


def _bitmap(side: int, bgra: tuple[int, int, int, int]) -> bytes:
    header = struct.pack(
        "<IiiHHIIiiII", 40, side, side * 2, 1, 32, 0, side * side * 4, 0, 0, 0, 0
    )
    return header + bytes(bgra) * side * side + bytes((side + 31) // 32 * 4) * side


def marker_icon() -> bytes:
    """A two-image .ico in a colour no launcher ships. Two images on purpose: one image
    cannot tell "replaced" from "the launcher only had one"."""
    images = [_bitmap(32, (0, 0, 255, 255)), _bitmap(32, (0, 255, 0, 255))]
    directory = b""
    cursor = 6 + 16 * len(images)
    for image in images:
        directory += struct.pack("<BBBBHHII", 32, 32, 0, 0, 1, 32, len(image), cursor)
        cursor += len(image)
    return struct.pack("<HHH", 0, 1, len(images)) + directory + b"".join(images)


# --- checks -------------------------------------------------------------------


@contextmanager
def scratch() -> Iterator[Path]:
    workspace = Path(tempfile.mkdtemp(prefix="sable-binder-"))
    try:
        yield workspace
    finally:
        for child in sorted(workspace.rglob("*"), reverse=True):
            try:
                child.unlink() if child.is_file() else child.rmdir()
            except OSError:
                pass
        try:
            workspace.rmdir()
        except OSError:
            pass


def check(stub: Path) -> list[str]:
    """Every assertion for one stub. Returns the failures; empty means it held."""
    failures: list[str] = []
    before = forge.resource_refs(stub.read_bytes())
    groups_before = sorted({ref.identifier for ref in before if ref.kind == 14})
    images_before = sorted({ref.identifier for ref in before if ref.kind == 3})
    icon_before = shell_icon(stub)

    with scratch() as work:
        icon_path = work / "marker.ico"
        icon_path.write_bytes(marker_icon())
        entries = forge.icon_entries(icon_path)
        patched = forge.patch_resources(stub, icons=entries)
        target = work / "patched.exe"
        target.write_bytes(patched)

        after = forge.resource_refs(target.read_bytes())
        groups_after = sorted({ref.identifier for ref in after if ref.kind == 14})
        images_after = sorted({ref.identifier for ref in after if ref.kind == 3})
        icon_after = shell_icon(target)

        expected_group = [min(groups_before)] if groups_before else [1]
        expected_images = list(range(1, len(entries) + 1))

        if groups_after != expected_group:
            failures.append(
                f"group ids {groups_after}, wanted {expected_group} (stub had {groups_before})"
            )
        if images_after != expected_images:
            failures.append(
                f"image ids {images_after}, wanted {expected_images} (stub had {len(images_before)})"
            )
        if icon_after == icon_before:
            failures.append(f"the shell still draws {icon_before}")

        # The group the file kept must name the images the file kept.
        group_bytes = _resource_bytes(target.read_bytes(), 14, expected_group[0])
        count = struct.unpack_from("<H", group_bytes, 4)[0]
        named = [struct.unpack_from("<BBBBHHIH", group_bytes, 6 + 14 * i)[7] for i in range(count)]
        if named != expected_images:
            failures.append(f"group names {named}, wanted {expected_images}")

    print(f"  {stub.name:<24} groups {groups_before} -> {groups_after}  "
          f"images {len(images_before)} -> {len(images_after)}  "
          f"icon {icon_before} -> {icon_after}")
    return failures


def _resource_bytes(data: bytes, kind: int, identifier: int) -> bytes:
    """One resource body, read the way the loader reads it."""
    pe = int.from_bytes(data[0x3C:0x40], "little")
    coff = pe + 4
    sections = int.from_bytes(data[coff + 2:coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    optional = coff + 20
    magic = int.from_bytes(data[optional:optional + 2], "little")
    directories = optional + (112 if magic == 0x20B else 96)
    table = optional + optional_size
    spans: list[tuple[int, int, int]] = []
    for index in range(sections):
        base = table + index * 40
        virtual = int.from_bytes(data[base + 12:base + 16], "little")
        size = int.from_bytes(data[base + 8:base + 12], "little") or 1
        raw = int.from_bytes(data[base + 20:base + 24], "little")
        spans.append((virtual, size, raw))

    def offset(rva: int) -> int:
        for virtual, size, raw in spans:
            if virtual <= rva < virtual + size:
                return raw + (rva - virtual)
        raise SystemExit(f"rva {rva:#x} is in no section")

    resource_rva = int.from_bytes(data[directories + 16:directories + 20], "little")
    root = offset(resource_rva)

    def entries(at: int) -> list[tuple[int, int]]:
        named = int.from_bytes(data[root + at + 12:root + at + 14], "little")
        ident = int.from_bytes(data[root + at + 14:root + at + 16], "little")
        rows = []
        for index in range(named + ident):
            entry = root + at + 16 + index * 8
            rows.append(
                (
                    int.from_bytes(data[entry:entry + 4], "little"),
                    int.from_bytes(data[entry + 4:entry + 8], "little"),
                )
            )
        return rows

    for kind_label, kind_target in entries(0):
        if kind_label != kind:
            continue
        for id_label, id_target in entries(kind_target & 0x7FFFFFFF):
            if id_label != identifier:
                continue
            for _language, leaf in entries(id_target & 0x7FFFFFFF):
                data_rva = int.from_bytes(
                    data[root + (leaf & 0x7FFFFFFF):root + (leaf & 0x7FFFFFFF) + 4],
                    "little",
                )
                size = int.from_bytes(
                    data[root + (leaf & 0x7FFFFFFF) + 4:root + (leaf & 0x7FFFFFFF) + 8],
                    "little",
                )
                start = offset(data_rva)
                return data[start:start + size]
    raise SystemExit(f"resource {kind}:{identifier} is missing")


# --- the properties sheet ------------------------------------------------------

_version = ctypes.WinDLL("version", use_last_error=True)
_version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
_version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
_version.GetFileVersionInfoW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
]
_version.GetFileVersionInfoW.restype = wintypes.BOOL
_version.VerQueryValueW.argtypes = [
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.UINT),
]
_version.VerQueryValueW.restype = wintypes.BOOL


def _query(block: bytes, path: str, *, wide: bool = False) -> bytes:
    payload = ctypes.create_string_buffer(block, len(block))
    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    if not _version.VerQueryValueW(
        payload, path, ctypes.byref(pointer), ctypes.byref(length)
    ):
        return b""
    if not pointer.value:
        return b""
    # A string query reports characters, not bytes. Reading it as bytes is how a
    # version check "fails" against a block that was written correctly.
    return ctypes.string_at(pointer.value, length.value * 2 if wide else length.value)


def read_version(path: Path) -> dict[str, object]:
    """What the properties sheet would show, read by the API the sheet uses."""
    ignored = wintypes.DWORD()
    size = _version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
    if not size:
        return {}
    block = bytes(size)
    if not _version.GetFileVersionInfoW(str(path), 0, size, block):
        return {}
    fixed = _query(block, "\\")
    if len(fixed) < 52:
        return {}
    signature, _structure, fms, fls, pms, pls = struct.unpack_from("<6I", fixed, 0)
    out: dict[str, object] = {
        "signature": f"{signature:#010x}",
        "file_version": f"{fms >> 16}.{fms & 0xFFFF}.{fls >> 16}.{fls & 0xFFFF}",
        "product_version": f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}",
    }
    for name in (
        "CompanyName",
        "FileDescription",
        "ProductName",
        "LegalCopyright",
        "OriginalFilename",
        "FileVersion",
        "ProductVersion",
    ):
        text = _query(block, f"\\StringFileInfo\\040904B0\\{name}", wide=True)
        if text:
            out[name] = text.decode("utf-16le").rstrip("\x00")
    return out


def check_version(stub: Path) -> list[str]:
    """The version block, written and then read back by ``version.dll``."""
    from core.schema import VersionConfig

    wanted = VersionConfig(
        company="Northline Software Ltd",
        product="Northline Setup",
        description="Setup loader",
        copyright="(c) 2026 Northline",
        original_name="northline-setup.exe",
        file_version="6.2.9.441",
        product_version="6.2.9.441",
    )

    with scratch() as work:
        blob = forge.version_blob(wanted)
        target = work / "versioned.exe"
        target.write_bytes(forge.patch_resources(stub, version=blob))
        shown = read_version(target)

    failures: list[str] = []
    if shown.get("signature") != "0xfeef04bd":
        failures.append(f"VS_FIXEDFILEINFO signature is {shown.get('signature')}")
    if shown.get("file_version") != wanted.file_version:
        failures.append(f"file version reads {shown.get('file_version')}")
    for name, value in (
        ("CompanyName", wanted.company),
        ("ProductName", wanted.product),
        ("FileDescription", wanted.description),
        ("LegalCopyright", wanted.copyright),
        ("OriginalFilename", wanted.original_name),
    ):
        if shown.get(name) != value:
            failures.append(f"{name} reads {shown.get(name)!r}, wanted {value!r}")

    print(
        f"  version {stub.name:<16} {shown.get('signature')} "
        f"{shown.get('file_version')} {shown.get('CompanyName')!r}"
    )
    return failures


def main(argv: list[str]) -> int:
    stubs = [Path(item) for item in argv] if argv else list(DEFAULT_STUBS)
    failures: list[str] = []
    for stub in stubs:
        if not stub.is_file():
            print(f"  {stub}: not on this machine, skipped")
            continue
        print(f"binder check: {stub}")
        failures += [f"{stub.name}: {text}" for text in check(stub)]
        failures += [f"{stub.name}: {text}" for text in check_version(stub)]

    if failures:
        print("\nFAILED")
        for line in failures:
            print("  -", line)
        return 1
    print("\nheld: group id preserved, orphan images gone, the shell draws the new icon")
    print("held: the version block reads back through version.dll")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
