"""PNG and JPEG without a Python image library.

No Pillow in the payload and no numpy: the encoder is GDI+, which ships with Windows and
encodes both formats in one codebase. The flat API is used rather than the C++ wrappers
because there is no C++ here — every call is ``gdiplus.dll`` exported, every handle is an
opaque pointer, and the token from ``GdiplusStartup`` is held for the life of the process.

The one thing worth knowing about this module: it never owns a bitmap. Both callers hand
it a pointer to pixels they already have — a DIB section for a screenshot, a decoded
Media Foundation buffer for a camera frame — and ``GdipCreateBitmapFromScan0`` wraps that
memory without copying it. The bitmap is disposed before the pixels it points at, always,
which is why the save path is a single function with no way to hold a bitmap handle.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Final

from . import log

_WINDOWS: Final[bool] = sys.platform == "win32"

# Status codes worth naming: the rest are reported as a number in the debug log.
_OK: Final[int] = 0
_GENERIC_ERROR: Final[int] = 1

# PixelFormat32bppRGB (0x00022009): three channels plus a skipped byte. It is what a
# 32-bit DIB holds, what BitBlt writes, and what a Media Foundation RGB32 frame decodes
# to, so no pixel format conversion happens anywhere in the capture path.
PIXEL_FORMAT_32BPP_RGB: Final[int] = 0x00022009

_MIME_EXTENSIONS: Final[dict[str, str]] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
}

if _WINDOWS:
    _gdiplus = ctypes.WinDLL("gdiplus", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
else:  # pragma: no cover - the Linux import test
    _gdiplus = None
    _k32 = None


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class ImageCodecInfo(ctypes.Structure):
    """``ImageCodecInfo`` from gdiplusimaging.h, laid out as the SDK declares it."""

    _fields_ = [
        ("Clsid", GUID),
        ("FormatID", GUID),
        ("CodecName", wintypes.LPCWSTR),
        ("DllName", wintypes.LPCWSTR),
        ("FormatDescription", wintypes.LPCWSTR),
        ("FilenameExtension", wintypes.LPCWSTR),
        ("MimeType", wintypes.LPCWSTR),
        ("Flags", wintypes.DWORD),
        ("Version", wintypes.DWORD),
        ("SigCount", wintypes.DWORD),
        ("SigSize", wintypes.DWORD),
        ("SigPattern", ctypes.POINTER(ctypes.c_ubyte)),
        ("SigMask", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", wintypes.UINT),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", wintypes.BOOL),
        ("SuppressExternalCodecs", wintypes.BOOL),
    ]


def _declare() -> None:
    _gdiplus.GdiplusStartup.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(GdiplusStartupInput),
        ctypes.c_void_p,
    ]
    _gdiplus.GdiplusStartup.restype = ctypes.c_long

    _gdiplus.GdiplusShutdown.argtypes = [ctypes.c_void_p]
    _gdiplus.GdiplusShutdown.restype = None

    _gdiplus.GdipCreateBitmapFromScan0.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _gdiplus.GdipCreateBitmapFromScan0.restype = ctypes.c_long

    _gdiplus.GdipDisposeImage.argtypes = [ctypes.c_void_p]
    _gdiplus.GdipDisposeImage.restype = ctypes.c_long

    _gdiplus.GdipSaveImageToFile.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
    ]
    _gdiplus.GdipSaveImageToFile.restype = ctypes.c_long

    _gdiplus.GdipGetImageEncodersSize.argtypes = [
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(wintypes.UINT),
    ]
    _gdiplus.GdipGetImageEncodersSize.restype = ctypes.c_long

    _gdiplus.GdipGetImageEncoders.argtypes = [
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ImageCodecInfo),
    ]
    _gdiplus.GdipGetImageEncoders.restype = ctypes.c_long


if _WINDOWS:
    _declare()


_state: dict[str, object] = {"token": None, "encoders": {}}


def start() -> bool:
    """Initialise GDI+. Idempotent; False on any refusal, after which every save fails."""
    if not _WINDOWS:
        return False
    if _state["token"] is not None:
        return True
    token = ctypes.c_void_p(0)
    startup = GdiplusStartupInput(1, None, False, False)
    status = int(_gdiplus.GdiplusStartup(ctypes.byref(token), ctypes.byref(startup), None))
    if status != _OK or not token.value:
        log.logger.warning("gdiplus: startup failed (%d)", status)
        return False
    _state["token"] = token
    return True


def stop() -> None:
    """Shut GDI+ down. Called once at the end of the run, never between captures."""
    token = _state.get("token")
    if not _WINDOWS or token is None:
        return
    _gdiplus.GdiplusShutdown(token)
    _state["token"] = None
    _state["encoders"] = {}


def _encoders() -> dict[str, GUID]:
    """mime type -> encoder CLSID, looked up once per process.

    Looked up rather than hard-coded: the PNG and JPEG CLSIDs are stable but they are
    also four hex groups of noise to get wrong, and the lookup is two calls.
    """
    cached = _state.get("encoders")
    if isinstance(cached, dict) and cached:
        return cached  # type: ignore[return-value]

    found: dict[str, GUID] = {}
    count = wintypes.UINT(0)
    size = wintypes.UINT(0)
    if int(_gdiplus.GdipGetImageEncodersSize(ctypes.byref(count), ctypes.byref(size))) != _OK:
        return found
    if not count.value or size.value < ctypes.sizeof(ImageCodecInfo):
        return found

    buffer = ctypes.create_string_buffer(size.value)
    table = ctypes.cast(buffer, ctypes.POINTER(ImageCodecInfo))
    if int(_gdiplus.GdipGetImageEncoders(count.value, size.value, table)) != _OK:
        return found

    for index in range(count.value):
        entry = table[index]
        mime = (entry.MimeType or "").lower()
        if mime in _MIME_EXTENSIONS:
            found[mime] = entry.Clsid

    _state["encoders"] = found
    return found


def save(
    pixels: int,
    width: int,
    height: int,
    stride: int,
    destination: Path,
    mime: str = "image/png",
) -> bool:
    """Wrap ``pixels`` and encode. ``stride`` is bytes per row, negative for bottom-up.

    The caller keeps ownership of the pixels and must keep them alive (and unwritten)
    for the length of the call. Nothing is retained afterwards: the bitmap is disposed
    before this returns, which is what makes it safe for the caller to free the buffer.
    """
    if not _WINDOWS or width <= 0 or height <= 0:
        return False
    if not start():
        return False

    clsid = _encoders().get(mime)
    if clsid is None:
        log.logger.warning("gdiplus: no encoder for %s", mime)
        return False

    bitmap = ctypes.c_void_p(0)
    status = int(
        _gdiplus.GdipCreateBitmapFromScan0(
            int(width),
            int(height),
            int(stride),
            PIXEL_FORMAT_32BPP_RGB,
            ctypes.cast(pixels, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.byref(bitmap),
        )
    )
    if status != _OK or not bitmap.value:
        log.logger.warning("gdiplus: bitmap from scan0 failed (%d)", status)
        return False

    try:
        status = int(
            _gdiplus.GdipSaveImageToFile(bitmap, str(destination), ctypes.byref(clsid), None)
        )
    finally:
        _gdiplus.GdipDisposeImage(bitmap)

    if status != _OK:
        log.logger.warning("gdiplus: save %s failed (%d)", destination.name, status)
        return False
    return True


def save_bytes(
    rows: bytes,
    width: int,
    height: int,
    stride: int,
    destination: Path,
    mime: str = "image/jpeg",
) -> bool:
    """Encode a frame that is already in memory. ``rows`` must be ``stride * height``."""
    needed = abs(stride) * height
    if len(rows) < needed:
        log.logger.debug(
            "gdiplus: %d bytes for a %dx%d frame that needs %d", len(rows), width, height, needed
        )
        return False
    buffer = ctypes.create_string_buffer(bytes(rows[:needed]), needed)
    return save(
        ctypes.addressof(buffer), width, height, stride, destination, mime
    )


__all__ = [
    "GUID",
    "PIXEL_FORMAT_32BPP_RGB",
    "ImageCodecInfo",
    "save",
    "save_bytes",
    "start",
    "stop",
]
