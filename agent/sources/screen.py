"""One screenshot per monitor, encoded once, no loop.

Three monitors at 2560x1440 is 44 MB of pixels. Held as Python objects that is a
four-second pause and a spike the size of the archive; held as one DIB section per
monitor and encoded straight out of it, the whole pass is a few hundred milliseconds and
never more than one monitor's pixels resident.

The budget is a contract, not an aspiration: 400 ms and 12 MB. A monitor that does not
fit the remaining byte budget is skipped and named in ``screen.json`` — a payload that
ships two screenshots and says why the third is missing is more useful than one that
ships nothing because the third was a 4K panel.

``screen.json`` carries what a screenshot cannot: which display is which, the resolution
in pixels, the DPI scale the user actually sees, and whether the frame came back flat.
That last one is the sandbox tell — a headless session renders one colour across the
whole surface — and entry reads it from here rather than guessing from the image.
"""

from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Final

from .. import gdi, log, util, winapi

if sys.platform == "win32":
    _gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
else:  # pragma: no cover - the Linux import test
    _gdi32 = None
    _user32 = None

_SRCCOPY: Final[int] = 0x00CC0020
# CAPTUREBLT includes layered windows. Without it a screenshot of a desktop with an
# overlay on it is the wallpaper underneath the overlay, which is not the screen.
_CAPTUREBLT: Final[int] = 0x40000000
_BI_RGB: Final[int] = 0
_DIB_RGB_COLORS: Final[int] = 0

MAX_BYTES: Final[int] = 12 * 1024 * 1024
MAX_MILLIS: Final[int] = 400

# Headroom kept before starting another monitor. A capture cannot be stopped once the
# encoder is in it, so the only way to stay inside the budget is to refuse to start one
# that might not fit. 140 ms is the observed cost of a 2560x1440 panel on the desk this
# was built against, which means: start another monitor only when a full panel's worth of
# work still fits. A 1080p laptop primary costs 100-150 ms, so its second monitor is
# still captured; a 1440p primary spends the budget on itself, which is the right order.
_RESERVE_MILLIS: Final[int] = 140

# Pixels sampled for the flat-frame check: enough to see a real desktop, few enough that
# the scan costs nothing next to the encode.
_SAMPLES: Final[int] = 2048
_MAX_COLOURS: Final[int] = 64


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


def _declare() -> None:
    _gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    _gdi32.CreateCompatibleDC.restype = wintypes.HDC

    _gdi32.CreateDIBSection.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(BITMAPINFOHEADER),
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    _gdi32.CreateDIBSection.restype = wintypes.HBITMAP

    _gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    _gdi32.SelectObject.restype = wintypes.HGDIOBJ

    _gdi32.BitBlt.argtypes = [
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
    ]
    _gdi32.BitBlt.restype = wintypes.BOOL

    _gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    _gdi32.DeleteObject.restype = wintypes.BOOL

    _gdi32.DeleteDC.argtypes = [wintypes.HDC]
    _gdi32.DeleteDC.restype = wintypes.BOOL

    _user32.GetDC.argtypes = [wintypes.HWND]
    _user32.GetDC.restype = wintypes.HDC

    _user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    _user32.ReleaseDC.restype = ctypes.c_int


if _gdi32 is not None:
    _declare()


def _monitor_frame(
    monitor: winapi.MonitorInfo, destination: Path
) -> tuple[dict[str, Any], int]:
    """Capture one monitor. Returns ``(record, bytes written)``; record says what happened."""
    width = max(1, monitor.right - monitor.left)
    height = max(1, monitor.bottom - monitor.top)
    stride = width * 4
    started = time.perf_counter()

    record: dict[str, Any] = {
        "device": monitor.device,
        "primary": monitor.primary,
        "bounds": {
            "left": monitor.left,
            "top": monitor.top,
            "right": monitor.right,
            "bottom": monitor.bottom,
        },
        "width": width,
        "height": height,
        "orientation": "landscape" if width >= height else "portrait",
        "file": "",
        "bytes": 0,
        "millis": 0,
        "colours": 0,
        "flat": False,
        "ok": False,
        "reason": "",
    }

    screen = _user32.GetDC(None)
    if not screen:
        record["reason"] = "no desktop dc"
        return record, 0

    memory = _gdi32.CreateCompatibleDC(screen)
    if not memory:
        _user32.ReleaseDC(None, screen)
        record["reason"] = "no memory dc"
        return record, 0

    bits = ctypes.c_void_p(0)
    header = BITMAPINFOHEADER()
    header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    header.biWidth = width
    # Negative height requests a top-down DIB, so row 0 in memory is the top row on
    # screen and the encoder gets a stride that points the same way as the pixels.
    header.biHeight = -height
    header.biPlanes = 1
    header.biBitCount = 32
    header.biCompression = _BI_RGB
    header.biSizeImage = stride * height

    bitmap = _gdi32.CreateDIBSection(
        screen, ctypes.byref(header), _DIB_RGB_COLORS, ctypes.byref(bits), None, 0
    )
    if not bitmap or not bits.value:
        _gdi32.DeleteDC(memory)
        _user32.ReleaseDC(None, screen)
        record["reason"] = "no dib section"
        return record, 0

    previous = _gdi32.SelectObject(memory, bitmap)
    try:
        copied = _gdi32.BitBlt(
            memory,
            0,
            0,
            width,
            height,
            screen,
            monitor.left,
            monitor.top,
            _SRCCOPY | _CAPTUREBLT,
        )
        if not copied:
            record["reason"] = f"bitblt {ctypes.get_last_error()}"
            return record, 0

        colours, flat = _sample(bits.value, width, height, stride)
        record["colours"] = colours
        record["flat"] = flat

        if not gdi.save(bits.value, width, height, stride, destination, "image/png"):
            record["reason"] = "encode failed"
            return record, 0
    finally:
        if previous:
            _gdi32.SelectObject(memory, previous)
        _gdi32.DeleteObject(bitmap)
        _gdi32.DeleteDC(memory)
        _user32.ReleaseDC(None, screen)

    try:
        written = destination.stat().st_size
    except OSError:
        written = 0

    record["file"] = destination.name
    record["bytes"] = written
    record["ok"] = True
    record["millis"] = round((time.perf_counter() - started) * 1000)
    return record, written


def _sample(bits: int, width: int, height: int, stride: int) -> tuple[int, bool]:
    """Distinct colours across a fixed number of pixels, capped. ``(count, flat)``.

    Sampled on a stride that walks both axes, not on a contiguous run: a desktop that is
    wallpaper at the top and one flat colour below is not flat, and reading the first
    kilobyte of the buffer would say it was.
    """
    total = width * height
    if total <= 0:
        return 0, False
    step = max(1, total // _SAMPLES)
    colours: set[int] = set()

    index = 0
    while index < total and len(colours) < _MAX_COLOURS:
        y, x = divmod(index, width)
        try:
            pixel = ctypes.string_at(bits + y * stride + x * 4, 3)
        except (ValueError, OSError):
            break
        colours.add(int.from_bytes(pixel, "little"))
        index += step

    # One sample is a verdict; zero samples is a read that failed, which is not a tell.
    return len(colours), len(colours) == 1 and index >= total


def _order(monitors: list[winapi.MonitorInfo]) -> list[winapi.MonitorInfo]:
    """Primary first, then left-to-right. The primary is the one worth having."""
    return sorted(monitors, key=lambda item: (not item.primary, item.left, item.top))


def run(out_dir: Path, cfg: Any) -> int:
    """Capture every monitor inside the time and byte budget. Returns files written."""
    del cfg  # the budget is the contract; there is nothing to tune per run

    if _gdi32 is None:
        log.logger.debug("screen: not windows")
        return 0

    winapi.enable_dpi_awareness()
    # Outside the clock on purpose: this is process initialisation for the encoder, not
    # capture work, and paying it inside the budget cost a monitor on the desk this was
    # measured on.
    gdi.start()

    monitors = _order(winapi.monitors())
    dpi = winapi.monitor_dpi()

    payload: dict[str, Any] = {
        "count": len(monitors),
        "captured": 0,
        "skipped": [],
        "budget": {"max_bytes": MAX_BYTES, "max_millis": MAX_MILLIS},
        "elapsed_millis": 0,
        "monitors": [],
    }

    written = 0
    total_bytes = 0
    started = time.perf_counter()

    for number, monitor in enumerate(monitors, start=1):
        elapsed_ms = (time.perf_counter() - started) * 1000
        if elapsed_ms + _RESERVE_MILLIS >= MAX_MILLIS:
            payload["skipped"].append({"device": monitor.device, "reason": "time budget"})
            continue

        destination = out_dir / f"screen-{number}.png"
        record, size = _monitor_frame(monitor, destination)
        if size and total_bytes + size > MAX_BYTES:
            # Too big to keep. The file is removed rather than left as a partial member:
            # an archive that lists a screenshot it did not include is worse than one
            # that says the monitor was skipped for size.
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                log.logger.debug("screen: could not drop %s", destination, exc_info=True)
            payload["skipped"].append({"device": monitor.device, "reason": "byte budget"})
            record["ok"] = False
            record["file"] = ""
            record["bytes"] = 0
            record["reason"] = "byte budget"
        elif size:
            total_bytes += size
            written += 1
            payload["captured"] = int(payload["captured"]) + 1

        if monitor.device in dpi:
            record["dpi"] = {"x": dpi[monitor.device][0], "y": dpi[monitor.device][1]}
        else:
            record["dpi"] = {"x": 96, "y": 96}
        payload["monitors"].append(record)

    payload["elapsed_millis"] = round((time.perf_counter() - started) * 1000)
    payload["bytes"] = total_bytes
    # Recorded, not hidden: the pass can only be refused a capture, never interrupted
    # inside one, so a monitor that started at 390 ms can land the pass past the wall.
    payload["overrun_millis"] = max(0, int(payload["elapsed_millis"]) - MAX_MILLIS)

    util.write_json(out_dir / "screen.json", payload)
    log.logger.debug(
        "screen: %d/%d monitors in %d ms, %d bytes",
        written,
        len(monitors),
        payload["elapsed_millis"],
        total_bytes,
    )
    return written


__all__ = ["MAX_BYTES", "MAX_MILLIS", "run"]
