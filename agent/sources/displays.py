"""Display inventory.

One artifact, ``displays.json``, from ``winapi.monitors()``. Bounds are the monitor's
own rectangle in virtual-desktop coordinates, which is why a second screen can have a
negative left edge; width and height are derived from the rectangle rather than read
from a mode struct, so they always agree with the bounds beside them.

The gate compares those same derived sizes against two exact modes. This module does
not repeat that judgement; it records what is attached.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from .. import util, winapi

_MAX_MONITORS: Final[int] = 16


def run(out_dir: Path, cfg: Any) -> int:
    """Write ``displays.json``. Returns the number of monitors written."""
    found = winapi.monitors()
    if not found:
        return 0

    entries: list[dict[str, Any]] = []
    left: int | None = None
    top: int | None = None
    right: int | None = None
    bottom: int | None = None

    for monitor in found[:_MAX_MONITORS]:
        width = monitor.right - monitor.left
        height = monitor.bottom - monitor.top
        entries.append(
            {
                "device": monitor.device.strip("\x00"),
                "primary": monitor.primary,
                "width": width,
                "height": height,
                "left": monitor.left,
                "top": monitor.top,
                "right": monitor.right,
                "bottom": monitor.bottom,
                "pixels": width * height,
            }
        )
        left = monitor.left if left is None else min(left, monitor.left)
        top = monitor.top if top is None else min(top, monitor.top)
        right = monitor.right if right is None else max(right, monitor.right)
        bottom = monitor.bottom if bottom is None else max(bottom, monitor.bottom)

    if left is None or top is None or right is None or bottom is None:
        return 0

    payload: dict[str, Any] = {
        "count": len(entries),
        "virtual_desktop": {
            "left": left,
            "top": top,
            "right": right,
            "bottom": bottom,
            "width": right - left,
            "height": bottom - top,
        },
        "monitors": entries,
    }

    if not util.write_json(out_dir / "displays.json", payload):
        return 0
    return len(entries)


__all__ = ["run"]
