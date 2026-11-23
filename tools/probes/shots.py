"""Render every page to a PNG so the layout can be looked at without a display.

    python tools/probes/shots.py [outdir]

Writes one image per route per theme, plus a tall window at the minimum size so
compression is visible when it exists.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "windows")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\Kuzenee\AppData\Local\Temp\opencode\shots")
ROUTES = ("relay", "sources", "tuning", "forge", "run")


def sample_icon(target: Path) -> Path:
    """A real 32px ``.ico``, so the forge page is photographed with a filled field."""
    size = 32
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = bytes([0x50, 0x30, 0x18, 0xFF]) * (size * size)
    image = header + pixels + bytes(size * size // 8)
    entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(image), 22)
    target.write_bytes(struct.pack("<HHH", 0, 1, 1) + entry + image)
    return target


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    app = QApplication([])
    app.setApplicationName("SableShots")
    app.setOrganizationName("sable-shots")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings().clear()

    from app import main as app_main
    from app.shell import MainWindow

    window = MainWindow()
    window.resize(1280, 820)
    window.show()
    app.processEvents()

    # A valid-looking form so the gate, preview and error states are not blank.
    window._relay._endpoint.set_text("https://discord.com/api/webhooks/1234/abcdef")
    window._relay._ping.set_text("https://discord.com/api/webhooks/1234/abcdef")
    # Two fallbacks so the card shows a live row and an empty one; a card photographed
    # empty is a card nobody can judge.
    window._relay.add_row("telegram", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42")
    window._relay.add_row()
    window._tuning._seal_key.set_text("k-3f9a-demo-seal-key-0123456789")
    window._tuning._output.set_text(r"C:\Users\Kuzenee\Desktop\builds")
    window._tuning._keep_local.setChecked(True)
    window._tuning._persist.setChecked(True)
    window._tuning._persist_hours.setValue(6)
    window._tuning._ballast.setValue(256)
    window._forge._icon.set_text(str(sample_icon(OUT / "sample.ico")))
    window._forge._fuse.set_text(str(ROOT / "tools" / "dist" / "sable-launcher.exe"))
    app.processEvents()

    for theme in ("dark", "light"):
        app_main.apply_theme(app, theme)
        app.processEvents()
        for route in ROUTES:
            window._rail._select(route)
            app.processEvents()
            app.processEvents()
            target = OUT / f"{theme}-{route}.png"
            window.grab().save(str(target))
            print(f"{target}  {target.stat().st_size} bytes")

        # The narrow case: the size where the old layout clipped its fields.
        window._rail._select("tuning")
        window.resize(1000, 660)
        app.processEvents()
        app.processEvents()
        target = OUT / f"{theme}-tuning-small.png"
        window.grab().save(str(target))
        print(f"{target}  {target.stat().st_size} bytes")
        window.resize(1280, 820)
        app.processEvents()

    # An error state, since that is where the overlap was.
    app_main.apply_theme(app, "dark")
    window._rail._select("tuning")
    window._tuning._seal_key.set_text("")
    window._revalidate()
    app.processEvents()
    target = OUT / "dark-tuning-error.png"
    window.grab().save(str(target))
    print(f"{target}  {target.stat().st_size} bytes")

    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
