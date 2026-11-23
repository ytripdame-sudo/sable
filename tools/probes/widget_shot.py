"""Close-up render of the two widgets whose arrows a stylesheet normally erases."""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "windows")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))
OUT = Path(r"C:\Users\Kuzenee\AppData\Local\Temp\opencode\shots")

from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QComboBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


def main() -> int:
    app = QApplication([])
    from app import main as app_main

    host = QWidget()
    host.setObjectName("card")
    column = QVBoxLayout(host)
    column.setContentsMargins(22, 22, 22, 22)
    column.setSpacing(14)

    combo = QComboBox()
    combo.addItems(["https", "telegram", "link"])
    combo.setFixedWidth(220)

    spin = QSpinBox()
    spin.setRange(0, 4096)
    spin.setValue(256)
    spin.setSuffix(" MB")
    spin.setFixedWidth(150)

    hours = QSpinBox()
    hours.setRange(0, 24)
    hours.setSpecialValueText("on logon only")
    hours.setFixedWidth(190)

    column.addWidget(combo)
    column.addWidget(spin)
    column.addWidget(hours)
    host.resize(320, 210)

    for theme in ("dark", "light"):
        app_main.apply_theme(app, theme)
        host.show()
        app.processEvents()
        app.processEvents()
        target = OUT / f"widgets-{theme}.png"
        host.grab().save(str(target))
        print(target, target.stat().st_size)
        host.hide()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
