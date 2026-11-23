"""Dump widget geometry and paint flags so a layout defect can be measured, not guessed."""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "windows")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402


def main() -> int:
    app = QApplication([])
    app.setApplicationName("SableDump")
    app.setOrganizationName("sable-dump")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings().clear()

    from app.shell import MainWindow

    window = MainWindow()
    window.resize(1280, 820)
    window.show()
    app.processEvents()
    app.processEvents()

    def walk(widget: QWidget, depth: int = 0) -> None:
        if depth > 6:
            return
        name = widget.objectName() or widget.metaObject().className()
        geo = widget.geometry()
        print(
            f"{'  ' * depth}{name:<22} {widget.metaObject().className():<20} "
            f"x={geo.x():<5} y={geo.y():<5} w={geo.width():<5} h={geo.height():<5} "
            f"visible={int(widget.isVisible())}"
        )
        for child in widget.children():
            if isinstance(child, QWidget):
                walk(child, depth + 1)

    walk(window)

    print("\n--- card style ---")
    from app.widgets.field import Card

    card = window.findChild(Card)
    if card is not None:
        print("card geometry:", card.geometry())
        print("card layout margins:", card.layout().contentsMargins())
        print("card visible:", card.isVisible())
        print("styled background:", card.testAttribute(
            card.WidgetAttribute.WA_StyledBackground))
    else:
        print("no Card found")

    print("\n--- scroll internals ---")
    from PySide6.QtWidgets import QScrollArea

    scroll = window.findChild(QScrollArea)
    if scroll is not None:
        print("scroll:", scroll.geometry())
        print("viewport:", scroll.viewport().geometry())
        print("widget:", scroll.widget().geometry() if scroll.widget() else None)

    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
