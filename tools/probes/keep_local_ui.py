"""Confirm the Tuning page shows the local-copy checkbox and feeds the config."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication, QCheckBox  # noqa: E402

from app.shell import MainWindow  # noqa: E402

app = QApplication.instance() or QApplication([])
window = MainWindow()

box = window.findChild(QCheckBox, "keepLocal")
print("keepLocal found    ", box is not None)
print("default checked    ", box.isChecked())
print("label              ", box.text())

form = window._collect()
print("cfg keep_local     ", form.keep_local)

box.setChecked(True)
form = window._collect()
print("after tick         ", form.keep_local)

tuning = window._tuning
tuning.reset()
print("after reset        ", box.isChecked())
