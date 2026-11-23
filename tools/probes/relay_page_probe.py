"""Probe the relay page wiring without showing a window.

The two new fields are only useful if the shell reads them, validates them, and paints
the complaint in the right row. That is three links in a chain and this checks all
three on the real widgets.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.shell import MainWindow  # noqa: E402
from core import validate  # noqa: E402

app = QApplication.instance() or QApplication([])
window = MainWindow()

print(f"1. mention defaults to @here: {window._relay.mention()!r}")
print(f"2. ping starts empty: {window._relay.ping()!r}")
print(f"3. collect carries the mention: {window._collect().relay.mention!r}")

window._relay._ping.set_text("https://discord.com/api/webhooks/abc/def")
window._relay._mention.set_text("@everyone")
cfg = window._collect()
print(f"4. collect carries edited values: ping={cfg.relay.ping!r} mention={cfg.relay.mention!r}")

window._relay._ping.set_text("ftp://nope")
window._revalidate()
paths = {
    problem.path
    for problem in validate.validate(
        window._collect(),
        mode=window._forge.mode(),
        name=window._forge.name(),
        stub=window._forge.stub(),
    )
    if problem.path.startswith("relay.")
}
print(f"5. validation names the ping path: {sorted(paths)}")
painted = window._relay._ping._message.text()
print(f"6. ping row carries a message: {painted!r}")

window._relay._ping.set_text("")
window._revalidate()
print(f"7. clearing the ping clears the row: {window._relay._ping._message.text()!r}")

window.close()
app.quit()
print("\nrelay page probe complete")
