"""Whole-window smoke: shell builds, gate behaves, a real build runs through the UI."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QApplication

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, str(detail)))


def pump(app, seconds: float = 0.0) -> None:
    deadline = time.monotonic() + seconds
    while True:
        app.processEvents()
        if time.monotonic() >= deadline:
            break
        time.sleep(0.01)


def main() -> int:
    app = QApplication([])
    app.setApplicationName("SableTest")
    app.setOrganizationName("sable-test")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings().clear()

    from app import main as app_main
    from app.shell import MainWindow

    # --- the stack and the scaffold -----------------------------------------
    window = MainWindow()
    check("window builds", window is not None)
    check("window is frameless",
          bool(window.windowFlags() & window.windowFlags().__class__.FramelessWindowHint))
    check("five pages in the stack", window._stack.count() == 5, window._stack.count())
    check("starts on relay", window._stack.currentIndex() == 0, window._stack.currentIndex())

    # every page got the shared scaffold: a heading with its own title
    headings = []
    for index in range(window._stack.count()):
        page = window._stack.widget(index)
        labels = page.findChildren(type(window._rail))
        headings.append(page.findChild(object, "pageTitle") is not None)
    check("every page has a scaffold heading", all(headings), headings)

    # --- rail navigation ----------------------------------------------------
    window._rail._select("tuning")
    pump(app)
    check("rail moves the stack", window._stack.currentIndex() == 2, window._stack.currentIndex())
    window._rail._select("run")
    pump(app)
    check("last route is the run page", window._stack.currentIndex() == 4)

    # --- the gate -----------------------------------------------------------
    check("run starts disabled", not window._run._run.isEnabled())
    gate_text = window._run._gate.text()
    check("gate explains itself", bool(gate_text), gate_text)

    window._relay._endpoint.set_text("https://example.invalid/relay")
    window._relay._kind.setCurrentIndex(0)
    window._tuning._seal_key.set_text("k-3f9a-window-test-key")
    window._tuning._mutex.set_text("Global\\SABLE_WINDOW_TEST")
    with tempfile.TemporaryDirectory(prefix="sable-win-") as scratch:
        window._tuning._output.set_text(scratch)
        window._forge._mode.setCurrentIndex(1)  # py
        pump(app)

        check("gate opens on a valid form", window._run._run.isEnabled(), window._run._gate.text())

        # --- the output folder is part of the gate --------------------------
        chosen_output = window._tuning._output.text()
        window._tuning._output.set_text("")
        pump(app)
        check("an empty output folder closes the gate", not window._run._run.isEnabled())
        check("the folder field shows the problem", window._tuning._output.has_problem(),
              window._tuning._output._message.text())
        window._tuning._output.set_text(chosen_output)
        pump(app)
        check("choosing a folder opens the gate again", window._run._run.isEnabled(),
              window._run._gate.text())

        # --- stopping is a state, not a crash -------------------------------
        window._run.begin()
        window._run.set_stopped("stopping at the next stage boundary")
        pump(app)
        check("a stop request leaves the run counted as running", window._run.is_running())
        check("stop does not re-open the gate while the thread lives",
              not window._run._run.isEnabled())
        window._run.reset()
        window._revalidate()
        pump(app)
        check("a reset run can be built again", window._run._run.isEnabled(),
              window._run._gate.text())

        # --- one click, one real build --------------------------------------
        window._start()
        deadline = time.monotonic() + 120
        while window._worker is not None and time.monotonic() < deadline:
            pump(app, 0.05)
        pump(app, 0.2)

        built = list(Path(scratch).glob("*.py"))
        check("the click produced an artifact", len(built) == 1, [p.name for p in built])
        check("run page reports done", window._run._panel._pill.property("state") == "done",
              window._run._panel._pill.property("state"))
        check("bar reached 100", window._run._panel._bar.value() == 100)
        check("open folder is offered", window._run._open.isEnabled())
        if built:
            check("artifact parses", bool(compile(built[0].read_text(encoding="utf-8"),
                                                  str(built[0]), "exec")))

        # --- gate closes again when the form breaks -------------------------
        window._relay._endpoint.set_text("")
        pump(app)
        check("gate closes on an emptied endpoint", not window._run._run.isEnabled())

        # --- problems land on the owning widget -----------------------------
        window._revalidate()
        check("the endpoint field shows the problem", window._relay._endpoint.has_problem(),
              window._relay._endpoint._message.text())

        # --- all sources off is a rejection, not a crash --------------------
        for box in window._sources._boxes.values():
            box.setChecked(False)
        window._relay._endpoint.set_text("https://example.invalid/relay")
        pump(app)
        check("all sources off closes the gate", not window._run._run.isEnabled())
        for box in window._sources._boxes.values():
            box.setChecked(True)
        pump(app)

        # --- exe mode: a discovered launcher, then a hand-picked one --------
        window._forge._mode.setCurrentIndex(0)
        pump(app)
        discovered = window._forge.stub()
        check(
            "exe mode starts with the launcher this tree built",
            discovered is not None and discovered.is_file(),
            str(discovered),
        )
        check("a discovered launcher opens the gate", window._run._run.isEnabled(),
              window._run._gate.text())

        window._forge._stub.set_text("")
        pump(app)
        check("exe without launcher closes the gate", not window._run._run.isEnabled())

        stub = Path(scratch) / "stub.bin"
        stub.write_bytes(os.urandom(2048))
        window._forge._stub.set_text(str(stub))
        pump(app)
        check("exe with a chosen launcher opens the gate", window._run._run.isEnabled(),
              window._run._gate.text())

        # --- the name preview is the name that ships ------------------------
        window._forge._name.set_text("quarterly")
        pump(app)
        check("preview appends the extension", "quarterly.exe" in window._forge._preview.text(),
              window._forge._preview.text())

        # --- fallbacks are routes, not decoration ---------------------------
        check("no fallback rows to start", window._relay.row_count() == 0)

        row = window._relay.add_row()
        pump(app)
        check("an empty fallback row is not a target", window._relay.targets() == ())
        check("an empty fallback row leaves the gate open", window._run._run.isEnabled(),
              window._run._gate.text())

        row._endpoint.set_text("https://example.invalid/mirror")
        pump(app)
        check("a filled fallback row becomes a target",
              window._relay.targets() == (("https", "https://example.invalid/mirror"),),
              window._relay.targets())
        check("a good fallback leaves the gate open", window._run._run.isEnabled(),
              window._run._gate.text())

        row._endpoint.set_text("https://example.invalid/relay")
        pump(app)
        check("a fallback that repeats the primary closes the gate",
              not window._run._run.isEnabled())
        check("the duplicate is painted on its own row",
              row._endpoint.has_problem(), row._endpoint._message.text())

        row._endpoint.set_text("https://example.invalid/mirror")
        pump(app)
        window._relay._remove_row(row)
        pump(app)
        check("removing a row takes it out of the target list",
              window._relay.row_count() == 0 and window._relay.targets() == ())

        # Left in place so the selector sweep below has the row widgets in the tree.
        window._relay.add_row("link", "https://example.invalid/mirror")
        pump(app)
        check("a row added back is a target again", len(window._relay.targets()) == 1)

    # --- theme switch -------------------------------------------------------
    applied = {}
    original_apply = app_main.apply_theme

    def spy(target, name):
        text = original_apply(target, name)
        applied[name] = len(target.styleSheet())
        return text

    app_main.apply_theme = spy
    start_theme = window._theme
    window._toggle_theme()
    pump(app)
    check("theme switched", window._theme != start_theme, f"{start_theme} -> {window._theme}")
    check("stylesheet actually applied", applied.get(window._theme, 0) > 500,
          applied)
    check("button offers the other theme",
          start_theme.capitalize() in window._theme_button.text(),
          window._theme_button.text())
    check("theme was remembered",
          QSettings().value("ui/theme") == window._theme, QSettings().value("ui/theme"))
    app_main.apply_theme = original_apply

    # --- every object name in the sheet exists in the tree ------------------
    import re as _re

    text = (ROOT / "app" / "theme" / "dark.qss").read_text(encoding="utf-8")
    names = {
        name
        for name in _re.findall(r"#([A-Za-z][A-Za-z0-9_]*)", text)
        if not _re.fullmatch(r"[0-9a-fA-F]{3,8}", name)
    }
    found = {window.objectName()} if window.objectName() else set()
    for widget in window.findChildren(object):
        name = getattr(widget, "objectName", lambda: "")()
        if name:
            found.add(name)
    missing = sorted(name for name in names if name not in found)
    check("dark.qss selectors all exist", not missing, missing)

    light = (ROOT / "app" / "theme" / "light.qss").read_text(encoding="utf-8")
    light_names = {
        name
        for name in _re.findall(r"#([A-Za-z][A-Za-z0-9_]*)", light)
        if not _re.fullmatch(r"[0-9a-fA-F]{3,8}", name)
    }
    check("light.qss defines the same objects", light_names == names,
          sorted(light_names ^ names))

    window.close()
    pump(app, 0.1)

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
