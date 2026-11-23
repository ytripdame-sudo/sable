"""Headless UI smoke: widgets construct, rail navigates, worker builds for real."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication

from app.rail import RAIL_WIDTH, ROUTES, Rail
from app.widgets.field import LabelledEdit
from app.widgets.status import DONE, FAILED, IDLE, RUNNING, ProgressPanel, StatusPill
from app.worker import SOURCE_LABELS, BuildWorker, config_from

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, str(detail)))


def main() -> int:
    app = QApplication([])

    # --- field ---------------------------------------------------------------
    field = LabelledEdit("Endpoint", placeholder="https://", text="https://x.test")
    check("field holds text", field.text() == "https://x.test", field.text())
    field.set_problem("must not be empty")
    check("field paints a problem", field.has_problem())
    field.set_text("https://y.test")
    check("programmatic set clears the stale problem", not field.has_problem())
    emitted: list[str] = []
    field.changed.connect(emitted.append)
    field.set_text("https://z.test")
    check("programmatic set emits changed", emitted == ["https://z.test"], emitted)

    picker = LabelledEdit("Output", browse=True)
    check("browse flag builds a picker", picker._browse is not None)
    picker.set_text("")
    check("blank path is None", picker.path() is None)
    picker.set_text(str(ROOT))
    check("path round-trips", picker.path() == ROOT, picker.path())

    # --- status --------------------------------------------------------------
    panel = ProgressPanel()
    check("panel starts idle", not panel.is_busy())
    panel.set_running()
    check("panel reports busy", panel.is_busy())
    panel.set_fraction(0.42)
    check("fraction clamps into 0..100", panel._bar.value() == 42, panel._bar.value())
    panel.set_fraction(-5.0)
    check("negative clamps to 0", panel._bar.value() == 0, panel._bar.value())
    panel.set_fraction(9.0)
    check("over one clamps to 100", panel._bar.value() == 100, panel._bar.value())
    panel.set_done("built")
    check("done is not busy", not panel.is_busy())
    check("done fills the bar", panel._bar.value() == 100)
    panel.set_failed("nope")
    check("failed labels the pill", panel._pill.property("state") == FAILED)
    panel.reset()
    check("reset returns to idle", panel._pill.property("state") == IDLE)

    # --- rail ----------------------------------------------------------------
    rail = Rail()
    seen: list[str] = []
    rail.navigated.connect(seen.append)
    check("rail width is 220", rail.width() == RAIL_WIDTH, rail.width())
    check("rail has five routes", len(rail._buttons) == 5, len(rail._buttons))
    check("rail starts on the first route", rail._buttons[ROUTES[0][0]].isChecked())
    rail._select("tuning")
    check("select emits once", seen == ["tuning"], seen)
    check("select moves the accent", rail._buttons["tuning"].property("active") is True)
    check(
        "previous route is deactivated",
        rail._buttons[ROUTES[0][0]].property("active") is False,
    )
    labelled = [b.text() for b in rail._buttons.values()]
    check("every button carries a glyph and a label",
          all(len(t.split()) >= 2 for t in labelled), labelled)

    # --- worker: real build --------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="sable-ui-") as scratch:
        out = Path(scratch) / "out"

        cfg = config_from(
            relay_kind="https",
            endpoint="https://example.invalid/relay",
            mutex="Global\\SABLE_UI_TEST",
            seal_key="k-3f9a-ui-test-key",
            sources={name: True for name, _ in SOURCE_LABELS},
            self_remove=False,
            ballast_mb=0,
        )
        check("config_from builds six sources",
              all(getattr(cfg.sources, name) for name, _ in SOURCE_LABELS))

        worker = BuildWorker(
            cfg, root=ROOT, out_dir=out, mode="py", name=None, stub=None
        )
        events: list[tuple[str, str, float]] = []
        built: list[object] = []
        failures: list[tuple[str, str, object]] = []
        worker.progress.connect(lambda s, m, f: events.append((s, m, f)))
        worker.built.connect(built.append)
        worker.failed.connect(lambda s, m, a: failures.append((s, m, a)))
        worker.start()
        ok = worker.wait(180_000)
        app.processEvents()

        check("worker finished", ok)
        check("worker emitted no failure", not failures, str(failures))
        check("worker produced one outcome", len(built) == 1, len(built))
        check("worker emitted progress", len(events) >= 8, len(events))
        check("progress covers every stage",
              {s for s, _, _ in events} >= {"validate", "payload", "seal", "forge", "rename", "done"},
              sorted({s for s, _, _ in events}))
        if built:
            artifact = built[0].artifact
            check("artifact exists on disk", artifact.is_file(), artifact)

        # --- worker: rejected config -----------------------------------------
        bad = config_from(
            relay_kind="https",
            endpoint="",
            mutex="Global\\SABLE_UI_TEST",
            seal_key="k-3f9a-ui-test-key",
            sources={name: True for name, _ in SOURCE_LABELS},
            self_remove=False,
            ballast_mb=0,
        )
        rejected: list[object] = []
        worker2 = BuildWorker(bad, root=ROOT, out_dir=out, mode="py", name=None, stub=None)
        worker2.rejected.connect(rejected.append)
        worker2.start()
        check("second worker finished", worker2.wait(60_000))
        app.processEvents()
        check("empty endpoint is rejected", len(rejected) == 1, len(rejected))
        if rejected:
            paths = {p.path for p in rejected[0]}
            check("rejection names relay.endpoint", "relay.endpoint" in paths, str(paths))

        # --- worker: cancel before start -------------------------------------
        cancelled: list[tuple[str, str, object]] = []
        worker3 = BuildWorker(cfg, root=ROOT, out_dir=out, mode="py", name=None, stub=None)
        worker3.failed.connect(lambda s, m, a: cancelled.append((s, m, a)))
        worker3.cancel()
        worker3.start()
        check("third worker finished", worker3.wait(60_000))
        app.processEvents()
        check("pre-cancel stops at validate", cancelled and cancelled[0][0] == "cancelled", str(cancelled))

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
