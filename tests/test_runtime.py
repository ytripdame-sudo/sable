"""The runtime contracts: layout ownership, the anti-analysis table, the capture reports.

Everything here is decided by a rule that is cheap to get wrong and expensive to notice:
which module may write which path, which signals make a host hostile, and what a capture
report says when the capture failed. Each test pins one of those rules with the smallest
input that can express it, and nothing here touches a real camera, a real desktop, or a
real Defender.

The capture tests inject an outcome rather than reading hardware. A test that needs a
webcam is a test that passes on one machine and is skipped everywhere else.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import defender, enrich, fingerprint, layout, log, media, platforms, progress, relay  # noqa: E402
from agent import state as run_state  # noqa: E402
from agent.sources import camera, screen  # noqa: E402

# --- layout ------------------------------------------------------------------


def test_captures_is_shared_by_name_and_nothing_else_may_write_there() -> None:
    assert layout.owns("screen", "captures/screen-1.png")
    assert layout.owns("screen", "captures/screen.json")
    assert layout.owns("camera", "captures/camera.jpg")
    assert layout.owns("camera", "captures/camera.json")
    assert not layout.owns("screen", "captures/camera.jpg")
    assert not layout.owns("camera", "captures/screen-2.png")
    assert not layout.owns("documents", "captures/screen-1.png")


def test_a_tree_under_its_own_directory_is_owned() -> None:
    assert layout.owns("browsers", "browsers/Chrome/Default/Cookies")
    assert layout.owns("wallets", "wallets/Exodus/wallet.dat")
    assert not layout.owns("browsers", "wallets/Exodus/wallet.dat")


def test_the_root_and_meta_belong_to_entry_not_to_a_module() -> None:
    assert layout.classify("manifest.json") == ()
    assert layout.classify("meta/gate.json") == ()
    assert layout.classify("captures/screen-1.png") == ("screen",)


def test_every_module_has_a_platform_label() -> None:
    # A new collector with no label lands in the report as "Host" and nobody notices.
    assert set(platforms.MODULE_PLATFORM) == set(layout.MODULE_DIRS)
    for module in layout.MODULE_DIRS:
        assert platforms.platform(module) in platforms.PLATFORMS


def test_the_platform_table_sums_by_platform_and_keeps_zeroes() -> None:
    rows = platforms.table({"system": 1, "network": 2, "browsers": 680, "sessions": 0})
    by_key = {row["platform"]: row for row in rows}
    assert by_key["host"]["items"] == 3
    assert by_key["browser"]["items"] == 680
    assert by_key["discord"]["items"] == 0
    assert by_key["host"]["modules"] == ["system", "network"]
    assert platforms.line({"system": 1, "browsers": 680}) == "Host 1 | Browser profiles 680"


# --- anti-analysis -----------------------------------------------------------


def _clean() -> dict[str, object]:
    """An ordinary desktop: no debugger, no tools, up for a day, windows open."""
    return {
        "processes": set(),
        "modules": set(),
        "uptime_ms": 9 * 24 * 3600 * 1000,
        "debugger": {"local": False, "remote": False},
        "windows": 9,
        "skew_ms": 260,
    }


def test_a_debugger_alone_is_hostile() -> None:
    # One decisive signal is not averaged against three weak ones.
    facts = _clean()
    facts["debugger"] = {"local": True, "remote": False}
    verdict = fingerprint.evaluate(**facts)
    assert verdict.score == 8
    assert verdict.hostile


def test_a_cold_quiet_desktop_is_suspicious_not_hostile() -> None:
    facts = _clean()
    facts["uptime_ms"] = 60_000
    facts["windows"] = 0
    verdict = fingerprint.evaluate(**facts)
    assert verdict.verdict == "suspicious"
    assert {signal.name for signal in verdict.signals} == {"cold-boot", "quiet-desktop"}


def test_a_clean_desktop_is_clean() -> None:
    verdict = fingerprint.evaluate(**_clean())
    assert verdict.score == 0
    assert verdict.verdict == "clean"


def test_the_execution_window_is_recorded_even_when_it_is_not_a_signal() -> None:
    facts = _clean()
    facts["uptime_ms"] = 9 * 86400 * 1000
    block = fingerprint.evaluate(**facts).as_dict()
    assert block["execution_window"] == {"uptime_seconds": 9 * 86400, "cold": False}


def test_a_fast_forwarded_sleep_is_hostile() -> None:
    facts = _clean()
    facts["skew_ms"] = 10
    assert fingerprint.evaluate(**facts).hostile


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("abort", True), ("warn", False), ("off", False)],
)
def test_only_abort_stops_a_hostile_run(mode: str, expected: bool) -> None:
    facts = _clean()
    facts["debugger"] = {"local": True, "remote": False}
    verdict = fingerprint.evaluate(**facts)
    assert fingerprint.should_stop(mode, verdict) is expected


def test_a_suspicious_verdict_does_not_stop_an_abort_run() -> None:
    facts = _clean()
    facts["uptime_ms"] = 60_000
    facts["windows"] = 0
    verdict = fingerprint.evaluate(**facts)
    assert not fingerprint.should_stop("abort", verdict)


# --- run state ---------------------------------------------------------------


def _state_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(run_state, "_root", lambda: tmp_path)
    return tmp_path / run_state.STATE_FILE


def test_a_finished_run_is_not_resumed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _state_file(tmp_path, monkeypatch)
    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    first.to_collecting(tmp_path / "work")
    first.to_collected(tmp_path / "p.zip", "0" * 64, 10)
    first.to_done()

    again = run_state.State.start("C:\\x\\sable.exe", "2", run_id="b")
    assert again.document["run_id"] == "b"
    assert again.stage == "started"


def test_a_collecting_run_resumes_and_keeps_its_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    first.to_collecting(tmp_path / "work")
    first.mark("browsers", 12, 1.5)

    again = run_state.State.start("C:\\x\\sable.exe", "2", run_id="b")
    assert again.document["run_id"] == "a"
    assert again.done_modules() == {"browsers"}
    assert again.counts() == {"browsers": 12}
    assert again.document["resumed"] == 1


def test_a_different_image_is_a_different_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    first.to_collecting(tmp_path / "work")

    again = run_state.State.start("C:\\y\\other.exe", "1", run_id="b")
    assert again.document["run_id"] == "b"


def test_a_failed_module_is_not_counted_as_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    record = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    record.to_collecting(tmp_path / "work")
    record.failed("sessions", "Access is denied")
    assert record.done_modules() == set()
    assert record.failures() == {"sessions": "Access is denied"}


def test_a_resumed_workspace_is_carried_into_the_new_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    old = tmp_path / "old-work"
    (old / layout.MODULE_DIRS["system"]).mkdir(parents=True)
    (old / layout.MODULE_DIRS["system"] / "system.json").write_text("{}", encoding="utf-8")

    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    first.to_collecting(old)
    first.mark("system", 7, 0.1)

    again = run_state.State.start("C:\\x\\sable.exe", "2", run_id="b")
    fresh = tmp_path / "new-work"
    fresh.mkdir()
    carried = again.bring_forward(fresh)

    assert carried == 1
    assert (fresh / layout.MODULE_DIRS["system"] / "system.json").is_file()
    # The file came across, so the module keeps its done mark and its count.
    assert again.done_modules() == {"system"}
    assert again.counts() == {"system": 7}


def test_a_module_whose_files_did_not_survive_is_collected_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    # The recorded workspace is gone, which is what a reboot leaves behind.
    first.to_collecting(tmp_path / "gone")
    first.mark("documents", 814, 2.0)
    first.mark("wallets", 0, 0.2)

    again = run_state.State.start("C:\\x\\sable.exe", "2", run_id="b")
    fresh = tmp_path / "new-work"
    fresh.mkdir()
    assert again.bring_forward(fresh) == 0

    # A count with no file behind it is not resumable. A module that wrote nothing
    # legitimately is: re-running it would produce the same nothing.
    assert again.done_modules() == {"wallets"}


def test_an_abandoned_run_is_not_resumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _state_file(tmp_path, monkeypatch)
    first = run_state.State.start("C:\\x\\sable.exe", "1", run_id="a")
    first.to_collecting(tmp_path / "work")
    first.mark("screen", 1, 0.4)
    first.to_abandoned("uniform capture")

    again = run_state.State.start("C:\\x\\sable.exe", "2", run_id="b")

    # Abandoned is not collecting and not collected, so the next boot starts clean
    # instead of skipping every module and sealing an empty archive.
    assert again.document["run_id"] == "b"
    assert again.stage == "started"
    assert again.done_modules() == set()


# --- camera ------------------------------------------------------------------


def _outcome(**fields: object) -> media.Outcome:
    outcome = media.Outcome()
    for key, value in fields.items():
        setattr(outcome, key, value)
    return outcome


def test_a_captured_frame_is_the_file_the_report_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        media,
        "grab",
        lambda destination: (
            destination.write_bytes(b"\xff\xd8\xff\xe0jpeg"),
            _outcome(status=media.OK, width=1920, height=1080, bytes=8, device="BRIO"),
        )[1],
    )

    assert camera.run(tmp_path, None) == 1
    report = json.loads((tmp_path / "camera.json").read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["captured"] is True
    assert report["file"] == "camera.jpg"
    assert report["width"] == 1920


@pytest.mark.parametrize("status", [media.NO_DEVICE, media.BLOCKED, media.BUSY])
def test_every_refusal_keeps_its_own_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    # The statuses are not collapsed into "error": blocked and busy are facts about the
    # machine's configuration, and no device is a fact about its hardware.
    monkeypatch.setattr(
        media, "grab", lambda destination: _outcome(status=status, reason=status)
    )

    assert camera.run(tmp_path, None) == 0
    report = json.loads((tmp_path / "camera.json").read_text(encoding="utf-8"))
    assert report["status"] == status
    assert report["captured"] is False
    assert report["file"] == ""
    assert not (tmp_path / "camera.jpg").exists()


def test_a_wedged_driver_is_a_timeout_not_a_hang(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def stuck(destination: Path) -> media.Outcome:
        release.wait(10)
        return _outcome(status=media.OK)

    monkeypatch.setattr(media, "grab", stuck)
    monkeypatch.setattr(camera, "MAX_MILLIS", 50)

    started = time.perf_counter()
    try:
        assert camera.run(tmp_path, None) == 0
    finally:
        release.set()

    assert time.perf_counter() - started < 2.0
    report = json.loads((tmp_path / "camera.json").read_text(encoding="utf-8"))
    assert report["status"] == media.TIMEOUT
    assert report["millis"] >= 50


def test_a_grab_that_raises_is_recorded_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(destination: Path) -> media.Outcome:
        raise OSError("driver went away")

    monkeypatch.setattr(media, "grab", boom)
    assert camera.run(tmp_path, None) == 0
    report = json.loads((tmp_path / "camera.json").read_text(encoding="utf-8"))
    assert report["status"] == media.ERROR
    assert "OSError" in report["reason"]


def test_a_timeout_drops_a_half_written_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def writes_then_hangs(destination: Path) -> media.Outcome:
        destination.write_bytes(b"\xff\xd8partial")
        release.wait(10)
        return _outcome(status=media.OK)

    monkeypatch.setattr(media, "grab", writes_then_hangs)
    monkeypatch.setattr(camera, "MAX_MILLIS", 50)
    try:
        assert camera.run(tmp_path, None) == 0
    finally:
        release.set()
    assert not (tmp_path / "camera.jpg").exists()


# --- screen ------------------------------------------------------------------


def test_the_screen_report_names_its_budget_and_every_monitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Monitor:
        def __init__(self, device: str, left: int, primary: bool) -> None:
            self.device = device
            self.left = left
            self.top = 0
            self.right = left + 1920
            self.bottom = 1080
            self.primary = primary

    monkeypatch.setattr(
        screen.winapi, "monitors", lambda: [Monitor("\\\\.\\DISPLAY1", 0, True)]
    )
    monkeypatch.setattr(screen.winapi, "monitor_dpi", lambda: {})
    monkeypatch.setattr(screen, "_monitor_frame", lambda monitor, path: (_record(path), 0))
    monkeypatch.setattr(screen.gdi, "save", lambda *a, **k: True)

    screen.run(tmp_path, None)
    report = json.loads((tmp_path / "screen.json").read_text(encoding="utf-8"))
    assert report["budget"] == {"max_bytes": screen.MAX_BYTES, "max_millis": screen.MAX_MILLIS}
    assert report["count"] == 1
    assert report["monitors"][0]["device"] == "\\\\.\\DISPLAY1"
    assert report["monitors"][0]["primary"] is True


def _record(path: Path) -> dict[str, object]:
    return {
        "device": "\\\\.\\DISPLAY1",
        "primary": True,
        "bounds": {"left": 0, "top": 0, "right": 1920, "bottom": 1080},
        "width": 1920,
        "height": 1080,
        "orientation": "landscape",
        "file": "",
        "bytes": 0,
        "millis": 0,
        "colours": 0,
        "flat": False,
        "ok": False,
        "reason": "encode failed",
    }


def test_the_primary_monitor_is_captured_first() -> None:
    class Monitor:
        def __init__(self, device: str, left: int, primary: bool) -> None:
            self.device = device
            self.left = left
            self.top = 0
            self.primary = primary

    ordered = screen._order(
        [
            Monitor("left", -1920, False),
            Monitor("secondary", 1920, False),
            Monitor("primary", 0, True),
        ]
    )
    assert [monitor.device for monitor in ordered] == ["primary", "left", "secondary"]


# --- upload progress ---------------------------------------------------------


def test_the_body_reports_every_byte_it_hands_over(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("a.bin", b"x" * (2 * relay._CHUNK + 17))

    body = relay._Body(b"head", archive, b"tail")
    seen: list[int] = []
    relay.set_progress(seen.append)
    try:
        total = sum(len(block) for block in body)
    finally:
        relay.set_progress(None)

    assert total == len(body)
    assert sum(seen) == total
    assert len(seen) > 2, "the file is read in more than one block"


def test_the_body_tells_the_sink_its_real_length(tmp_path: Path) -> None:
    """The file size is an estimate; the body length is what the counter measures."""
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"PK\x03\x04" + b"z" * 5000)

    reporter = progress.Reporter(archive.stat().st_size)
    relay.set_progress(reporter)
    try:
        body = relay._Body(b"h" * 400, archive, b"t" * 300)
    finally:
        relay.set_progress(None)

    assert reporter.total == len(body)
    assert reporter.total > archive.stat().st_size


def test_progress_never_reports_more_than_the_total(tmp_path: Path) -> None:
    reporter = progress.Reporter(1000)
    reporter.expect(1200)
    reporter.advance(600)
    assert reporter.percent == 50
    reporter.advance(700)
    assert reporter.percent == 100
    assert reporter.sent == 1300


# --- the log in a frozen run -------------------------------------------------


def test_a_traceback_that_cannot_be_rendered_still_writes_the_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inside a frozen payload, source lines live in a zip that may already be closed.

    Rendering the traceback then raises from ``linecache``/zipimport, logging swallows
    the failure, and the record disappears — which is how a refused rename left only
    "keeping payload.zip" and nothing about why.
    """
    formatter = log._SourceSafeFormatter("%(message)s")

    try:
        raise RuntimeError("the zip is closed")
    except RuntimeError:
        info = sys.exc_info()

    record = logging.LogRecord("sable", logging.DEBUG, __file__, 1, "boom", None, info)

    def _hostile(self: logging.Formatter, ei: object) -> str:
        raise EOFError("EOF read where not expected")

    monkeypatch.setattr(logging.Formatter, "formatException", _hostile)
    text = formatter.format(record)

    assert "boom" in text
    assert "RuntimeError: the zip is closed" in text


def test_a_progress_sink_that_raises_does_not_break_the_upload(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"PK\x03\x04" + b"y" * 4096)

    def hostile(count: int) -> None:
        raise RuntimeError("the log is on fire")

    body = relay._Body(b"head", archive, b"tail")
    relay.set_progress(hostile)
    try:
        assert sum(len(block) for block in body) == len(body)
    finally:
        relay.set_progress(None)


def test_the_reporter_reports_on_steps_and_always_finishes() -> None:
    seen: list[int] = []
    reporter = progress.Reporter(1000, lambda percent, *_: seen.append(percent), step=25)
    for _ in range(10):
        reporter.advance(100)
    reporter.finish()
    assert seen[0] == 10
    assert seen[-1] == 100
    assert seen == sorted(seen)
    assert len(seen) <= 6


# --- defender ----------------------------------------------------------------


class _Completed:
    def __init__(self, text: str, code: int = 0) -> None:
        self.stdout = text.encode()
        self.returncode = code


def test_an_accepted_exclusion_is_recorded_as_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    image = tmp_path / "sable.exe"
    image.write_bytes(b"MZ")
    workspace = tmp_path / "work"
    workspace.mkdir()

    monkeypatch.setattr(defender.util, "executable_path", lambda: image)
    monkeypatch.setattr(
        defender,
        "_powershell",
        lambda: Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    )
    monkeypatch.setattr(
        defender.util,
        "run_hidden",
        lambda *a, **k: _Completed(f"OK {workspace};{image}"),
    )

    record = defender.exclusions(workspace)
    assert record["status"] == defender.OK
    assert record["added"] == [str(workspace), str(image)]
    assert record["requested"]
    assert str(workspace) in record["requested"]


def test_a_refusal_is_recorded_and_the_run_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        defender.util, "run_hidden", lambda *a, **k: _Completed("DENIED Access is denied")
    )
    monkeypatch.setattr(defender, "_powershell", lambda: Path("powershell.exe"))

    record = defender.exclusions(Path(r"C:\x"))
    assert record["status"] == defender.BLOCKED
    assert "Access is denied" in record["reason"]
    assert record["added"] == []


def test_a_call_that_changes_nothing_is_not_a_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Tamper Protection has been seen to accept the call and leave the list empty.
    monkeypatch.setattr(defender.util, "run_hidden", lambda *a, **k: _Completed("OK "))
    monkeypatch.setattr(defender, "_powershell", lambda: Path("powershell.exe"))

    record = defender.exclusions(Path(r"C:\x"))
    assert record["status"] == defender.BLOCKED
    assert "changed nothing" in record["reason"]


def test_no_powershell_is_a_failure_not_an_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(defender, "_powershell", lambda: None)
    record = defender.exclusions(Path(r"C:\x"))
    assert record["status"] == defender.FAILED


def test_an_exclusion_that_was_already_there_is_not_claimed_as_added(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Withdrawal removes what this run added; a pre-existing entry is somebody else's.

    Measured in the guest: a second run re-requested the image path that the first run
    had left behind and then withdrew it, so the machine ended with fewer exclusions
    than it started with.
    """
    image = tmp_path / "sable.exe"
    image.write_bytes(b"MZ")
    workspace = tmp_path / "work"
    workspace.mkdir()

    monkeypatch.setattr(defender.util, "executable_path", lambda: image)
    monkeypatch.setattr(defender, "_powershell", lambda: Path("powershell.exe"))
    monkeypatch.setattr(
        defender.util,
        "run_hidden",
        lambda *a, **k: _Completed(f"OK|{image}|{image};{workspace}"),
    )

    record = defender.exclusions(workspace)

    assert record["status"] == defender.OK
    assert record["added"] == [str(workspace)]
    assert str(image) in record["requested"]


def test_the_exclusions_this_run_added_are_taken_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One temp path per run accumulated on the guest: six after six runs."""
    seen: list[list[str]] = []

    def _record(args: list[str], **_kwargs: object) -> _Completed:
        seen.append(list(args))
        return _Completed("OK")

    monkeypatch.setattr(defender, "_powershell", lambda: Path("powershell.exe"))
    monkeypatch.setattr(defender.util, "run_hidden", _record)

    defender.withdraw({"status": defender.OK, "added": [r"C:\Users\b\Temp\sable-collect-1"]})

    assert len(seen) == 1
    command = seen[0][-1]
    assert "Remove-MpPreference" in command
    assert r"C:\Users\b\Temp\sable-collect-1" in command


def test_withdrawing_nothing_asks_defender_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def _record(args: list[str], **_kwargs: object) -> _Completed:
        seen.append(list(args))
        return _Completed("OK")

    monkeypatch.setattr(defender.util, "run_hidden", _record)

    # Not first run, refused, or never attempted: an empty list must not become a call.
    defender.withdraw({"status": defender.BLOCKED, "reason": "denied", "added": []})
    defender.withdraw({"status": defender.SKIPPED, "reason": "not first run"})

    assert seen == []


# --- enrichment --------------------------------------------------------------


def test_enrichment_reads_the_reports_and_writes_nothing(tmp_path: Path) -> None:
    layout.prepare(tmp_path)
    (tmp_path / "accounts" / "roblox_status.json").write_text(
        json.dumps({"cookie": ".ROBLOSECURITY", "found": 2, "reason": ""}), encoding="utf-8"
    )
    (tmp_path / "accounts" / "sessions.json").write_text(
        json.dumps([{"token": "t", "valid": True, "username": "bench"}]), encoding="utf-8"
    )
    (tmp_path / "captures" / "camera.json").write_text(
        json.dumps({"status": "blocked", "reason": "privacy setting"}), encoding="utf-8"
    )

    before = sorted(path.name for path in tmp_path.rglob("*"))
    block = enrich.collect(tmp_path)
    after = sorted(path.name for path in tmp_path.rglob("*"))

    assert before == after, "enrichment must not write"
    assert block["accounts"][0] == {"platform": "roblox", "count": 2}
    assert block["accounts"][1]["name"] == "bench"
    assert block["camera"]["status"] == "blocked"

    lines = enrich.lines(block, {"roblox": 2, "sessions": 1})
    assert any("Roblox 2" in line for line in lines)
    assert any("camera" in line and "blocked" in line for line in lines)


def test_enrichment_of_an_empty_workspace_is_empty() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        assert enrich.collect(Path(folder)) == {}


def test_enrichment_refuses_a_report_that_is_not_the_shape_it_expects(
    tmp_path: Path,
) -> None:
    layout.prepare(tmp_path)
    (tmp_path / "accounts" / "sessions.json").write_text("{}", encoding="utf-8")
    (tmp_path / "system" / "system.json").write_text('["not", "an", "object"]', encoding="utf-8")
    assert enrich.collect(tmp_path) == {}
