"""Filesystem helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import util  # noqa: E402


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
