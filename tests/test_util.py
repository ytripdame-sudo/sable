"""Filesystem helpers."""

from __future__ import annotations

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
