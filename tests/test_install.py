"""Staging contracts: the image's *shape* is the unit, not its exe.

The failure this file guards against has already been observed on a real host: an
artifact frozen one-directory, staged as a bare ``.exe``, dies inside the PyInstaller
bootloader with "Failed to load Python DLL" and exit code -1 — before
``agent.loader`` exists to notice. Every byte-level check still passes, because the
trailer is intact and the file is intact; there is simply no interpreter beside it.

So the contracts are about shapes:

* a non-frozen or one-file process stages as one file
* a frozen one-directory process stages as the whole tree, ``_internal`` included
* a copy that does not match its source is reported as a failure, never as success
* the Add/Remove Programs key is named from the identifier, nothing else
* the batch uninstaller removes every artifact ``install`` wrote, in one file
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent import install

# --- shape detection --------------------------------------------------------


def test_tree_root_is_none_when_not_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert install.tree_root() is None


def test_tree_root_detects_a_frozen_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "app"
    (root / install.INTERNAL_DIR).mkdir(parents=True)
    (root / "app.exe").write_bytes(b"MZ")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "app.exe"))

    assert install.tree_root() == root.resolve()


def test_tree_root_rejects_a_frozen_one_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "solo"
    root.mkdir()
    exe = root / "app.exe"
    exe.write_bytes(b"MZ")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))

    assert install.tree_root() is None


# --- inventory and copy verification ---------------------------------------


def test_inventory_counts_files_and_bytes(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.bin").write_bytes(b"x" * 10)
    (tmp_path / "two.bin").write_bytes(b"y" * 5)

    assert install._inventory(tmp_path) == (2, 15)


def test_copy_tree_reports_success_on_a_complete_copy(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "_internal").mkdir(parents=True)
    (source / "app.exe").write_bytes(b"MZ" * 100)
    (source / "_internal" / "python312.dll").write_bytes(b"\x00" * 4096)

    destination = tmp_path / "destination"
    assert install.copy_tree(source, destination) is True
    assert install._inventory(destination) == install._inventory(source)


def test_copy_tree_refuses_to_overwrite_a_different_tree(tmp_path: Path) -> None:
    """A second copy is never attempted on top of a live one; a mismatch is a failure."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.exe").write_bytes(b"MZ" * 10)

    destination = tmp_path / "destination"
    destination.mkdir()
    (destination / "stale.dll").write_bytes(b"\x00" * 999)

    assert install.copy_tree(source, destination) is False


def test_copy_tree_is_idempotent_on_an_identical_tree(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.exe").write_bytes(b"MZ" * 10)

    destination = tmp_path / "destination"
    assert install.copy_tree(source, destination) is True
    assert install.copy_tree(source, destination) is True


def test_copy_tree_fails_on_a_missing_source(tmp_path: Path) -> None:
    assert install.copy_tree(tmp_path / "absent", tmp_path / "destination") is False


# --- staging ----------------------------------------------------------------


def test_stage_image_copies_one_file_when_not_a_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    source = tmp_path / "payload.exe"
    source.write_bytes(b"MZ" + b"\x00" * 256)

    destination = tmp_path / "staged"
    staged = install.stage_image(source, destination)

    assert staged == destination / "payload.exe"
    assert staged is not None and staged.read_bytes() == source.read_bytes()


def test_stage_image_copies_the_whole_tree_when_frozen_as_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "live"
    (root / install.INTERNAL_DIR).mkdir(parents=True)
    exe = root / "sable.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 64)
    (root / install.INTERNAL_DIR / "python312.dll").write_bytes(b"\x00" * 2048)
    (root / install.INTERNAL_DIR / "base_library.zip").write_bytes(b"PK" + b"\x00" * 128)

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))

    destination = tmp_path / "staged"
    staged = install.stage_image(exe, destination)

    assert staged == destination / "sable.exe"
    assert install._inventory(destination) == install._inventory(root)
    assert (destination / install.INTERNAL_DIR / "python312.dll").is_file()


def test_stage_image_reports_none_on_a_missing_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert install.stage_image(tmp_path / "absent.exe", tmp_path / "staged") is None


# --- the Add/Remove Programs record ----------------------------------------


def test_arp_key_is_derived_from_the_identifier() -> None:
    assert install.arp_key("SableHost") == (
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\SableHost"
    )


def test_uninstall_batch_removes_everything_install_wrote(tmp_path: Path) -> None:
    destination = tmp_path / "Programs" / "SableHost"
    text = install.uninstall_batch(
        destination,
        identifier="SableHost",
        run_value="WinSvcHost",
        tasks=("WinSvcHost", "WinSvcHostTimer"),
    )

    assert text.startswith("@echo off\r\n"), "a batch without CRLF misbehaves on cmd.exe"
    assert text.endswith("\r\n")
    assert r'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\SableHost' in text
    assert '/v "WinSvcHost" /f' in text
    assert text.count('schtasks /delete /tn "') == 2
    assert str(destination) in text
    assert 'del "%~f0"' in text, "the batch has to remove itself"

    # Every path in the file is absolute or a key, never a bare relative path: Add/Remove
    # Programs runs the command from whatever directory the shell happens to be in.
    assert "rmdir /s /q \"" in text


def test_uninstall_batch_omits_the_run_key_when_none_was_registered(tmp_path: Path) -> None:
    text = install.uninstall_batch(
        tmp_path / "Programs" / "SableHost", identifier="SableHost", run_value=None, tasks=()
    )
    assert "/v \"" not in text
    assert "schtasks" not in text


def test_uninstall_batch_runs_itself_from_temp(tmp_path: Path) -> None:
    """cmd.exe holds a batch open while reading it, so the folder deletion has to happen
    from a copy that lives outside the folder being deleted."""
    text = install.uninstall_batch(
        tmp_path / "Programs" / "SableHost", identifier="SableHost", run_value=None, tasks=()
    )
    assert 'if defined SABLE_UNINSTALL_TEMP goto :run' in text
    assert 'copy /y "%~f0" "%TEMP%\\~sable-uninstall.cmd"' in text
    assert ":run" in text, "the marker has to have somewhere to jump to"


def test_write_uninstaller_puts_the_script_beside_the_image(tmp_path: Path) -> None:
    destination = tmp_path / "Programs" / "SableHost"
    command = install.write_uninstaller(
        destination, identifier="SableHost", run_value="SableHost", tasks=()
    )

    script = destination / install.UNINSTALL_SCRIPT
    assert command == f'cmd.exe /c ""{script}""'
    assert script.is_file()
    assert script.read_bytes().startswith(b"@echo off\r\n")
