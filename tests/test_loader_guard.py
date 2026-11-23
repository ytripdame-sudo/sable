"""A launcher with no payload behind it refuses. It must not hang.

The mutex name lives in the artifact trailer, so a stub copied without one has no name
to guard with. That failure used to escape :func:`agent.loader.boot` before its first
try block, and a windowed build turns an escaping exception into a modal traceback with
no way to close it from a script: the process sits on the dialog forever. A probe that
ran the bare stub then waited on a pipe that never closed, so the defect read as a hang
in the probe rather than as a refusal that never happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import loader


def _bare_stub(tmp_path: Path) -> Path:
    # Big enough to pass the "cannot carry a trailer" size floor, so the failure is the
    # missing magic rather than the length.
    stub = tmp_path / "bare.exe"
    stub.write_bytes(b"MZ" + b"\x00" * 8192)
    return stub


def test_boot_refuses_a_stub_with_no_trailer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    stub = _bare_stub(tmp_path)
    monkeypatch.setattr(loader.util, "executable_path", lambda: stub)

    assert loader.boot() == 1


def test_boot_does_not_let_the_guard_exception_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub = _bare_stub(tmp_path)
    monkeypatch.setattr(loader.util, "executable_path", lambda: stub)

    def explode(_argv: list[str]) -> bool:
        raise loader.ArchiveError("mutex slot is empty")

    monkeypatch.setattr(loader, "_guarded", explode)

    assert loader.boot() == 1
