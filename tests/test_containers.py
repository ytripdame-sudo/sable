"""Container contracts: the payload that comes out is the payload that went in.

A container is the one place in the build where the artifact passes through a format
writer. Everything else either copies bytes or addresses them; here a library decides how
the bytes are laid out, and a library that "helpfully" recompresses or rewrites is a
silent corruption of the container the loader expects.

So the property under test is identity, not shape:

* the member extracted from the zip equals the input, byte for byte
* the archive recovered from the base64 stub equals the input, byte for byte
* the same input renders the same bytes twice — no clock, no locale, no dict ordering
* a name that would land outside the extraction root is refused
"""

from __future__ import annotations

import io
import zipfile

import pytest

from core import containers

PAYLOAD_NAME = "setup.exe"
# Seal-like bytes: no valid UTF-8, no repeating pattern a compressor would find, and long
# enough that a truncated copy cannot accidentally compare equal.
PAYLOAD = bytes(range(256)) * 8 + b"SABLE-CONTAINER-PROOF"
DECOY = ("Invoice.pdf", b"%PDF-1.4\n% decoy\n")


def _members(archive: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(archive)) as handle:
        return {name: handle.read(name) for name in handle.namelist()}


# --- zip --------------------------------------------------------------------


def test_zip_member_is_byte_identical_to_the_input() -> None:
    built = containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])
    archive = built["setup.zip"]
    assert _members(archive)[PAYLOAD_NAME] == PAYLOAD


def test_zip_carries_the_decoy_beside_the_payload() -> None:
    archive = containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.zip"]
    members = _members(archive)
    assert members["Invoice.pdf"] == DECOY[1]
    assert set(members) == {"Invoice.pdf", PAYLOAD_NAME}


def test_zip_puts_the_payload_last() -> None:
    archive = containers.zip_bundle(
        PAYLOAD_NAME, PAYLOAD, [DECOY, ("notes.txt", b"nothing to see")]
    )["setup.zip"]
    with zipfile.ZipFile(io.BytesIO(archive)) as handle:
        assert handle.namelist()[-1] == PAYLOAD_NAME


def test_zip_stores_rather_than_deflates_the_payload() -> None:
    # A sealed payload is ciphertext: deflate saves nothing and a stored member can be
    # compared against the input by the same arithmetic a forensic tool would use.
    archive = containers.zip_bundle(PAYLOAD_NAME, PAYLOAD)["setup.zip"]
    with zipfile.ZipFile(io.BytesIO(archive)) as handle:
        info = handle.getinfo(PAYLOAD_NAME)
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.compress_size == info.file_size == len(PAYLOAD)


def test_zip_is_deterministic() -> None:
    first = containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.zip"]
    second = containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.zip"]
    assert first == second, "no clock in the central directory"


def test_zip_refuses_two_decoys_with_the_same_name() -> None:
    with pytest.raises(containers.ContainerError):
        containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY, DECOY])


def test_zip_refuses_a_decoy_named_like_the_payload() -> None:
    with pytest.raises(containers.ContainerError):
        containers.zip_bundle(PAYLOAD_NAME, PAYLOAD, [(PAYLOAD_NAME, b"decoy")])


@pytest.mark.parametrize("name", ["../escape.exe", r"C:\Windows\x.exe", r"\x.exe"])
def test_zip_refuses_a_member_that_escapes_the_extraction_root(name: str) -> None:
    with pytest.raises(containers.ContainerError):
        containers.zip_bundle(name, PAYLOAD)


def test_zip_refuses_an_empty_member() -> None:
    with pytest.raises(containers.ContainerError):
        containers.zip_bundle(PAYLOAD_NAME, b"")


# --- sfx --------------------------------------------------------------------


def test_sfx_round_trips_the_payload() -> None:
    stub = containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.cmd"]
    archive = containers.sfx_strip(stub)
    assert _members(archive)[PAYLOAD_NAME] == PAYLOAD
    assert _members(archive)["Invoice.pdf"] == DECOY[1]


def test_sfx_skip_count_matches_the_prologue() -> None:
    """The one number in the stub that nothing else can check: ``more +N`` only works if N
    is exactly the number of lines above the base64 body."""
    stub = containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD)["setup.cmd"].decode("ascii")
    lines = stub.split("\r\n")
    skip_line = next(line for line in lines if line.startswith("more +"))
    skip = int(skip_line.split("+")[1].split()[0])
    assert lines[skip] != "", "the body starts at the skipped line"
    assert containers.SFX_MARKER not in lines[skip], "the marker is the last skipped line"
    assert lines[skip - 1] == containers.SFX_MARKER


def test_sfx_never_lets_cmd_parse_the_body() -> None:
    stub = containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD)["setup.cmd"].decode("ascii")
    lines = stub.split("\r\n")
    marker = lines.index(containers.SFX_MARKER)
    assert lines[marker - 1] == "exit /b"


def test_sfx_is_deterministic() -> None:
    first = containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.cmd"]
    second = containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD, [DECOY])["setup.cmd"]
    assert first == second


def test_sfx_refuses_a_stub_that_is_not_a_script() -> None:
    with pytest.raises(containers.ContainerError):
        containers.sfx_bundle(PAYLOAD_NAME, PAYLOAD, stub_name="setup.exe")


def test_sfx_strip_refuses_a_file_that_is_not_a_stub() -> None:
    with pytest.raises(containers.ContainerError):
        containers.sfx_strip(b"@echo off\r\necho hello\r\n")
