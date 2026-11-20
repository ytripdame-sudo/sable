"""Config error paths.

Every rejection has to name the dotted path of the field that caused it, because the
UI paints a field and the operator edits a field. "invalid config" is a message that
costs another round trip.

``ConfigError`` carries ``path`` and ``detail`` separately, so these assert on both:
the path is the contract with the UI, the detail is the contract with a human.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.schema import (  # noqa: E402
    MAX_BALLAST_MB,
    SCHEMA_VERSION,
    ConfigError,
    RelayConfig,
    RunConfig,
    SourceConfig,
    from_dict,
    from_json,
    to_dict,
)


def minimal() -> dict:
    """The smallest document ``from_dict`` accepts: required keys only."""
    return {
        "schema_version": SCHEMA_VERSION,
        "mutex": "Global\\SableTest",
        "seal_key": "k-3f9a-test-key",
        "relay": {"kind": "https", "endpoint": "https://example.invalid/relay"},
        "sources": {},
    }


# --- required fields --------------------------------------------------------


@pytest.mark.parametrize("key", ["schema_version", "mutex", "seal_key", "relay", "sources"])
def test_missing_required_names_the_key(key: str) -> None:
    document = minimal()
    document.pop(key)
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == key, caught.value.path


def test_missing_nested_key_names_the_dotted_path() -> None:
    document = minimal()
    document["relay"] = {"kind": "https"}
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "relay.endpoint"


# --- unknown keys -----------------------------------------------------------


def test_unknown_top_level_key_names_itself() -> None:
    document = minimal()
    document["extra"] = 1
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "extra"
    assert "unknown" in caught.value.detail


def test_unknown_source_key_names_the_dotted_path() -> None:
    document = minimal()
    document["sources"] = {"system": True, "telepathy": True}
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "sources.telepathy"


def test_unknown_relay_key_names_the_dotted_path() -> None:
    document = minimal()
    document["relay"]["headers"] = {}
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "relay.headers"


# --- version ----------------------------------------------------------------


@pytest.mark.parametrize("version", [0, 2, 99])
def test_wrong_version_is_named(version: int) -> None:
    document = minimal()
    document["schema_version"] = version
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "schema_version"


def test_version_is_not_coerced_from_a_string() -> None:
    document = minimal()
    document["schema_version"] = str(SCHEMA_VERSION)
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "schema_version"


# --- types ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "value", "path"),
    [
        ("mutex", 5, "mutex"),
        ("seal_key", [], "seal_key"),
        ("relay", "https://x", "relay"),
        ("ballast_mb", "lots", "ballast_mb"),
        ("self_remove", "yes", "self_remove"),
        ("sources", [], "sources"),
    ],
)
def test_wrong_type_names_the_field(key: str, value: object, path: str) -> None:
    document = minimal()
    document[key] = value
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == path, caught.value.path


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_blank_mutex_and_seal_key_are_rejected(value: str) -> None:
    document = minimal()
    document["mutex"] = value
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "mutex"

    document = minimal()
    document["seal_key"] = value
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "seal_key"


@pytest.mark.parametrize("value", [-1, MAX_BALLAST_MB + 1])
def test_ballast_outside_the_range_is_named(value: int) -> None:
    document = minimal()
    document["ballast_mb"] = value
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "ballast_mb"


def test_ballast_ceiling_is_inclusive() -> None:
    document = minimal()
    document["ballast_mb"] = MAX_BALLAST_MB
    assert from_dict(document).ballast_mb == MAX_BALLAST_MB


def test_unknown_relay_kind_is_named() -> None:
    document = minimal()
    document["relay"]["kind"] = "carrier-pigeon"
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    assert caught.value.path == "relay.kind"


# --- defaults and round trip ------------------------------------------------


def test_optional_fields_take_their_defaults() -> None:
    cfg = from_dict(minimal())
    assert cfg.self_remove is False
    assert cfg.ballast_mb == 0
    assert all(
        getattr(cfg.sources, name)
        for name in ("autofill", "documents", "wallets", "sessions", "system", "browsers")
    )


def test_round_trip_is_lossless() -> None:
    cfg = RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex="Global\\Round",
        seal_key="k-3f9a-round-trip",
        relay=RelayConfig(kind="telegram", endpoint="123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42"),
        sources=SourceConfig(system=False, documents=False),
        self_remove=True,
        ballast_mb=7,
    )
    again = from_dict(to_dict(cfg))
    assert again == cfg


def test_json_round_trip_is_lossless() -> None:
    cfg = from_dict(minimal())
    text = json.dumps(to_dict(cfg))
    assert from_json(text) == cfg


def test_invalid_json_names_the_member() -> None:
    with pytest.raises(ConfigError) as caught:
        from_json("{not json")
    assert caught.value.path == "cfg.json"


def test_error_mentions_both_parts() -> None:
    document = minimal()
    document.pop("mutex")
    with pytest.raises(ConfigError) as caught:
        from_dict(document)
    message = str(caught.value)
    assert "mutex" in message
