"""Read the agent's config out of the running archive.

``agent/`` may not import ``core/``, and the config schema has to exist in exactly
one place. ``core/forge.py`` copies ``core/schema.py`` into the archive verbatim as
``sable_schema.py``; this module loads that member and calls its ``from_json``. One
reader, one set of dataclasses, no duplicated validation.

The loaded config is typed as ``Any`` on purpose. ``tests/test_contracts.py`` asserts
that the shipped schema's dataclasses match ``core.schema`` field for field, which
is the guarantee a static import would have given without crossing the boundary.
"""

from __future__ import annotations

import sys
import zipfile
from types import ModuleType
from typing import Any, Final

from . import log

SCHEMA_MEMBER: Final[str] = "sable_schema.py"
CONFIG_MEMBER: Final[str] = "cfg.json"
MAX_SCHEMA_BYTES: Final[int] = 256 * 1024
MAX_CONFIG_BYTES: Final[int] = 256 * 1024

_schema: ModuleType | None = None


class ConfigLoadError(RuntimeError):
    """The archive is missing a member, or a member is unusable.

    Content defects come back as the schema's own ``ConfigError``; this type covers
    the packaging failures that happen before the schema ever sees the document.
    """


def _load_schema(archive: zipfile.ZipFile) -> ModuleType:
    global _schema
    if _schema is not None:
        return _schema

    try:
        info = archive.getinfo(SCHEMA_MEMBER)
    except KeyError as exc:
        raise ConfigLoadError(f"{SCHEMA_MEMBER}: member missing from archive") from exc
    if info.file_size > MAX_SCHEMA_BYTES:
        raise ConfigLoadError(f"{SCHEMA_MEMBER}: {info.file_size} bytes exceeds the cap")

    source = archive.read(SCHEMA_MEMBER)
    module = ModuleType("sable_schema")
    module.__file__ = SCHEMA_MEMBER
    try:
        exec(compile(source, SCHEMA_MEMBER, "exec"), module.__dict__)
    except SyntaxError as exc:
        raise ConfigLoadError(f"{SCHEMA_MEMBER}: does not compile ({exc.msg})") from exc

    if not hasattr(module, "from_json"):
        raise ConfigLoadError(f"{SCHEMA_MEMBER}: no from_json")

    # Unconditional: a stale sable_schema left in sys.modules must never win over
    # the copy that is actually inside this archive.
    sys.modules["sable_schema"] = module
    _schema = module
    return module


def load(archive: zipfile.ZipFile) -> Any:
    """Validate ``cfg.json`` from the archive and return the frozen config."""
    schema = _load_schema(archive)

    try:
        info = archive.getinfo(CONFIG_MEMBER)
    except KeyError as exc:
        raise ConfigLoadError(f"{CONFIG_MEMBER}: member missing from archive") from exc
    if info.file_size > MAX_CONFIG_BYTES:
        raise ConfigLoadError(f"{CONFIG_MEMBER}: {info.file_size} bytes exceeds the cap")

    raw = archive.read(CONFIG_MEMBER)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigLoadError(f"{CONFIG_MEMBER}: not UTF-8 ({exc.reason})") from exc

    cfg = schema.from_json(text)
    log.logger.debug("config: schema_version=%s kind=%s", cfg.schema_version, cfg.relay.kind)
    return cfg


__all__ = [
    "CONFIG_MEMBER",
    "SCHEMA_MEMBER",
    "ConfigLoadError",
    "load",
]
