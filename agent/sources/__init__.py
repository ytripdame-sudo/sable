"""Collector registry.

One entry per ``SourceConfig`` flag. ``system`` owns three modules, because network
and display inventory are part of the system picture and have no flag of their own.

Every collector obeys the same contract: ``run(out_dir, cfg) -> int``, returning the
number of items written. A collector that raises is logged and counted as zero, so
one broken artifact source cannot take the rest of the run with it.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Final

from .. import log

# flag on SourceConfig -> module names, in the order they run
_PLAN: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("system", ("system", "network", "displays")),
    ("browsers", ("browsers",)),
    ("sessions", ("sessions",)),
    ("wallets", ("wallets",)),
    ("autofill", ("autofill",)),
    ("documents", ("documents",)),
)


def run_all(out_dir: Path, cfg: Any) -> dict[str, int]:
    """Run every enabled collector. Returns module name -> items written."""
    counts: dict[str, int] = {}

    for flag, modules in _PLAN:
        if not getattr(cfg.sources, flag):
            log.logger.debug("sources: %s disabled", flag)
            continue
        for name in modules:
            counts[name] = _run_one(name, out_dir, cfg)

    return counts


def _run_one(name: str, out_dir: Path, cfg: Any) -> int:
    try:
        module = importlib.import_module(f".{name}", __name__)
    except Exception:
        log.logger.exception("sources: %s could not be imported", name)
        return 0

    runner = getattr(module, "run", None)
    if runner is None:
        log.logger.error("sources: %s has no run()", name)
        return 0

    try:
        written = int(runner(out_dir, cfg))
    except Exception:
        log.logger.exception("sources: %s raised", name)
        return 0

    log.logger.debug("sources: %s wrote %d", name, written)
    return written


__all__ = ["run_all"]
