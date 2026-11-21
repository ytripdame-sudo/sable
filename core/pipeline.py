"""Build orchestration: validate, payload, seal, forge, rename.

One entry point, six stages, one ``Outcome``. The order is the dependency order and
each stage refuses to start on the output of a failed one: nothing is sealed that
did not validate, nothing is forged that did not seal, and the finished artifact is
only renamed after it exists.

Nothing here imports ``app/``. Progress is a plain callable taking ``Event``, and the
worker adapts its own Qt signal to it, so the event type carries no toolkit and the
import direction stays ``app`` -> ``core``.

Failures are raised, not returned, and every one carries the stage that raised it.
The exception is a validation failure, which carries the whole problem list instead
of the first line, because the UI has six fields to paint.
"""

from __future__ import annotations

import contextlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from . import forge, rename, seal
from .rename import RenameError
from .schema import RunConfig
from .validate import Problem, blocking, describe, validate

STAGE_VALIDATE: Final[str] = "validate"
STAGE_PAYLOAD: Final[str] = "payload"
STAGE_SEAL: Final[str] = "seal"
STAGE_FORGE: Final[str] = "forge"
STAGE_RENAME: Final[str] = "rename"
STAGE_DONE: Final[str] = "done"

STAGES: Final[tuple[str, ...]] = (
    STAGE_VALIDATE,
    STAGE_PAYLOAD,
    STAGE_SEAL,
    STAGE_FORGE,
    STAGE_RENAME,
    STAGE_DONE,
)

_EXTENSIONS: Final[dict[str, str]] = {forge.OUTPUT_EXE: ".exe", forge.OUTPUT_PY: ".py"}
_WORKING_STEM: Final[str] = "sable-build-"


@dataclass(frozen=True, slots=True)
class Event:
    """One progress step. ``fraction`` is monotonic across a run."""

    stage: str
    message: str
    fraction: float


@dataclass(frozen=True, slots=True)
class Outcome:
    """A finished build. ``artifact`` is the renamed, shipping path."""

    artifact: Path
    mode: str
    size: int
    seconds: float


class PipelineError(RuntimeError):
    """A stage failed. ``stage`` names it and ``artifact`` is set once one exists."""

    def __init__(
        self,
        stage: str,
        message: str,
        *,
        artifact: Path | None = None,
        problems: tuple[Problem, ...] = (),
    ) -> None:
        self.stage = stage
        self.message = message
        self.artifact = artifact
        self.problems = problems
        super().__init__(f"{stage}: {message}")


class ValidationFailed(PipelineError):
    """The form did not pass. ``problems`` holds every failure, not just the first."""


class PipelineCancelled(PipelineError):
    """The caller asked to stop between two stages."""


Progress = Callable[[Event], None]
Cancel = Callable[[], bool]


def _ignore(event: Event) -> None:
    return None


def _emit(progress: Progress, stage: str, message: str, fraction: float) -> None:
    """Deliver one event. A callback that raises does not take the build with it."""
    with contextlib.suppress(Exception):
        progress(Event(stage=stage, message=message, fraction=fraction))


def _check_cancel(cancel: Cancel | None, stage: str) -> None:
    if cancel is not None and cancel():
        raise PipelineCancelled(stage, "cancelled")


def _discard(path: Path) -> None:
    """Remove a working file. A failed cleanup is not worth a second exception."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def _target_name(name: str, mode: str) -> str:
    """Sanitise a caller-supplied name and give it the mode's extension."""
    expected = _EXTENSIONS[mode]
    try:
        cleaned = rename.sanitize(name)
    except RenameError as exc:
        raise PipelineError("output", str(exc)) from exc

    suffix = Path(cleaned).suffix
    if not suffix:
        return cleaned + expected
    if suffix.lower() != expected:
        raise PipelineError("output", f"{mode} output must end {expected}")
    return cleaned


def run(
    cfg: RunConfig,
    *,
    root: Path,
    out_dir: Path,
    mode: str = forge.OUTPUT_EXE,
    name: str | None = None,
    stub: Path | None = None,
    icon: Path | None = None,
    fuse: Path | None = None,
    progress: Progress | None = None,
    cancel: Cancel | None = None,
) -> Outcome:
    """Build the artifact into ``out_dir``. Returns the renamed path.

    ``stub``, ``icon`` and ``fuse`` are build inputs rather than configuration: they are
    files on this machine, they never travel in ``cfg.json``, and the agent cannot see
    any of them by name. Two of them end up inside the artifact — the icon patched into
    the launcher's resources, the bound file welded into the archive — and the launcher
    is the third.
    """
    deliver: Progress = progress or _ignore
    started = time.monotonic()

    def emit(stage: str, message: str, fraction: float) -> None:
        _emit(deliver, stage, message, fraction)

    _check_cancel(cancel, STAGE_VALIDATE)
    emit(STAGE_VALIDATE, "checking the form", 0.0)
    problems = validate(cfg, mode=mode, name=name, stub=stub, icon=icon, fuse=fuse)
    stopped = blocking(problems)
    if stopped:
        raise ValidationFailed(
            STAGE_VALIDATE, describe(stopped), problems=tuple(problems)
        )
    emit(STAGE_VALIDATE, f"form accepted, {len(problems)} note(s)", 0.1)

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PipelineError(STAGE_FORGE, f"{out_dir}: cannot create ({exc.strerror})") from exc

    _check_cancel(cancel, STAGE_PAYLOAD)
    emit(STAGE_PAYLOAD, "assembling the payload", 0.15)
    try:
        payload = forge.payload(root, cfg, fuse=fuse)
    except forge.ForgeError as exc:
        raise PipelineError(STAGE_PAYLOAD, str(exc)) from exc
    emit(STAGE_PAYLOAD, f"payload {len(payload)} bytes", 0.3)

    _check_cancel(cancel, STAGE_SEAL)
    emit(STAGE_SEAL, "sealing", 0.35)
    try:
        sealed = seal.seal(payload, cfg.seal_key)
    except seal.SealError as exc:
        raise PipelineError(STAGE_SEAL, str(exc)) from exc
    emit(STAGE_SEAL, f"sealed {len(sealed)} bytes", 0.5)

    # Built under a working name: forge requires the suffix up front and rename owns
    # legality and collision, so the two are separate stages rather than one guess.
    working = out_dir / f"{_WORKING_STEM}{secrets.token_hex(4)}{_EXTENSIONS[mode]}"

    _check_cancel(cancel, STAGE_FORGE)
    emit(STAGE_FORGE, f"writing {mode} container", 0.55)
    try:
        built = forge.build(cfg, sealed, working, mode=mode, stub=stub, icon=icon)
    except forge.ForgeError as exc:
        raise PipelineError(STAGE_FORGE, str(exc)) from exc

    try:
        size = built.stat().st_size
    except OSError as exc:
        _discard(built)
        raise PipelineError(STAGE_FORGE, f"{built}: cannot stat ({exc.strerror})") from exc
    emit(STAGE_FORGE, f"container {size} bytes", 0.85)

    try:
        _check_cancel(cancel, STAGE_RENAME)
    except PipelineCancelled:
        # A cancelled build must not leave a finished artifact under a working name:
        # the next run would never touch it, and the folder would slowly fill with
        # random 20 MB files nobody asked for.
        _discard(built)
        raise

    emit(STAGE_RENAME, "naming the artifact", 0.9)
    try:
        artifact = rename.rename(
            built,
            name=None if name is None else _target_name(name, mode),
            directory=out_dir,
        )
    except RenameError as exc:
        # The build is good; the name is not. Hand the path back rather than delete it.
        raise PipelineError(STAGE_RENAME, str(exc), artifact=built) from exc

    seconds = time.monotonic() - started
    emit(STAGE_DONE, f"{artifact.name} {size} bytes in {seconds:.2f} s", 1.0)
    return Outcome(artifact=artifact, mode=mode, size=size, seconds=seconds)


__all__ = [
    "STAGES",
    "STAGE_DONE",
    "STAGE_FORGE",
    "STAGE_PAYLOAD",
    "STAGE_RENAME",
    "STAGE_SEAL",
    "STAGE_VALIDATE",
    "Event",
    "Outcome",
    "PipelineCancelled",
    "PipelineError",
    "Progress",
    "ValidationFailed",
    "run",
]
