"""Run page: the gated Run button, the progress, the terminal state.

The button is disabled until every blocking rule passes, and the reason it is disabled
is written next to it rather than left to be discovered by clicking. That means the page
has to be re-validated on every edit anywhere in the form, which the shell does by
calling ``set_gate`` after each change.

Progress arrives from ``BuildWorker`` signals on the GUI thread. Nothing here reads a
thread field: the worker owns the run, this page owns the pixels.

A failure names the file it died on when there is one. A rename that fails leaves a
complete artifact under a working name, and the message says so instead of reporting a
build that produced nothing.

The gate sentence and the progress panel are in one card because they answer the same
question at two moments: what is stopping this build, and how far has it got.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..widgets.field import Card
from ..widgets.status import ProgressPanel

__all__ = ["RunPage"]


class RunPage(QWidget):
    """Run controls plus the terminal state."""

    run_requested = Signal()
    stop_requested = Signal()
    reveal_requested = Signal(str)

    title: Final[str] = "Run"
    description: Final[str] = "Build the artifact, then transmit nothing until you say so."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._run = QPushButton("Run")
        self._run.setObjectName("runButton")
        self._run.setCursor(Qt.CursorShape.PointingHandCursor)
        self._run.setEnabled(False)
        self._run.clicked.connect(self.run_requested.emit)

        self._stop = QPushButton("Stop")
        self._stop.setObjectName("stopButton")
        self._stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self._stop.setEnabled(False)
        self._stop.clicked.connect(self.stop_requested.emit)

        self._open = QPushButton("Open folder")
        self._open.setObjectName("openButton")
        self._open.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open.setEnabled(False)
        self._open.clicked.connect(self._on_open)

        self._gate = QLabel("")
        self._gate.setObjectName("gate")
        self._gate.setWordWrap(True)

        self._panel = ProgressPanel()
        self._artifact: Path | None = None
        # A stop is requested from the GUI thread but takes effect at the next stage
        # boundary, so the run is still live for a while after the pill says stopped.
        self._stopping = False

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(self._run, 0)
        row.addWidget(self._stop, 0)
        row.addWidget(self._open, 0)
        row.addStretch(1)

        card = Card(
            "Build",
            "The artifact is written to the output directory and nothing leaves this "
            "machine until it is run on a target.",
        )
        card.add_row(row)
        card.body.addWidget(self._gate)
        card.body.addSpacing(6)
        card.add(self._panel)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(18)
        column.addWidget(card)
        column.addStretch(1)

    # --- gate ----------------------------------------------------------------

    def set_gate(self, enabled: bool, reason: str = "") -> None:
        """Enable the Run button, and say why when it is off."""
        running = self._panel.is_busy()
        self._run.setEnabled(bool(enabled) and not running)
        self._stop.setEnabled(running)
        self._gate.setText("" if enabled else reason)
        self._gate.setVisible(bool(reason))
        self._repaint(self._gate)

    def is_running(self) -> bool:
        return self._stopping or self._panel.is_busy()

    def set_stopped(self, message: str = "stopped") -> None:
        """Show a requested stop. The worker is still finishing its current stage."""
        self._stopping = True
        self._stop.setEnabled(False)
        self._run.setEnabled(False)
        self._panel.set_stopped(message)

    # --- state ---------------------------------------------------------------

    def begin(self) -> None:
        self._stopping = False
        self._artifact = None
        self._open.setEnabled(False)
        self._run.setEnabled(False)
        self._stop.setEnabled(True)
        self._gate.setVisible(False)
        self._panel.set_running()

    def on_progress(self, stage: str, message: str, fraction: float) -> None:
        self._panel.set_fraction(fraction)
        self._panel.set_running(f"{stage}: {message}")

    def on_built(self, outcome) -> None:
        self._stopping = False
        self._artifact = Path(outcome.artifact)
        self._stop.setEnabled(False)
        self._open.setEnabled(True)
        size = outcome.size
        self._panel.set_done(f"{self._artifact.name}   {size:,} bytes   {outcome.seconds:.2f} s")

    def on_failed(self, stage: str, message: str, artifact: object) -> None:
        self._stopping = False
        self._stop.setEnabled(False)
        if isinstance(artifact, Path):
            # The build succeeded and only the name failed. Say so, and offer the file.
            self._artifact = artifact
            self._open.setEnabled(True)
            self._panel.set_failed(
                f"{stage}: {message}   artifact kept as {artifact.name}"
            )
            return
        self._panel.set_failed(f"{stage}: {message}")

    def on_rejected(self, problems) -> None:
        self._stopping = False
        self._stop.setEnabled(False)
        if problems:
            self._panel.set_failed("; ".join(str(problem) for problem in problems[:4]))
        else:
            self._panel.set_failed("the form was rejected")

    def reset(self) -> None:
        self._stopping = False
        self._artifact = None
        self._open.setEnabled(False)
        self._stop.setEnabled(False)
        self._panel.reset()

    # --- internals -----------------------------------------------------------

    def _repaint(self, widget: QWidget) -> None:
        # Dynamic properties and visibility-only changes need a re-polish before the
        # stylesheet's new colour applies.
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)

    def _on_open(self) -> None:
        if self._artifact is not None:
            self.reveal_requested.emit(str(self._artifact.parent))
