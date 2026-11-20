"""Run page: the gated Run button, the progress, the terminal state.

The button is disabled until every blocking rule passes, and the reason it is disabled
is written next to it rather than left to be discovered by clicking. That means the
page has to be re-validated on every edit anywhere in the form, which the shell does
by calling ``set_gate`` after each change.

Progress arrives from ``BuildWorker`` signals on the GUI thread. Nothing here reads a
thread field: the worker owns the run, this page owns the pixels.

A failure names the file it died on when there is one. A rename that fails leaves a
complete artifact under a working name, and the message says so instead of reporting a
build that produced nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

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
        self._stop.setEnabled(False)
        self._stop.clicked.connect(self.stop_requested.emit)

        self._open = QPushButton("Open folder")
        self._open.setObjectName("openButton")
        self._open.setEnabled(False)
        self._open.clicked.connect(self._on_open)

        self._gate = QLabel("")
        self._gate.setObjectName("gate")
        self._gate.setWordWrap(True)

        self._panel = ProgressPanel()
        self._artifact: Path | None = None

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(self._run, 0)
        row.addWidget(self._stop, 0)
        row.addWidget(self._open, 0)
        row.addStretch(1)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)
        column.addLayout(row)
        column.addWidget(self._gate)
        column.addWidget(self._panel)
        column.addStretch(1)

    # --- gate ----------------------------------------------------------------

    def set_gate(self, enabled: bool, reason: str = "") -> None:
        """Enable the Run button, and say why when it is off."""
        running = self._panel.is_busy()
        self._run.setEnabled(bool(enabled) and not running)
        self._stop.setEnabled(running)
        self._gate.setText("" if enabled else reason)

    def is_running(self) -> bool:
        return self._panel.is_busy()

    # --- state ---------------------------------------------------------------

    def begin(self) -> None:
        self._artifact = None
        self._open.setEnabled(False)
        self._run.setEnabled(False)
        self._stop.setEnabled(True)
        self._panel.set_running()

    def on_progress(self, stage: str, message: str, fraction: float) -> None:
        self._panel.set_fraction(fraction)
        self._panel.set_running(f"{stage}: {message}")

    def on_built(self, outcome) -> None:
        self._artifact = Path(outcome.artifact)
        self._stop.setEnabled(False)
        self._open.setEnabled(True)
        size = outcome.size
        self._panel.set_done(f"{self._artifact.name}   {size:,} bytes   {outcome.seconds:.2f} s")

    def on_failed(self, stage: str, message: str, artifact: object) -> None:
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
        self._stop.setEnabled(False)
        if problems:
            self._panel.set_failed("; ".join(str(problem) for problem in problems[:4]))
        else:
            self._panel.set_failed("the form was rejected")

    def reset(self) -> None:
        self._artifact = None
        self._open.setEnabled(False)
        self._stop.setEnabled(False)
        self._panel.reset()

    # --- internals -----------------------------------------------------------

    def _on_open(self) -> None:
        if self._artifact is not None:
            self.reveal_requested.emit(str(self._artifact.parent))
