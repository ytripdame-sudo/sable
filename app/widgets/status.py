"""Status pill and progress composite.

One widget instead of a label, a bar and a busy indicator wired separately in every
page. The pill carries the run state and the bar carries the fraction, because they
describe the same thing at two resolutions and separating them is how a UI ends up
saying "running" under a bar that has been at 100% for a minute.

The pill is a plain label with a dynamic property, so the palette lives in the
stylesheet and a theme switch repaints it without touching Python.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

__all__ = ["ProgressPanel", "StatusPill"]

_STATE_PROPERTY: Final[str] = "state"

IDLE: Final[str] = "idle"
RUNNING: Final[str] = "running"
DONE: Final[str] = "done"
FAILED: Final[str] = "failed"
STOPPED: Final[str] = "stopped"


class StatusPill(QLabel):
    """A small state chip. Colour comes from the ``state`` property in the stylesheet."""

    def __init__(self, text: str = "idle", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("statusPill")
        self.setProperty(_STATE_PROPERTY, IDLE)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_state(self, state: str, text: str | None = None) -> None:
        """Set the state and optionally the caption, then re-polish for the colour."""
        self.setProperty(_STATE_PROPERTY, state)
        if text is not None:
            self.setText(text)
        style = self.style()
        style.unpolish(self)
        style.polish(self)


class ProgressPanel(QWidget):
    """A status pill above a progress bar and a message line."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._pill = StatusPill(IDLE)
        self._bar = QProgressBar()
        self._bar.setObjectName("progress")
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(8)

        self._message = QLabel("")
        self._message.setObjectName("progressMessage")
        self._message.setWordWrap(True)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.addWidget(self._pill, 0)
        top.addStretch(1)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(6)
        column.addLayout(top)
        column.addWidget(self._bar)
        column.addWidget(self._message)

    # --- driven by the worker's signals --------------------------------------

    def reset(self) -> None:
        self._pill.set_state(IDLE, "idle")
        self._bar.setValue(0)
        self._message.setText("")

    def set_running(self, message: str = "building") -> None:
        self._pill.set_state(RUNNING, "running")
        self._message.setText(message)

    def set_fraction(self, fraction: float) -> None:
        """Clamp to 0..100. A callback can arrive out of order after a cancel."""
        clamped = min(max(fraction, 0.0), 1.0)
        self._bar.setValue(round(clamped * 100))

    def set_done(self, message: str) -> None:
        self._pill.set_state(DONE, "done")
        self._bar.setValue(100)
        self._message.setText(message)

    def set_failed(self, message: str) -> None:
        self._pill.set_state(FAILED, "failed")
        self._message.setText(message)

    def set_stopped(self, message: str = "stopped") -> None:
        self._pill.set_state(STOPPED, "stopped")
        self._message.setText(message)

    def is_busy(self) -> bool:
        return self._pill.property(_STATE_PROPERTY) == RUNNING
