"""Labelled input row with an inline validation state and an optional picker.

The field is one widget rather than a label and an edit stacked in every page, so a
page can say "this row is wrong" in one call instead of reaching into two objects.
``set_problem`` paints the edit and writes the message underneath; ``clear_problem``
puts it back. Nothing here validates — ``core.validate`` owns the rules, and this only
renders what it returns.

``browse`` turns the row into a path picker. The gate-table slot for a separate path
widget was folded in here because the difference is one button and a dialog, and a
second file for that is a file whose whole content is a callback to
``QFileDialog.getExistingDirectory``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

_STATE_PROPERTY: Final[str] = "state"
__all__ = ["Field", "LabelledEdit"]


class LabelledEdit(QWidget):
    """One labelled line edit with optional validation state and optional picker.

    ``changed`` carries the current text, so a page can bind it straight to a form
    model without a lambda wrapper per field.
    """

    changed = Signal(str)

    def __init__(
        self,
        label: str,
        *,
        placeholder: str = "",
        text: str = "",
        browse: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._label = QLabel(label)
        self._label.setObjectName("fieldLabel")

        self._edit = QLineEdit(text)
        self._edit.setPlaceholderText(placeholder)
        self._edit.setClearButtonEnabled(True)
        self._edit.textChanged.connect(self._on_text)

        self._message = QLabel("")
        self._message.setObjectName("fieldMessage")
        self._message.setVisible(False)
        self._message.setWordWrap(True)

        self._label.setBuddy(self._edit)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(self._edit, 1)

        self._browse: QPushButton | None = None
        if browse:
            self._browse = QPushButton("Browse")
            self._browse.setObjectName("browse")
            self._browse.clicked.connect(self._pick)
            row.addWidget(self._browse, 0)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(4)
        column.addWidget(self._label)
        column.addLayout(row)
        column.addWidget(self._message)

    # --- value ---------------------------------------------------------------

    def text(self) -> str:
        return self._edit.text()

    def set_text(self, value: str) -> None:
        """Set the text without emitting ``changed`` for the programmatic write."""
        blocked = self._edit.blockSignals(True)
        try:
            self._edit.setText(value)
        finally:
            self._edit.blockSignals(blocked)

    def path(self) -> Path | None:
        """The text as a path, or None when it is blank or cannot be one."""
        raw = self._edit.text().strip()
        if not raw:
            return None
        try:
            return Path(raw)
        except (OSError, ValueError):
            return None

    def set_read_only(self, read_only: bool) -> None:
        self._edit.setReadOnly(read_only)
        if self._browse is not None:
            self._browse.setEnabled(not read_only)

    # --- state ---------------------------------------------------------------

    def set_problem(self, message: str) -> None:
        """Paint the row as failing, with the message underneath."""
        self._message.setText(message)
        self._message.setVisible(bool(message))
        self._edit.setProperty(_STATE_PROPERTY, "error" if message else "")
        self._repolish()

    def clear_problem(self) -> None:
        self.set_problem("")

    def has_problem(self) -> bool:
        # isVisible() is False whenever the parent window is hidden, which makes it
        # useless as state; the message text is the state.
        return bool(self._message.text())

    # --- internals -----------------------------------------------------------

    def _on_text(self, value: str) -> None:
        # Typing is the user answering the complaint, so the message clears as soon as
        # the text changes. Re-validation happens on the next Run, not on every key.
        if self.has_problem():
            self.clear_problem()
        self.changed.emit(value)

    def _pick(self) -> None:
        start = self._edit.text().strip() or str(Path.home())
        chosen = QFileDialog.getExistingDirectory(self, self._label.text(), start)
        if chosen:
            self.set_text(chosen)
            self.changed.emit(chosen)

    def _repolish(self) -> None:
        # A dynamic property only changes appearance after a style re-polish; without
        # this the border colour never updates.
        style = self._edit.style()
        style.unpolish(self._edit)
        style.polish(self._edit)


class Field(LabelledEdit):
    """Alias kept so a page can import either name and get the same widget."""

    def __init__(self, label: str, **kwargs) -> None:
        super().__init__(label, **kwargs)
