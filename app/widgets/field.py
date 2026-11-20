"""Form surfaces: a labelled input, and the card that groups inputs.

``LabelledEdit`` is one widget rather than a label and an edit stacked in every page, so
a page can say "this row is wrong" in one call instead of reaching into two objects.
``set_problem`` paints the edit and writes the message underneath; ``clear_problem`` puts
it back. Nothing here validates — ``core.validate`` owns the rules, and this only renders
what it returns.

``Card`` is the unit the pages are built from: a bordered panel with a title, an optional
description, and a body layout the page fills. Grouping exists because a settings page
built as one long column of controls has no edges for the eye to land on, and because a
border is what tells a reader that these four controls belong to each other. It lives
here rather than in its own file because the manifest is locked at fifty paths and this
is the widget module.

``browse`` turns a labelled row into a path picker. The gate-table slot for a separate
path widget was folded in here because the difference is one button and a dialog, and a
second file for that is a file whose whole content is a callback to
``QFileDialog.getExistingDirectory``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

_STATE_PROPERTY: Final[str] = "state"
__all__ = ["Card", "Field", "LabelledEdit"]


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
        self._edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
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
            self._browse.setCursor(Qt.CursorShape.PointingHandCursor)
            self._browse.clicked.connect(self._pick)
            row.addWidget(self._browse, 0)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(6)
        column.addWidget(self._label)
        column.addLayout(row)
        column.addWidget(self._message)

        # The row is as tall as its parts. Without this a crowded page is free to
        # squeeze a 40px edit into 18px, which clips the caret and the text rather than
        # producing a scrollbar.
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    # --- value ---------------------------------------------------------------

    def text(self) -> str:
        return self._edit.text()

    def set_text(self, value: str) -> None:
        """Set the text. Emits ``changed`` exactly as typing does.

        An earlier version blocked the signal so a programmatic write looked quiet.
        That made the Run button's gate disagree with a field the program had just
        filled, which is worse than a redundant re-validation: the gate must track the
        text however it changed, so there is one path and no exceptions.
        """
        self._edit.setText(value)

    def path(self) -> Path | None:
        """The text as a path, or None when it is blank or cannot be one."""
        raw = self._edit.text().strip()
        if not raw:
            return None
        try:
            return Path(raw)
        except (OSError, ValueError):
            return None

    def set_placeholder(self, text: str) -> None:
        """Change the greyed example. Used when the relay kind changes shape."""
        self._edit.setPlaceholderText(text)

    def set_read_only(self, read_only: bool) -> None:
        self._edit.setReadOnly(read_only)
        if self._browse is not None:
            self._browse.setEnabled(not read_only)

    def focus(self) -> None:
        """Put the caret in the edit. Used when a page is opened on a problem."""
        self._edit.setFocus(Qt.FocusReason.OtherFocusReason)

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


class Card(QFrame):
    """A titled panel. The page fills ``body`` with rows.

    ``hint`` is the sentence that explains the group; a field's own explanation belongs
    next to the field, but a group needs one line saying why it exists at all.
    """

    def __init__(
        self,
        title: str = "",
        hint: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setFrameShape(QFrame.Shape.NoFrame)
        # Preferred, not Maximum: Maximum tells Qt the widget may shrink below its size
        # hint, which is exactly how a card with six rows ends up 40px tall with its
        # contents spilling out of the border.
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        column = QVBoxLayout(self)
        column.setContentsMargins(22, 18, 22, 20)
        column.setSpacing(6)

        if title:
            heading = QLabel(title)
            heading.setObjectName("cardTitle")
            column.addWidget(heading)
        if hint:
            note = QLabel(hint)
            note.setObjectName("cardHint")
            note.setWordWrap(True)
            column.addWidget(note)

        if title or hint:
            column.addSpacing(8)

        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(16)
        column.addLayout(self.body)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_row(self, layout: QLayout) -> None:
        """Add a row of widgets that a page built itself, e.g. a pair of buttons."""
        self.body.addLayout(layout)
