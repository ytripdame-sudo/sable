"""Sources page: six toggles bound to ``SourceConfig``.

One checkbox per field in ``SourceConfig``, taken from that dataclass rather than
written out here, so a field added to the schema appears without this file changing.
The labels come from ``app.worker.SOURCE_LABELS`` because the worker is what turns the
page's values into a config and the two must agree on the names.

The page reports and never enforces. "Every source is switched off" is
``core.validate``'s rule, and it says so against the dotted path ``sources``.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtWidgets import QCheckBox, QVBoxLayout, QWidget

from core.schema import SOURCE_FIELDS

from ..worker import SOURCE_LABELS

__all__ = ["SourcesPage"]

_LABELS: Final[dict[str, str]] = dict(SOURCE_LABELS)

_HINTS: Final[dict[str, str]] = {
    "system": "UUID, CPU, GPU, memory, uptime, OS build, machine and user name.",
    "browsers": "Profiles, cookies, logins, cards, history and downloads.",
    "sessions": "Discord tokens from the LevelDB store, checked against the API.",
    "wallets": "Wallet directories, names and sizes. No key material is read.",
    "autofill": "Address and card rows from the Chromium autofill tables.",
    "documents": "Recent-document lists from the user registry hives.",
}


class SourcesPage(QWidget):
    """One checkbox per ``SourceConfig`` field."""

    title: Final[str] = "Sources"
    description: Final[str] = "What the agent collects when it runs."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._boxes: dict[str, QCheckBox] = {}

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(10)

        for name in SOURCE_FIELDS:
            box = QCheckBox(_LABELS.get(name, name))
            box.setObjectName("sourceToggle")
            box.setChecked(True)
            if name in _HINTS:
                box.setToolTip(_HINTS[name])
            column.addWidget(box)
            self._boxes[name] = box

        column.addStretch(1)

    # --- value ---------------------------------------------------------------

    def values(self) -> dict[str, bool]:
        return {name: box.isChecked() for name, box in self._boxes.items()}

    def enabled_count(self) -> int:
        return sum(1 for box in self._boxes.values() if box.isChecked())

    def reset(self) -> None:
        for box in self._boxes.values():
            box.setChecked(True)

    # --- state ---------------------------------------------------------------

    def show_problems(self, problems) -> None:
        """There is no per-source field to paint; the shell shows the message."""
        return
