"""Navigation rail: icon, label, and a 2px accent bar on the active route.

Fixed at 220px. The rail owns the route list and emits the route name; the shell owns
which page is showing. That split means the rail can be built once and never rebuilt
on navigation — it only moves its own accent bar.

Icons are drawn as text glyphs rather than shipped as image files, because a PNG per
route is six more files that are not in the manifest and a font glyph is the same
information. The glyph set is limited to what Segoe UI Symbol has on Windows, which
is every glyph used here.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

__all__ = ["RAIL_WIDTH", "ROUTES", "Rail"]

RAIL_WIDTH: Final[int] = 220

# (route, glyph, label). Order is the order the rail shows and the order the pages
# stack uses, so the two cannot drift.
ROUTES: Final[tuple[tuple[str, str, str], ...]] = (
    ("relay", "\u25c8", "Relay"),
    ("sources", "\u25a6", "Sources"),
    ("tuning", "\u2699", "Tuning"),
    ("forge", "\u25b2", "Forge"),
    ("run", "\u25b6", "Run"),
)

_ACTIVE_PROPERTY: Final[str] = "active"


class Rail(QWidget):
    """The left rail. Emits ``navigated`` with the route name."""

    navigated = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("rail")
        self.setFixedWidth(RAIL_WIDTH)

        self._buttons: dict[str, QPushButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        title = QLabel("SABLE")
        title.setObjectName("railTitle")

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(title)

        separator = QFrame()
        separator.setObjectName("railSeparator")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        column.addWidget(separator)

        for route, glyph, label in ROUTES:
            button = QPushButton(f"{glyph}   {label}")
            button.setObjectName("railButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setProperty(_ACTIVE_PROPERTY, False)
            button.clicked.connect(lambda _checked=False, name=route: self._select(name))
            self._group.addButton(button)
            self._buttons[route] = button
            column.addWidget(button)

        column.addStretch(1)

        self.set_route(ROUTES[0][0])

    def set_route(self, route: str) -> None:
        """Mark ``route`` active without emitting. Used by the shell on startup."""
        button = self._buttons.get(route)
        if button is None:
            raise KeyError(f"{route!r}: expected one of {', '.join(self._buttons)}")
        for name, candidate in self._buttons.items():
            active = name == route
            candidate.setChecked(active)
            candidate.setProperty(_ACTIVE_PROPERTY, active)
            style = candidate.style()
            style.unpolish(candidate)
            style.polish(candidate)

    def _select(self, route: str) -> None:
        self.set_route(route)
        self.navigated.emit(route)
