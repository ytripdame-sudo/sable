"""Navigation rail: brand, routes, and the live gate state.

Fixed width. The rail owns the route list and emits the route name; the shell owns which
page is showing. That split means the rail can be built once and never rebuilt on
navigation — it only moves its own accent bar and repaints the status chip.

Icons are drawn as text glyphs rather than shipped as image files, because a PNG per
route is six more files that are not in the manifest and a font glyph is the same
information. The glyph set is limited to what Segoe UI Symbol has on Windows, which is
every glyph used here.

The status chip at the foot is the one piece of global state the rail carries: whether the
form can be built. It is written by the shell on every re-validation, so the answer is
visible from every page instead of only from the one holding the Run button.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .widgets.status import StatusPill

__all__ = ["RAIL_WIDTH", "ROUTES", "Rail"]

RAIL_WIDTH: Final[int] = 240

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

# The state names are the ones the stylesheet already knows; a blocked form is painted
# with the failure colour because that is what the chip is saying.
_READY_STATE: Final[str] = "done"
_BLOCKED_STATE: Final[str] = "stopped"


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

        brand = QWidget()
        brand.setObjectName("brand")
        mark = QLabel("S")
        mark.setObjectName("brandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(30, 30)

        name = QLabel("SABLE")
        name.setObjectName("brandName")
        edition = QLabel("v1.0")
        edition.setObjectName("brandEdition")

        words = QVBoxLayout()
        words.setContentsMargins(0, 0, 0, 0)
        words.setSpacing(0)
        words.addWidget(name)
        words.addWidget(edition)

        brand_row = QHBoxLayout(brand)
        brand_row.setContentsMargins(18, 0, 18, 0)
        brand_row.setSpacing(11)
        brand_row.addWidget(mark, 0)
        brand_row.addLayout(words, 1)

        section = QLabel("CONFIGURE")
        section.setObjectName("railSection")

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 16, 0, 14)
        column.setSpacing(0)
        column.addWidget(brand)
        column.addSpacing(22)
        column.addWidget(section)
        column.addSpacing(8)

        nav = QVBoxLayout()
        nav.setContentsMargins(12, 0, 12, 0)
        nav.setSpacing(2)
        for route, glyph, label in ROUTES:
            button = QPushButton(f"{glyph}    {label}")
            button.setObjectName("railButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setProperty(_ACTIVE_PROPERTY, False)
            button.clicked.connect(lambda _checked=False, name=route: self._select(name))
            self._group.addButton(button)
            self._buttons[route] = button
            nav.addWidget(button)
        column.addLayout(nav)
        column.addStretch(1)

        separator = QFrame()
        separator.setObjectName("railSeparator")
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)

        self._status = StatusPill("ready")
        self._status.set_state(_READY_STATE, "ready")
        self._status.setToolTip("the form can be built")

        foot = QWidget()
        foot.setObjectName("railFoot")
        foot_row = QHBoxLayout(foot)
        foot_row.setContentsMargins(18, 0, 18, 0)
        foot_row.setSpacing(8)
        foot_row.addWidget(self._status, 0)
        foot_row.addStretch(1)

        column.addWidget(separator)
        column.addSpacing(12)
        column.addWidget(foot)

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

    def set_status(self, ready: bool, text: str = "") -> None:
        """Paint the gate chip. ``text`` is the short reason when it is blocked."""
        caption = text or ("ready" if ready else "blocked")
        self._status.set_state(_READY_STATE if ready else _BLOCKED_STATE, caption)
        self._status.setToolTip(
            "the form can be built" if ready else (text or "the form is incomplete")
        )

    def _select(self, route: str) -> None:
        self.set_route(route)
        self.navigated.emit(route)
