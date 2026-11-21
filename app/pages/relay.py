"""Relay page: kind, endpoint, fallbacks, and the status webhook.

The kind and the endpoint are one decision, so they are one card rather than two pages.
Switching the kind rewrites the placeholder and the hint under the field, because
``https`` wants a URL and ``telegram`` wants ``token$chat`` and a field that says
"https://" while the validator wants a bot token is a form that argues with itself.

The fallbacks card is separate and below, because a mirror is not the same decision as
the primary: it is what the run does when the primary refuses. Rows are added by hand and
tried in the order they appear, which is why the order is visible rather than alphabetical
or hidden in a set.

The status pair is deliberately a third card. A status webhook is usually the same URL as
the endpoint and sometimes is not, and the mention is a piece of text rather than a
delivery route, so neither changes shape when the kind changes. Three cards state that
separation without a sentence saying so.

The page never decides whether anything is valid. It holds text and paints whatever
``core.validate`` returns against its dotted path.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.schema import MAX_RELAY_TARGETS, RELAY_KINDS

from ..widgets.field import Card, LabelledEdit

__all__ = ["RelayPage"]

_DEFAULT_MENTION: Final[str] = "@here"

_PLACEHOLDERS: Final[dict[str, str]] = {
    "https": "https://discord.com/api/webhooks/...",
    "telegram": "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42",
    "link": "https://discord.com/api/webhooks/...",
    "phantom": "ytripdame-sudo/sable-archive$ghp_...",
}

_HINTS: Final[dict[str, tuple[str, str]]] = {
    "https": (
        _PLACEHOLDERS["https"],
        "A URL that accepts a multipart POST. The artifact is uploaded whole, so the "
        "host's own file ceiling applies.",
    ),
    "telegram": (
        _PLACEHOLDERS["telegram"],
        "Bot token, a $, then the chat id. The artifact is sent as a document.",
    ),
    "link": (
        _PLACEHOLDERS["link"],
        "The artifact is hosted first and only the link is posted, so the host's file "
        "ceiling does not apply. Small archives go to catbox and stay; large ones go "
        "to litterbox and expire in 72 hours.",
    ),
    "phantom": (
        _PLACEHOLDERS["phantom"],
        "Repository, a $, then a token with repo scope. The artifact is hosted on an "
        "anonymous host and a release page is published that points at it — the "
        "repository itself never stores the file. Worth a fallback where the file "
        "hosts are blocked and github answers.",
    ),
}

_KIND_WIDTH: Final[int] = 150


class _MirrorRow(QWidget):
    """One fallback: a transport, an address, and a button that takes it away.

    A row rather than a form field because a mirror is a pair. Two separate lists — one
    of kinds, one of endpoints — cannot express that the third kind belongs to the third
    endpoint, and a reader should not have to count to add a route.
    """

    def __init__(self, on_remove, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("mirrorRow")

        self._kind = QComboBox()
        self._kind.setObjectName("mirrorKind")
        self._kind.setFixedWidth(_KIND_WIDTH)
        for kind in RELAY_KINDS:
            self._kind.addItem(kind, kind)
        self._kind.currentIndexChanged.connect(self._on_kind)

        self._endpoint = LabelledEdit("Fallback address", placeholder=_PLACEHOLDERS["https"])
        self._endpoint.setObjectName("mirrorEndpoint")

        remove = QPushButton("Remove")
        remove.setObjectName("removeRow")
        remove.setCursor(Qt.CursorShape.PointingHandCursor)
        remove.clicked.connect(lambda: on_remove(self))
        self._remove = remove

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        row.addWidget(self._kind, 0, Qt.AlignmentFlag.AlignTop)
        row.addWidget(self._endpoint, 1)
        row.addWidget(remove, 0, Qt.AlignmentFlag.AlignTop)

    # --- value ---------------------------------------------------------------

    def kind(self) -> str:
        return str(self._kind.currentData())

    def endpoint(self) -> str:
        return self._endpoint.text().strip()

    def pair(self) -> tuple[str, str]:
        return self.kind(), self.endpoint()

    def set_pair(self, kind: str, endpoint: str) -> None:
        """Set both halves at once, as a row created with values is."""
        index = self._kind.findData(kind)
        if index >= 0:
            self._kind.setCurrentIndex(index)
        if endpoint:
            self._endpoint.set_text(endpoint)

    def set_enabled_remove(self, enabled: bool) -> None:
        self._remove.setVisible(enabled)

    def clear_problem(self) -> None:
        self._endpoint.clear_problem()

    def set_problem(self, message: str) -> None:
        self._endpoint.set_problem(message)

    # --- internals -----------------------------------------------------------

    def _on_kind(self, _index: int) -> None:
        self._endpoint.set_placeholder(_PLACEHOLDERS.get(self.kind(), _PLACEHOLDERS["https"]))
        self._endpoint.clear_problem()


class RelayPage(QWidget):
    """Kind selector, endpoint, the ordered fallbacks, and the optional status pair."""

    # Rows come and go while the page is alive, so the shell cannot bind to them once
    # at construction the way it binds to the fixed fields. Everything a fallback row
    # can change is funnelled through here instead, and the shell binds this one signal.
    changed = Signal()

    title: Final[str] = "Relay"
    description: Final[str] = "Where the finished artifact is transmitted."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._kind = QComboBox()
        self._kind.setObjectName("relayKind")
        self._kind.setFixedWidth(150)
        for kind in RELAY_KINDS:
            self._kind.addItem(kind, kind)
        self._kind.currentIndexChanged.connect(self._on_kind)

        kind_label = QLabel("Kind")
        kind_label.setObjectName("fieldLabel")

        kind_row = QHBoxLayout()
        kind_row.setContentsMargins(0, 0, 0, 0)
        kind_row.setSpacing(12)
        kind_row.addWidget(self._kind, 0)
        kind_row.addStretch(1)

        self._endpoint = LabelledEdit("Endpoint", placeholder=_HINTS["https"][0])
        self._hint = QLabel(_HINTS["https"][1])
        self._hint.setObjectName("hint")
        self._hint.setWordWrap(True)

        delivery = Card(
            "Delivery",
            "One endpoint, one transport. The kind decides what the endpoint has to be.",
        )
        delivery.body.addWidget(kind_label)
        delivery.add_row(kind_row)
        delivery.body.addWidget(self._endpoint)
        delivery.body.addWidget(self._hint)

        # --- fallbacks -------------------------------------------------------
        self._rows: list[_MirrorRow] = []
        self._row_layout = QVBoxLayout()
        self._row_layout.setContentsMargins(0, 0, 0, 0)
        self._row_layout.setSpacing(14)

        self._add = QPushButton("Add a fallback")
        self._add.setObjectName("addRow")
        self._add.setCursor(Qt.CursorShape.PointingHandCursor)
        self._add.clicked.connect(self.add_row)

        fallback_hint = QLabel(
            "Tried in order, but only when the delivery above fails: the first route that "
            "accepts the archive ends the run, and the rest are not sent to. Empty rows "
            "are ignored."
        )
        fallback_hint.setObjectName("hint")
        fallback_hint.setWordWrap(True)

        fallbacks = Card(
            "Fallbacks",
            "Other places the same archive can go when the first one refuses it.",
        )
        fallbacks.body.addLayout(self._row_layout)
        fallbacks.add(self._add)
        fallbacks.body.addWidget(fallback_hint)

        # --- status ----------------------------------------------------------
        self._ping = LabelledEdit(
            "Status webhook (optional)",
            placeholder=_HINTS["https"][0],
            text="",
        )
        ping_hint = QLabel(
            "Short stage messages go here: collecting, uploading, delivered, failed. "
            "Leave it empty for silent runs. The endpoint above is the delivery; this "
            "is the report."
        )
        ping_hint.setObjectName("hint")
        ping_hint.setWordWrap(True)

        self._mention = LabelledEdit(
            "Mention", placeholder=_DEFAULT_MENTION, text=_DEFAULT_MENTION
        )
        mention_hint = QLabel(
            "@here, @everyone, or a user id written as <@123456789012345678>. Several "
            "can go on one line. Placed in front of the messages that confirm a "
            "delivery or report a failure."
        )
        mention_hint.setObjectName("hint")
        mention_hint.setWordWrap(True)

        status = Card(
            "Status report",
            "Both fields are optional and neither is used for delivery.",
        )
        status.add(self._ping)
        status.body.addWidget(ping_hint)
        status.add(self._mention)
        status.body.addWidget(mention_hint)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(18)
        column.addWidget(delivery)
        column.addWidget(fallbacks)
        column.addWidget(status)
        column.addStretch(1)

        self._sync_add()

    # --- value ---------------------------------------------------------------

    def kind(self) -> str:
        return str(self._kind.currentData())

    def endpoint(self) -> str:
        return self._endpoint.text().strip()

    def ping(self) -> str:
        return self._ping.text().strip()

    def mention(self) -> str:
        return self._mention.text().strip()

    def targets(self) -> tuple[tuple[str, str], ...]:
        """The fallbacks that have an address. A blank row is not a target."""
        return tuple(row.pair() for row in self._rows if row.endpoint())

    def values(self) -> dict[str, object]:
        return {
            "relay_kind": self.kind(),
            "endpoint": self.endpoint(),
            "ping": self.ping(),
            "mention": self.mention(),
            "targets": self.targets(),
        }

    def reset(self) -> None:
        self._kind.setCurrentIndex(0)
        self._endpoint.set_text("")
        self._endpoint.clear_problem()
        self._ping.set_text("")
        self._ping.clear_problem()
        self._mention.set_text(_DEFAULT_MENTION)
        self._mention.clear_problem()
        for row in list(self._rows):
            self._remove_row(row)
        self._sync_add()

    # --- rows ----------------------------------------------------------------

    def add_row(self, kind: str = "", endpoint: str = "") -> _MirrorRow:
        """Append a fallback row. Returns it so a caller can drive it in a test."""
        if len(self._rows) >= MAX_RELAY_TARGETS:
            return self._rows[-1]
        row = _MirrorRow(self._remove_row)
        if kind or endpoint:
            row.set_pair(kind, endpoint)
        row._endpoint.changed.connect(lambda _text: self.changed.emit())
        row._kind.currentIndexChanged.connect(lambda _index: self.changed.emit())
        self._rows.append(row)
        self._row_layout.addWidget(row)
        self._sync_add()
        return row

    def row_count(self) -> int:
        return len(self._rows)

    # --- state ---------------------------------------------------------------

    def show_problems(self, problems) -> None:
        """Paint each complaint on the field that owns it.

        The ping is checked under the same rule as the endpoint, so it is routed by
        path rather than by rule: two fields, one rule, and the message still lands
        under the text that caused it. The fallbacks are routed by index.
        """
        self._endpoint.clear_problem()
        self._ping.clear_problem()
        for row in self._rows:
            row.clear_problem()

        for problem in problems:
            path = problem.path
            if path == "relay.ping":
                self._ping.set_problem(problem.message)
            elif path.startswith("relay.targets."):
                index = _index_of(path)
                if index is None or index >= len(self._rows):
                    continue
                self._rows[index].set_problem(problem.message)
            elif path.startswith("relay."):
                self._endpoint.set_problem(problem.message)

    # --- internals -----------------------------------------------------------

    def _remove_row(self, row: _MirrorRow) -> None:
        if row not in self._rows:
            return
        self._rows.remove(row)
        self._row_layout.removeWidget(row)
        row.setParent(None)
        row.deleteLater()
        self._sync_add()
        # Removing a row changes what the build would do, so the gate has to look again
        # even though no field was typed into.
        self.changed.emit()

    def _sync_add(self) -> None:
        # A full list is a disabled button rather than a row that silently does nothing.
        self._add.setEnabled(len(self._rows) < MAX_RELAY_TARGETS)
        self._add.setToolTip(
            "" if self._add.isEnabled() else f"{MAX_RELAY_TARGETS} fallbacks is the limit"
        )

    def _on_kind(self, _index: int) -> None:
        placeholder, hint = _HINTS.get(self.kind(), _HINTS["https"])
        self._endpoint.set_placeholder(placeholder)
        self._hint.setText(hint)
        # A kind switch almost always invalidates the text that was already there, so
        # the old complaint is cleared rather than left pointing at a different shape.
        self._endpoint.clear_problem()


def _index_of(path: str) -> int | None:
    """The row index out of ``relay.targets.<n>.<field>``."""
    parts = path.split(".")
    if len(parts) < 3:
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None
