"""Relay page: kind, endpoint, and the status webhook.

The kind and the endpoint are one decision, so they are one card rather than two pages.
Switching the kind rewrites the placeholder and the hint under the field, because
``https`` wants a URL and ``telegram`` wants ``token$chat`` and a field that says
"https://" while the validator wants a bot token is a form that argues with itself.

The status pair is deliberately a second card. A status webhook is usually the same URL
as the endpoint and sometimes is not, and the mention is a piece of text rather than a
delivery route, so neither changes shape when the kind changes. Two cards state that
separation without a sentence saying so.

The page never decides whether anything is valid. It holds text and paints whatever
``core.validate`` returns against its dotted path.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core.schema import RELAY_KINDS

from ..widgets.field import Card, LabelledEdit

__all__ = ["RelayPage"]

_DEFAULT_MENTION: Final[str] = "@here"

_HINTS: Final[dict[str, tuple[str, str]]] = {
    "https": (
        "https://discord.com/api/webhooks/...",
        "A URL that accepts a multipart POST. The artifact is uploaded whole, so the "
        "host's own file ceiling applies.",
    ),
    "telegram": (
        "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42",
        "Bot token, a $, then the chat id. The artifact is sent as a document.",
    ),
    "link": (
        "https://discord.com/api/webhooks/...",
        "The artifact is hosted first and only the link is posted, so the host's file "
        "ceiling does not apply. Small archives go to catbox and stay; large ones go "
        "to litterbox and expire in 72 hours.",
    ),
}


class RelayPage(QWidget):
    """Kind selector, endpoint, and the optional status pair."""

    title: Final[str] = "Relay"
    description: Final[str] = "Where the finished artifact is transmitted."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._kind = QComboBox()
        self._kind.setObjectName("relayKind")
        self._kind.setFixedWidth(220)
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
        column.addWidget(status)
        column.addStretch(1)

    # --- value ---------------------------------------------------------------

    def kind(self) -> str:
        return str(self._kind.currentData())

    def endpoint(self) -> str:
        return self._endpoint.text().strip()

    def ping(self) -> str:
        return self._ping.text().strip()

    def mention(self) -> str:
        return self._mention.text().strip()

    def values(self) -> dict[str, str]:
        return {
            "relay_kind": self.kind(),
            "endpoint": self.endpoint(),
            "ping": self.ping(),
            "mention": self.mention(),
        }

    def reset(self) -> None:
        self._kind.setCurrentIndex(0)
        self._endpoint.set_text("")
        self._endpoint.clear_problem()
        self._ping.set_text("")
        self._ping.clear_problem()
        self._mention.set_text(_DEFAULT_MENTION)
        self._mention.clear_problem()

    # --- state ---------------------------------------------------------------

    def show_problems(self, problems) -> None:
        """Paint each complaint on the field that owns it.

        The ping is checked under the same rule as the endpoint, so it is routed by
        path rather than by rule: two fields, one rule, and the message still lands
        under the text that caused it.
        """
        self._endpoint.clear_problem()
        self._ping.clear_problem()
        for problem in problems:
            if problem.path == "relay.ping":
                self._ping.set_problem(problem.message)
            elif problem.path.startswith("relay."):
                self._endpoint.set_problem(problem.message)

    def _on_kind(self, _index: int) -> None:
        placeholder, hint = _HINTS.get(self.kind(), _HINTS["https"])
        self._endpoint.set_placeholder(placeholder)
        self._hint.setText(hint)
        # A kind switch almost always invalidates the text that was already there, so
        # the old complaint is cleared rather than left pointing at a different shape.
        self._endpoint.clear_problem()
