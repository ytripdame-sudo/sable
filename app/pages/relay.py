"""Relay page: kind and endpoint.

The kind and the endpoint are one decision, so they are one row block rather than two
pages. Switching the kind rewrites the placeholder and the hint under the field,
because ``https`` wants a URL and ``telegram`` wants ``token$chat`` and a field that
says "https://" while the validator wants a bot token is a form that argues with
itself.

The page never decides whether the pair is valid. It holds text and paints whatever
``core.validate`` returns against ``relay.endpoint``.
"""

from __future__ import annotations

from typing import Final

from PySide6.QtWidgets import QComboBox, QLabel, QVBoxLayout, QWidget

from core.schema import RELAY_KINDS

from ..widgets.field import LabelledEdit

__all__ = ["RelayPage"]

_HINTS: Final[dict[str, tuple[str, str]]] = {
    "https": (
        "https://relay.example/ingest",
        "A URL that accepts a multipart POST. The artifact is uploaded whole.",
    ),
    "telegram": (
        "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42",
        "Bot token, a $, then the chat id. The artifact is sent as a document.",
    ),
}


class RelayPage(QWidget):
    """Kind selector plus endpoint field."""

    title: Final[str] = "Relay"
    description: Final[str] = "Where the finished artifact is transmitted."

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._kind = QComboBox()
        self._kind.setObjectName("relayKind")
        for kind in RELAY_KINDS:
            self._kind.addItem(kind, kind)
        self._kind.currentIndexChanged.connect(self._on_kind)

        self._endpoint = LabelledEdit("Endpoint", placeholder=_HINTS["https"][0])
        self._hint = QLabel(_HINTS["https"][1])
        self._hint.setObjectName("hint")
        self._hint.setWordWrap(True)

        kind_label = QLabel("Kind")
        kind_label.setObjectName("fieldLabel")

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)
        column.addWidget(kind_label)
        column.addWidget(self._kind)
        column.addWidget(self._endpoint)
        column.addWidget(self._hint)
        column.addStretch(1)

    # --- value ---------------------------------------------------------------

    def kind(self) -> str:
        return str(self._kind.currentData())

    def endpoint(self) -> str:
        return self._endpoint.text().strip()

    def values(self) -> dict[str, str]:
        return {"relay_kind": self.kind(), "endpoint": self.endpoint()}

    def reset(self) -> None:
        self._kind.setCurrentIndex(0)
        self._endpoint.set_text("")
        self._endpoint.clear_problem()

    # --- state ---------------------------------------------------------------

    def show_problems(self, problems) -> None:
        """Paint anything targeting the endpoint or the kind."""
        for problem in problems:
            if problem.path.startswith("relay."):
                self._endpoint.set_problem(problem.message)
                return

    def _on_kind(self, _index: int) -> None:
        placeholder, hint = _HINTS.get(self.kind(), _HINTS["https"])
        self._endpoint._edit.setPlaceholderText(placeholder)
        self._hint.setText(hint)
        # A kind switch almost always invalidates the text that was already there, so
        # the old complaint is cleared rather than left pointing at a different shape.
        self._endpoint.clear_problem()
