"""The window: frameless shell, custom titlebar, rail, page stack.

Frameless, so the titlebar is ours: a drag region, minimise, and close. The three
buttons and the drag are the whole reason the window is frameless — a native titlebar
cannot carry the theme and does not match the rail.

The shell owns three things and nothing else: which page is showing, when the form is
re-validated, and the lifetime of the build thread. Pages hold values, ``core.validate``
holds the rules, and the worker holds the run.

Every widget that can change a value emits into ``_revalidate``, which rebuilds the
config, runs the six rules, paints the problems onto the page that owns each dotted
path, and gates the Run button. That is one path for every edit, so a new field cannot
arrive without the gate seeing it.

The page scaffold that the gate table listed as ``pages/base.py`` lives here instead:
``_page`` builds the heading, the description and the body for each page, because the
shell is already the only place that knows the stack order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import validate as validate_module

from . import main as app_main
from .pages.forge import ForgePage
from .pages.relay import RelayPage
from .pages.run import RunPage
from .pages.sources import SourcesPage
from .pages.tuning import TuningPage
from .rail import Rail
from .worker import BuildWorker, config_from

__all__ = ["MainWindow"]

_TITLEBAR_HEIGHT: Final[int] = 40
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent


class MainWindow(QWidget):
    """Frameless main window. One instance per process."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("shell")
        self.setWindowTitle(app_main.APP_NAME)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window
        )
        self.setMinimumSize(980, 640)
        self.resize(1120, 720)

        self._drag_origin: QPoint | None = None
        self._worker: BuildWorker | None = None
        self._theme = app_main.saved_theme()

        # --- pages -----------------------------------------------------------
        self._relay = RelayPage()
        self._sources = SourcesPage()
        self._tuning = TuningPage()
        self._forge = ForgePage()
        self._run = RunPage()

        self._pages: dict[str, QWidget] = {
            "relay": self._relay,
            "sources": self._sources,
            "tuning": self._tuning,
            "forge": self._forge,
            "run": self._run,
        }

        self._stack = QStackedWidget()
        self._stack.setObjectName("pageStack")
        for route in ("relay", "sources", "tuning", "forge", "run"):
            self._stack.addWidget(self._wrap(self._pages[route]))

        self._rail = Rail()
        self._rail.navigated.connect(self._on_navigate)

        # --- assembly --------------------------------------------------------
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._rail, 0)
        body.addWidget(self._stack, 1)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self._build_titlebar())
        column.addLayout(body, 1)

        # --- wiring ----------------------------------------------------------
        self._run.run_requested.connect(self._start)
        self._run.stop_requested.connect(self._stop)
        self._run.reveal_requested.connect(self._reveal)

        for widget in (self._relay._endpoint, self._tuning._mutex, self._tuning._seal_key,
                       self._tuning._output, self._forge._name, self._forge._stub):
            widget.changed.connect(self._revalidate)
        self._relay._kind.currentIndexChanged.connect(self._revalidate)
        self._forge._mode.currentIndexChanged.connect(self._revalidate)
        self._tuning._ballast.valueChanged.connect(self._revalidate)
        self._tuning._self_remove.toggled.connect(self._revalidate)
        for box in self._sources._boxes.values():
            box.toggled.connect(self._revalidate)

        self._revalidate()

    # --- titlebar ------------------------------------------------------------

    def _build_titlebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("titlebar")
        bar.setFixedHeight(_TITLEBAR_HEIGHT)

        heading = QLabel(app_main.APP_NAME)
        heading.setObjectName("titlebarTitle")

        self._theme_button = QPushButton("")
        self._theme_button.setObjectName("titlebarButton")
        self._theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._theme_button.clicked.connect(self._toggle_theme)

        minimise = QPushButton("\u2013")
        minimise.setObjectName("titlebarButton")
        minimise.setCursor(Qt.CursorShape.PointingHandCursor)
        minimise.clicked.connect(self.showMinimized)

        close = QPushButton("\u00d7")
        close.setObjectName("titlebarClose")
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(self.close)

        row = QHBoxLayout(bar)
        row.setContentsMargins(16, 0, 8, 0)
        row.setSpacing(6)
        row.addWidget(heading, 0)
        row.addStretch(1)
        row.addWidget(self._theme_button, 0)
        row.addWidget(minimise, 0)
        row.addWidget(close, 0)

        self._refresh_theme_button()
        return bar

    def _refresh_theme_button(self) -> None:
        other = app_main.next_theme(self._theme)
        self._theme_button.setText(f"  {other.capitalize()} theme  ")

    def _toggle_theme(self) -> None:
        target = app_main.next_theme(self._theme)
        try:
            app_main.apply_theme(_app(), target)
        except app_main.ThemeError:
            return
        self._theme = target
        app_main.remember_theme(target)
        self._refresh_theme_button()

    # --- frame drag ----------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() <= _TITLEBAR_HEIGHT:
            self._drag_origin = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_origin is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_origin)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._drag_origin = None
        super().mouseReleaseEvent(event)

    # --- pages ---------------------------------------------------------------

    def _wrap(self, page: QWidget) -> QWidget:
        """The shared page scaffold: heading, description, body."""
        container = QWidget()
        container.setObjectName("page")

        title = QLabel(getattr(page, "title", ""))
        title.setObjectName("pageTitle")
        description = QLabel(getattr(page, "description", ""))
        description.setObjectName("pageDescription")
        description.setWordWrap(True)

        column = QVBoxLayout(container)
        column.setContentsMargins(36, 28, 36, 28)
        column.setSpacing(6)
        column.addWidget(title)
        column.addWidget(description)
        column.addSpacing(16)
        column.addWidget(page, 1)
        return container

    def _on_navigate(self, route: str) -> None:
        page = self._pages.get(route)
        if page is None:
            return
        self._stack.setCurrentWidget(page.parentWidget())
        self._revalidate()

    # --- form ----------------------------------------------------------------

    def _collect(self):
        relay = self._relay.values()
        tuning = self._tuning.values()
        sources = self._sources.values()
        return config_from(
            relay_kind=relay["relay_kind"],
            endpoint=relay["endpoint"],
            mutex=tuning["mutex"],
            seal_key=tuning["seal_key"],
            sources=sources,
            self_remove=bool(tuning["self_remove"]),
            ballast_mb=int(tuning["ballast_mb"]),
        )

    def _revalidate(self, *_args) -> None:
        cfg = self._collect()
        mode = self._forge.mode()
        problems = validate_module.validate(
            cfg, mode=mode, name=self._forge.name(), stub=self._forge.stub()
        )

        for page in (self._relay, self._tuning, self._forge):
            page.show_problems(problems)

        stopped = validate_module.blocking(problems)
        self._run.set_gate(
            not stopped and not self._run.is_running(),
            validate_module.describe(stopped) or "the form is incomplete",
        )

    # --- run -----------------------------------------------------------------

    def _start(self) -> None:
        if self._run.is_running():
            return

        cfg = self._collect()
        out_dir = self._tuning.values()["out_dir"]
        if not out_dir:
            self._run.on_failed("output", "no output directory set", None)
            return

        self._run.begin()
        worker = BuildWorker(
            cfg,
            root=_REPO_ROOT,
            out_dir=Path(str(out_dir)),
            mode=self._forge.mode(),
            name=self._forge.name(),
            stub=self._forge.stub(),
            parent=self,
        )
        worker.progress.connect(self._run.on_progress)
        worker.built.connect(self._on_built)
        worker.failed.connect(self._on_failed)
        worker.rejected.connect(self._on_rejected)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._run.set_stopped("stopping at the next stage boundary")

    def _on_built(self, outcome) -> None:
        self._run.on_built(outcome)
        self._revalidate()

    def _on_failed(self, stage: str, message: str, artifact: object) -> None:
        self._run.on_failed(stage, message, artifact)
        self._revalidate()

    def _on_rejected(self, problems) -> None:
        self._run.on_rejected(problems)
        self._revalidate()

    def _on_worker_finished(self) -> None:
        self._worker = None
        self._revalidate()

    def _reveal(self, directory: str) -> None:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(directory))

    # --- teardown ------------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(10_000)
            self._worker = None
        super().closeEvent(event)


def _app() -> object:
    """The live QApplication. Imported lazily so this module stays cheap to import."""
    from PySide6.QtWidgets import QApplication

    instance = QApplication.instance()
    if instance is None:
        raise RuntimeError("no QApplication")
    return instance
