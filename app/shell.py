"""The window: frameless shell, custom titlebar, rail, page stack.

Frameless, so the titlebar is ours: the drag region, the build action, the theme switch
and the window buttons. A native titlebar cannot carry the theme and cannot hold the
primary action, which is the whole reason this window draws its own.

The shell owns four things and nothing else: which page is showing, when the form is
re-validated, the lifetime of the build thread, and the gate. Pages hold values,
``core.validate`` holds the rules, and the worker holds the run.

Every widget that can change a value emits into ``_revalidate``, which rebuilds the
config, runs the six rules, paints the problems onto the page that owns each dotted
path, and gates both the titlebar action and the Run page. That is one path for every
edit, so a new field cannot arrive without the gate seeing it.

Each page is wrapped in a scroll area. A settings column taller than the window is
normal, and the alternative to a scrollbar is Qt compressing every field until the text
is clipped — which is what the previous build did, and what the first screenshot of this
one showed.

The page scaffold that the gate table listed as ``pages/base.py`` lives here instead:
``_wrap`` builds the heading, the description and the scroll frame for each page,
because the shell is already the only place that knows the stack order.
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
    QScrollArea,
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

_TITLEBAR_HEIGHT: Final[int] = 48
_CONTENT_WIDTH: Final[int] = 880
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
        self.setMinimumSize(1000, 640)
        self.resize(1240, 780)

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
        self._frames: dict[str, QWidget] = {}
        for route in ("relay", "sources", "tuning", "forge", "run"):
            frame = self._wrap(self._pages[route])
            self._frames[route] = frame
            self._stack.addWidget(frame)

        self._rail = Rail()
        self._rail.navigated.connect(self._on_navigate)

        # --- assembly --------------------------------------------------------
        titlebar = self._build_titlebar()

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._rail, 0)
        body.addWidget(self._stack, 1)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(titlebar)
        column.addLayout(body, 1)

        # --- wiring ----------------------------------------------------------
        self._run.run_requested.connect(self._start)
        self._run.stop_requested.connect(self._stop)
        self._run.reveal_requested.connect(self._reveal)
        self._build_button.clicked.connect(self._start)

        for widget in (self._relay._endpoint, self._relay._ping, self._relay._mention,
                       self._tuning._mutex, self._tuning._seal_key,
                       self._tuning._output, self._forge._name, self._forge._stub,
                       self._forge._icon, self._forge._fuse,
                       self._forge._company, self._forge._product,
                       self._forge._description, self._forge._copyright,
                       self._forge._original_name, self._forge._file_version,
                       self._forge._product_version, self._forge._decoy_seconds,
                       self._forge._decoy_title, self._forge._decoy_text):
            widget.changed.connect(self._revalidate)
        self._relay._kind.currentIndexChanged.connect(self._revalidate)
        # The fallback rows are built and destroyed at runtime, so the page re-emits one
        # signal for all of them rather than the shell chasing widgets that do not exist
        # yet.
        self._relay.changed.connect(self._revalidate)
        self._forge._mode.currentIndexChanged.connect(self._revalidate)
        self._tuning._ballast.valueChanged.connect(self._revalidate)
        self._tuning._persist_hours.valueChanged.connect(self._revalidate)
        self._tuning._self_remove.toggled.connect(self._revalidate)
        self._tuning._keep_local.toggled.connect(self._revalidate)
        self._tuning._persist.toggled.connect(self._revalidate)
        for box in self._sources._boxes.values():
            box.toggled.connect(self._revalidate)

        self._on_navigate("relay")

    # --- titlebar ------------------------------------------------------------

    def _build_titlebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("titlebar")
        bar.setFixedHeight(_TITLEBAR_HEIGHT)

        self._path = QLabel("")
        self._path.setObjectName("titlebarPath")

        self._build_button = QPushButton("Build")
        self._build_button.setObjectName("buildButton")
        self._build_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._build_button.setEnabled(False)

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
        row.setContentsMargins(22, 0, 10, 0)
        row.setSpacing(6)
        row.addWidget(self._path, 0)
        row.addStretch(1)
        row.addWidget(self._build_button, 0)
        row.addSpacing(10)
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
        """The shared page scaffold: heading, description, scrolling body."""
        content = QWidget()
        content.setObjectName("page")

        title = QLabel(getattr(page, "title", ""))
        title.setObjectName("pageTitle")
        description = QLabel(getattr(page, "description", ""))
        description.setObjectName("pageDescription")
        description.setWordWrap(True)

        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(6)
        column.addWidget(title)
        column.addWidget(description)
        column.addSpacing(20)
        column.addWidget(page, 1)

        column_holder = QWidget()
        column_holder.setObjectName("pageColumn")
        column_holder.setMaximumWidth(_CONTENT_WIDTH)
        held = QVBoxLayout(column_holder)
        held.setContentsMargins(0, 0, 0, 0)
        held.setSpacing(0)
        held.addWidget(content, 1)

        viewport = QWidget()
        viewport.setObjectName("pageBody")
        centred = QHBoxLayout(viewport)
        centred.setContentsMargins(40, 30, 40, 34)
        centred.setSpacing(0)
        # The spacers carry no stretch on purpose. Qt hands surplus width to the only
        # item that asks for it — the column, up to its 880px ceiling — and then splits
        # whatever is left between the two zero-stretch spacers. Giving the spacers a
        # stretch factor too would split the width three ways, which is how the first
        # cut of this scaffold ended up with a 316px column in a 1040px stack.
        centred.addStretch(0)
        centred.addWidget(column_holder, 1)
        centred.addStretch(0)

        scroll = QScrollArea()
        scroll.setObjectName("pageScroll")
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(viewport)
        return scroll

    def _on_navigate(self, route: str) -> None:
        frame = self._frames.get(route)
        if frame is None:
            return
        self._stack.setCurrentWidget(frame)
        self._path.setText(f"Sable  /  {getattr(self._pages[route], 'title', route)}")
        self._revalidate()

    # --- form ----------------------------------------------------------------

    def _collect(self):
        relay = self._relay.values()
        tuning = self._tuning.values()
        sources = self._sources.values()
        seconds, title, text = self._forge.decoy()
        return config_from(
            relay_kind=relay["relay_kind"],
            endpoint=relay["endpoint"],
            ping=relay["ping"],
            mention=relay["mention"],
            targets=relay["targets"],
            mutex=tuning["mutex"],
            seal_key=tuning["seal_key"],
            sources=sources,
            self_remove=bool(tuning["self_remove"]),
            ballast_mb=int(tuning["ballast_mb"]),
            keep_local=bool(tuning["keep_local"]),
            persist=bool(tuning["persist"]),
            persist_hours=int(tuning["persist_hours"]),
            version=self._forge.version(),
            decoy_seconds=seconds,
            decoy_title=title,
            decoy_text=text,
        )

    def _revalidate(self, *_args) -> None:
        cfg = self._collect()
        mode = self._forge.mode()
        problems = validate_module.validate(
            cfg,
            mode=mode,
            name=self._forge.name(),
            stub=self._forge.stub(),
            icon=self._forge.icon(),
            fuse=self._forge.fuse(),
            donor=self._forge.donor(),
            carrier=self._forge.carrier(),
        )

        # ``core.validate`` describes a config, and a config has no output folder. The
        # build cannot run without one, so the gate says so here rather than letting the
        # button light up and then fail on click.
        if not str(self._tuning.values()["out_dir"]).strip():
            problems.append(
                validate_module.Problem(
                    rule=validate_module.RULE_OUTPUT,
                    path="output.dir",
                    message="choose an output directory",
                )
            )

        for page in (self._relay, self._tuning, self._forge):
            page.show_problems(problems)

        stopped = validate_module.blocking(problems)
        ready = not stopped and not self._run.is_running()
        reason = validate_module.describe(stopped) or "the form is incomplete"

        self._run.set_gate(ready, reason)
        self._build_button.setEnabled(ready)
        self._build_button.setToolTip("" if ready else reason)
        self._rail.set_status(ready, "" if ready else _short(stopped))

    # --- run -----------------------------------------------------------------

    def _start(self) -> None:
        # The worker reference is the authority, not the pill: a stop request flips the
        # pill to "stopped" while the thread is still finishing a stage.
        if self._worker is not None or self._run.is_running():
            return

        cfg = self._collect()
        out_dir = self._tuning.values()["out_dir"]
        if not out_dir:
            self._run.on_failed("output", "no output directory set", None)
            return

        self._run.begin()
        self._build_button.setEnabled(False)
        worker = BuildWorker(
            cfg,
            root=_REPO_ROOT,
            out_dir=Path(str(out_dir)),
            mode=self._forge.mode(),
            name=self._forge.name(),
            stub=self._forge.stub(),
            icon=self._forge.icon(),
            fuse=self._forge.fuse(),
            version=self._forge.version(),
            donor=self._forge.donor(),
            carrier=self._forge.carrier(),
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
        self._on_navigate("run")
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
            if not self._worker.wait(10_000):
                # A seal or a forge of a large artifact cannot be interrupted, and a
                # QThread destroyed while it is still running takes the process down.
                # Leaving the window open is the lesser defect.
                self._run.set_stopped("finishing the current stage before closing")
                event.ignore()
                return
            self._worker = None
        super().closeEvent(event)


def _short(problems) -> str:
    """One short line for the rail chip. The full sentence stays on the Run page."""
    count = len(problems)
    if count == 0:
        return "blocked"
    return "1 issue" if count == 1 else f"{count} issues"


def _app() -> object:
    """The live QApplication. Imported lazily so this module stays cheap to import."""
    from PySide6.QtWidgets import QApplication

    instance = QApplication.instance()
    if instance is None:
        raise RuntimeError("no QApplication")
    return instance
