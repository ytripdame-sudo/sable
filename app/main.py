"""Application entry: the QApplication, the theme, the window.

Qt is imported inside functions, never at module scope. ``import app.main`` therefore
succeeds with no binding installed, which is what lets the import test and the Linux
run work without a display or a wheel. The only cost is one import statement per
function, and those functions are called once per process.

The theme is a file read and a stylesheet set. Switching is the same call as setting
it the first time, so a switch re-applies without a restart and without a rebuilt
window; Qt re-polishes the existing widgets when the stylesheet string changes. The
choice is remembered in ``QSettings`` and re-read on the next launch.

Bindings are PySide6. The three names that differ from PyQt (``Signal``, ``Slot``,
``exec``) are used throughout, so a mixed import cannot half-work.

The arrow images are here for the same reason the themes are: a stylesheet can describe a
rounded rectangle but it cannot draw a triangle, and styling a combo box's drop-down takes
the style's own arrow away rather than inheriting it. The two chevrons are rasterised once
per theme into a temp file and referenced by ``url()``. A shipped PNG would be two files
outside the manifest that cannot follow the theme.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import Final

APP_NAME: Final[str] = "Sable"
ORG_NAME: Final[str] = "sable"

THEME_DIR: Final[Path] = Path(__file__).resolve().parent / "theme"
THEMES: Final[tuple[str, ...]] = ("dark", "light")
DEFAULT_THEME: Final[str] = "dark"

_THEME_KEY: Final[str] = "ui/theme"

# Chevron colour per theme, and the generated-file cache. The stylesheet cannot pick a
# colour at paint time, so the chevron is rasterised in the theme's colour instead.
_ARROW_COLOURS: Final[dict[str, str]] = {"dark": "#8d97a6", "light": "#667085"}
_arrow_cache: dict[tuple[str, str], str] = {}


class ThemeError(RuntimeError):
    """A theme name that is not one of ``THEMES``, or a stylesheet that cannot load."""


def theme_path(name: str) -> Path:
    """Path of the stylesheet for ``name``. Validates the name before it is a path."""
    if name not in THEMES:
        raise ThemeError(f"{name!r}: expected one of {', '.join(THEMES)}")
    return THEME_DIR / f"{name}.qss"


def read_theme(name: str) -> str:
    """The stylesheet text. Raises ThemeError rather than returning an empty string."""
    path = theme_path(name)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ThemeError(f"{path.name}: cannot read ({exc.strerror})") from exc
    if not text.strip():
        raise ThemeError(f"{path.name}: is empty")
    return text


def apply_theme(app: object, name: str) -> str:
    """Set ``name`` on ``app`` and return it. Safe to call on every switch."""
    app.setStyleSheet(_resolve_arrows(read_theme(name), name))  # type: ignore[attr-defined]
    return name


def _resolve_arrows(text: str, theme: str) -> str:
    """Replace the arrow placeholders with real file URLs for ``theme``.

    Qt's stylesheet language can draw a rounded rectangle but not a triangle, and a
    stylesheet that touches ``QComboBox::down-arrow`` or ``QSpinBox::up-arrow`` takes
    the arrow away from the style instead of inheriting it. The two chevrons are
    therefore drawn once per theme, written to a temp file, and referenced as an image.
    A shipped PNG would be two files outside the manifest that cannot follow the theme;
    this is the same pixels, generated at the same moment the theme is chosen.
    """
    colour = _ARROW_COLOURS.get(theme, _ARROW_COLOURS[DEFAULT_THEME])
    down = _arrow_png("down", colour)
    up = _arrow_png("up", colour)
    return text.replace("@arrow-down", down).replace("@arrow-up", up)


def _arrow_png(direction: str, colour: str) -> str:
    """Draw a 9x5 chevron once per direction and colour, and return its URL."""
    cached = _arrow_cache.get((direction, colour))
    if cached is not None:
        return cached

    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QColor, QPainter, QPen, QPixmap

    scale = 2
    width, height = 9, 5
    pixmap = QPixmap(width * scale, height * scale)
    pixmap.fill(Qt.GlobalColor.transparent)
    pixmap.setDevicePixelRatio(scale)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(QColor(colour))
    pen.setWidthF(1.5)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    high, low = (0.9, 4.1) if direction == "down" else (4.1, 0.9)
    painter.drawPolyline(
        [QPointF(0.6, high), QPointF(width / 2, low), QPointF(width - 0.6, high)]
    )
    painter.end()

    target = _arrow_dir() / f"{direction}-{colour.lstrip('#')}.png"
    if not target.is_file():
        pixmap.save(str(target), "PNG")
    url = target.as_posix()
    _arrow_cache[(direction, colour)] = url
    return url


def _arrow_dir() -> Path:
    """Where the generated chevrons live. Per-user, outside the repo, created once."""
    import tempfile

    folder = Path(tempfile.gettempdir()) / "sable-ui"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def next_theme(current: str) -> str:
    """The other theme. A name that is not in ``THEMES`` yields the default."""
    if current not in THEMES:
        return DEFAULT_THEME
    return THEMES[(THEMES.index(current) + 1) % len(THEMES)]


def saved_theme() -> str:
    """The remembered theme, or the default when unset or no longer present."""
    from PySide6.QtCore import QSettings

    stored = QSettings().value(_THEME_KEY, DEFAULT_THEME)
    name = str(stored)
    return name if name in THEMES else DEFAULT_THEME


def remember_theme(name: str) -> None:
    """Persist the choice. Unknown names are ignored rather than stored."""
    if name not in THEMES:
        return

    from PySide6.QtCore import QSettings

    settings = QSettings()
    settings.setValue(_THEME_KEY, name)
    # Explicit sync: the switch is a user action and the process can be closed by the
    # window manager straight after it.
    settings.sync()


def _enable_high_dpi() -> None:
    """Opt into fractional scaling. A no-op on a Qt that already does this."""
    from PySide6.QtCore import Qt

    policy = getattr(Qt, "HighDpiScaleFactorRoundingPolicy", None)
    if policy is None:
        return

    from PySide6.QtGui import QGuiApplication

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(policy.PassThrough)


def build_application(argv: list[str] | None = None) -> object:
    """Create the QApplication with the saved theme already applied."""
    _enable_high_dpi()

    from PySide6.QtWidgets import QApplication

    app = QApplication(list(sys.argv if argv is None else argv))
    # Before any QSettings is constructed, so the organisation key is the one stored.
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)

    name = saved_theme()
    try:
        apply_theme(app, name)
    except ThemeError:
        # A missing stylesheet is not a reason to fail to start: the default widgets
        # are ugly, not broken, and the fallback theme may still be on disk.
        if name != DEFAULT_THEME:
            with contextlib.suppress(ThemeError):
                apply_theme(app, DEFAULT_THEME)

    return app


def main(argv: list[str] | None = None) -> int:
    """Run the UI. Returns the process exit code."""
    app = build_application(argv)

    # Imported here so the module stays importable without Qt, and so a broken page
    # import fails after the application exists and can report it.
    from .shell import MainWindow

    window = MainWindow()
    window.show()
    return int(app.exec())  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
