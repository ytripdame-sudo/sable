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
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

APP_NAME: Final[str] = "Sable"
ORG_NAME: Final[str] = "sable"

THEME_DIR: Final[Path] = Path(__file__).resolve().parent / "theme"
THEMES: Final[tuple[str, ...]] = ("dark", "light")
DEFAULT_THEME: Final[str] = "dark"

_THEME_KEY: Final[str] = "ui/theme"


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
    app.setStyleSheet(read_theme(name))  # type: ignore[attr-defined]
    return name


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
            try:
                apply_theme(app, DEFAULT_THEME)
            except ThemeError:
                pass

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
