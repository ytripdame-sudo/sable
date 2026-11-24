"""Manifest parity, import direction, and headless import.

Three things a green build must prove, and none of them can be checked by reading:

1. ``MANIFEST.txt`` and the tree agree in both directions. A listed path that does not
   exist fails, and a ``.py`` under the three packages that is not listed fails. The
   second direction is the one that matters: it is how a file arrives without a slot
   and nobody notices the count moved.
2. The import direction holds. Parsed with ``ast``, never grepped: ``core/forge.py``
   contains ``from agent import entry, loader`` inside ``_SCRIPT_TEMPLATE``, which is
   the generated script's own source text. A grep matches it and would tempt someone to
   break script output to silence a false positive.
3. ``import app`` and ``import app.main`` succeed with no Qt binding installed. That is
   the acceptance line, and it is a real constraint: Qt is imported per function there.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.txt"
PACKAGES = ("agent", "core", "app")

# Rendered by the style sheet, not by Python. Listed so a rename of one of these
# blocks is a decision rather than a silent no-op selector.
QSS_DIR = ROOT / "app" / "theme"


def manifest_paths() -> list[str]:
    return [line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_manifest_exists_and_is_locked_at_seventy() -> None:
    assert MANIFEST.is_file(), "MANIFEST.txt is the spec; it cannot be missing"
    assert len(manifest_paths()) == 70


def test_every_listed_path_exists() -> None:
    missing = [name for name in manifest_paths() if not (ROOT / name).is_file()]
    assert missing == [], f"listed but absent: {missing}"


def test_no_unlisted_python_file() -> None:
    listed = set(manifest_paths())
    extra: list[str] = []
    for package in PACKAGES:
        base = ROOT / package
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative not in listed:
                extra.append(relative)
    assert extra == [], f"present but not in MANIFEST.txt: {extra}"


def test_manifest_has_no_duplicates() -> None:
    paths = manifest_paths()
    assert len(paths) == len(set(paths))


# --- import direction -------------------------------------------------------


def _imported_roots(path: Path) -> list[tuple[int, str]]:
    """Top-level module names imported by ``path``, with line numbers."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative: stays inside its own package by construction
            if node.module:
                roots.append((node.lineno, node.module.split(".")[0]))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                roots.append((node.lineno, alias.name.split(".")[0]))
    return roots


def _modules_in(package: str) -> list[Path]:
    base = ROOT / package
    if not base.is_dir():
        return []
    return [p for p in base.rglob("*.py") if "__pycache__" not in p.parts]


@pytest.mark.parametrize("package", PACKAGES)
def test_import_direction(package: str) -> None:
    forbidden = {
        "core": {"agent", "app"},
        "agent": {"core", "app"},
        "app": {"agent"},  # app may read core; it may not reach into the payload
    }[package]

    violations = [
        f"{path.relative_to(ROOT).as_posix()}:{line} imports {root}"
        for path in _modules_in(package)
        for line, root in _imported_roots(path)
        if root in forbidden
    ]
    assert violations == [], violations


def test_generated_script_template_is_not_an_import() -> None:
    """The one place a forbidden name appears, and why it is not a violation."""
    source = (ROOT / "core" / "forge.py").read_text(encoding="utf-8")
    assert "from agent import entry, loader" in source
    assert [root for _, root in _imported_roots(ROOT / "core" / "forge.py") if root in {"agent", "app"}] == []


# --- headless ---------------------------------------------------------------


def test_import_app_without_qt() -> None:
    """``app`` and ``app.main`` must import with no binding installed."""
    for name in ("app", "app.main"):
        __import__(name)
    assert "app" in sys.modules
    assert "app.main" in sys.modules


def test_theme_constants_are_available_without_qt() -> None:
    from app import main as entry

    assert entry.THEMES == ("dark", "light")
    assert entry.DEFAULT_THEME in entry.THEMES
    assert entry.next_theme("dark") == "light"
    assert entry.next_theme("light") == "dark"
    assert entry.next_theme("bogus") == entry.DEFAULT_THEME


def test_theme_files_are_present_and_paired() -> None:
    for name in ("dark", "light"):
        path = QSS_DIR / f"{name}.qss"
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        assert text.strip(), f"{path.name} is empty"
        assert not text.startswith("\ufeff"), "a BOM would break the first selector"


def test_every_package_imports() -> None:
    import importlib
    import pkgutil

    failures: list[str] = []
    for package in PACKAGES:
        importlib.import_module(package)
        for module in pkgutil.walk_packages([str(ROOT / package)], package + "."):
            try:
                importlib.import_module(module.name)
            except ImportError as exc:
                # A missing Qt binding is expected on a headless box; anything else is
                # a real defect. app.main is the only module that must survive both.
                if "PySide6" not in str(exc):
                    failures.append(f"{module.name}: {exc}")
            except Exception as exc:
                failures.append(f"{module.name}: {type(exc).__name__}: {exc}")
    assert failures == [], failures
