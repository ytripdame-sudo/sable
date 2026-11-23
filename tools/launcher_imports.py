"""What the frozen launcher must carry for the payload to run.

The launcher freezes an interpreter that cannot see the host's standard library, so every
module ``agent/`` imports has to be collected at build time. That list was hand-typed in
``sable-launcher.spec`` and it drifted: the stealth pass added ``import uuid`` to
``agent/entry.py`` and the next artifact died four seconds into a guest run with
``ModuleNotFoundError: No module named 'uuid'`` — after the payload had decrypted, so the
only evidence was one line on stderr.

This computes the set from the source instead. ``ast`` is used rather than importing the
package because importing it opens WinDLL handles, allocates, and would run on the build
machine with the agent's own machinery.

Not in the manifest: ``tools/`` is build machinery, like the Rust crate.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

# Packages the payload imports, but only through a submodule, so the top-level name is
# not enough: PyInstaller resolves ``Crypto.Cipher.AES`` and not ``Crypto``.
SUBMODULES: Final[tuple[str, ...]] = (
    "Crypto.Cipher.AES",
    "Crypto.Hash.SHA256",
    "Crypto.Protocol.KDF",
)

# First-party packages that live inside the payload rather than in the interpreter.
_FIRST_PARTY: Final[frozenset[str]] = frozenset({"agent", "core", "__future__"})


def payload_imports(agent_root: Path) -> list[str]:
    """Top-level external modules imported anywhere under ``agent_root``."""
    found: set[str] = set()

    for path in sorted(agent_root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            # A file that will not parse cannot be imported either, so it cannot add a
            # requirement. The test suite is where that failure belongs.
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                found.add(node.module.split(".")[0])

    return sorted(name for name in found if name not in _FIRST_PARTY)


def hidden_imports(agent_root: Path) -> list[str]:
    """Everything PyInstaller has to be told about: the imports, then the submodules."""
    return sorted(set(payload_imports(agent_root)) | set(SUBMODULES))


__all__ = ["SUBMODULES", "hidden_imports", "payload_imports"]
