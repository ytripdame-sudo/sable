"""Frozen launcher entry point.

This is the file PyInstaller freezes. It carries no key, no address and no config:
it imports ``agent.loader`` and calls ``boot``, which reads the trailer behind
whichever artifact this executable was welded to. One freeze opens every build, and
re-freezing is only needed when the loader itself changes.

``tools/`` is build tooling, not shipping source, so it is outside ``MANIFEST.txt``.
``tools/probes/sable_launcher.py`` proves the result against a fake payload.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Source runs need the repository on sys.path. A frozen bundle already carries the
# loader inside it, and its __file__ points into an extraction directory that has no
# repository above it.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.loader import boot

if __name__ == "__main__":
    raise SystemExit(boot())
