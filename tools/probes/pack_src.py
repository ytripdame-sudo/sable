"""Pack the source tree the guest extracts, and nothing that only exists to build it.

The guest needs ``agent/`` and ``core/`` on disk to run the probe harness. It does not
need the PyInstaller scratch, the frozen stub, or a bytecode cache — shipping those
turns a 300 KB transfer into a 15 MB one and invites the guest to import a stale .pyc.

    python pack_src.py _out/live/sable-src.zip
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "sable"
TARGET = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "_out" / "live" / "sable-src.zip")

SKIP_DIRS = frozenset(
    {".git", "__pycache__", ".pytest_cache", "build", "dist", "target", "node_modules", ".venv"}
)
SKIP_SUFFIX = frozenset({".pyc", ".pyo", ".pyd", ".dll"})


def wanted(path: Path) -> bool:
    if path.suffix.lower() in SKIP_SUFFIX:
        return False
    return True


def main() -> int:
    if not (ROOT / "agent").is_dir():
        raise SystemExit(f"not a source tree: {ROOT}")

    files: list[Path] = []
    for path in sorted(ROOT.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.is_file() and wanted(path):
            files.append(path)

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(TARGET, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT).as_posix())

    print(f"source   {len(files)} files  {TARGET.stat().st_size:,} bytes")
    roblox = [p for p in files if p.name == "roblox.py"]
    print(f"roblox   {roblox[0].relative_to(ROOT).as_posix() if roblox else 'MISSING'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
