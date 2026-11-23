"""Pack a minimal CPython for the clean VM.

The guest has no Python, and the translator proof has to happen *inside* the guest:
Chromium's key is wrapped with that machine's own DPAPI, so a fixture built anywhere
else cannot be unwrapped there. This ships enough to run ``sable_fixture.py`` and
nothing else: the interpreter, the standard library zip, the extension modules, and
pycryptodome. No PySide6, no pytest, no test suite.

    python guest_seed.py _out/live/guest-py.zip
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = Path(sys.executable).parent
DEST = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "_out" / "live" / "guest-py.zip")

# This interpreter is laid out the embedded way: the standard library is a zip in the
# root, the extension modules are loose .pyd files beside the executable, and ``Lib``
# holds nothing but site-packages.
ROOT_GLOBS = ("*.exe", "*.dll", "*.pyd", "python312.zip", "LICENSE.txt")

# pycryptodome is the only third-party package the fixture needs: DPAPI unwrap is
# ctypes, and AES-GCM is Crypto.
KEEP_SITE = ("Crypto", "pycryptodome")


def keep_site(name: str) -> bool:
    return any(name == prefix or name.startswith(prefix + "-") for prefix in KEEP_SITE)


def main() -> int:
    if not (PY / "python.exe").is_file():
        raise SystemExit(f"no python at {PY}")

    count = 0
    total = 0
    DEST.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(DEST, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for pattern in ROOT_GLOBS:
            for path in sorted(PY.glob(pattern)):
                if not path.is_file():
                    continue
                archive.write(path, f"py/{path.name}")
                count += 1
                total += path.stat().st_size

        site = PY / "Lib" / "site-packages"
        for entry in sorted(site.iterdir()):
            if not keep_site(entry.name):
                continue
            files = [entry] if entry.is_file() else [
                path for path in entry.rglob("*") if path.is_file()
            ]
            for path in files:
                if "__pycache__" in path.parts or path.suffix in (".pyc", ".pdb"):
                    continue
                rel = path.relative_to(PY)
                archive.write(path, f"py/{rel.as_posix()}")
                count += 1
                total += path.stat().st_size

        fixture = HERE / "sable_fixture.py"
        archive.write(fixture, "sable_fixture.py")
        count += 1
        total += fixture.stat().st_size

    print(f"{count} files, {total:,} B raw -> {DEST.stat().st_size:,} B zipped")
    print(DEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
