# PyInstaller spec for Sable's launcher.
#
# One file, no console, no key inside it. The launcher carries only the loader and
# what the loader imports; the collectors stay in the sealed payload and are imported
# at run time out of the decrypted archive.
#
# That split has one consequence worth stating: a frozen interpreter cannot see the
# host's standard library, so every module the *payload* imports must be collected here
# or it will be absent at run time. That list is computed from `agent/` by
# `tools/launcher_imports.py` rather than typed: the hand-typed version drifted once —
# `uuid` arrived with the stealth pass and the artifact died with ModuleNotFoundError
# after the payload had already decrypted.
#
#   pyinstaller tools/sable-launcher.spec --distpath tools/dist --workpath tools/build
#
# Output: tools/dist/sable-launcher.exe

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

from launcher_imports import hidden_imports  # noqa: E402

a = Analysis(
    [str(ROOT / "tools" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports(ROOT / "agent"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6",
        "shiboken6",
        "tkinter",
        "unittest",
        "doctest",
        "pydoc",
        "pydoc_data",
        "setuptools",
        "pip",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="sable-launcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
