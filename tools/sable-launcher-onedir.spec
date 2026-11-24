# PyInstaller spec for Sable's launcher — one-directory variant.
#
# Same Analysis as `sable-launcher.spec`, different packaging. One-file mode unpacks the
# whole interpreter into `%TEMP%\_MEIxxxxxx` on every launch and deletes it on exit; that
# tree is the reason the artifact leaves scratch directories behind on a machine that
# never asked for them. In one-directory mode the interpreter sits next to the exe in
# `_internal\` and nothing is extracted at run time.
#
# The payload container is unchanged: `core/forge.py` still appends
# `[ ballast ][ sealed ][ trailer 868 ][ footer 12 ]` to the end of this exe, because the
# exe is still a file. `expected_offset` is computed from that same file's size, and
# `agent/loader.py` opens `sys.executable`, so a launcher nested one directory deeper
# resolves its own tail the same way.
#
#   pyinstaller tools/sable-launcher-onedir.spec \
#       --distpath tools/dist-onedir --workpath tools/build-onedir
#
# Output: tools/dist-onedir/sable-launcher/sable-launcher.exe (+ _internal\)

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
    [],
    exclude_binaries=True,
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

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="sable-launcher",
)
