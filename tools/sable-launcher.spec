# PyInstaller spec for Sable's launcher.
#
# One file, no console, no key inside it. The launcher carries only the loader and
# what the loader imports; the collectors stay in the sealed payload and are imported
# at run time out of the decrypted archive.
#
# That split has one consequence worth stating: a frozen interpreter cannot see the
# host's standard library, so every module the *payload* imports must be named here or
# it will be absent at run time. The list below is exactly the set agent/ uses that
# analysis cannot reach from tools/launcher.py. Adding an import to agent/ means
# adding it here; `_harness/sable_launcher.py` imports the same set through a fake
# payload so a missed one fails a test instead of a run.
#
#   pyinstaller tools/sable-launcher.spec --distpath tools/dist --workpath tools/build
#
# Output: tools/dist/sable-launcher.exe

from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent

PAYLOAD_STDLIB = [
    "base64",
    "hashlib",
    "itertools",
    "re",
    "secrets",
    "sqlite3",
    "ssl",
    "urllib.error",
    "urllib.request",
]

CRYPTO = [
    "Crypto.Cipher.AES",
    "Crypto.Hash.SHA256",
    "Crypto.Protocol.KDF",
]

a = Analysis(
    [str(ROOT / "tools" / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=PAYLOAD_STDLIB + CRYPTO,
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
