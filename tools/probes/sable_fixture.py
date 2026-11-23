"""Synthetic Chrome profile, sealed with the real DPAPI and real AES-GCM.

Nothing here reads the operator's data. The key is made up, protected with the
machine's own DPAPI so the unwrap path is the real one, and every artifact is
written into a temp directory that is deleted on exit.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

def _sable_root() -> Path:
    """The directory holding ``agent/``, found by walking up from this file.

    The harness lives beside the tree in some layouts and inside it in others, so the
    only assumption worth making is that ``sable/agent`` exists somewhere above.
    """
    for base in Path(__file__).resolve().parents:
        if (base / "sable" / "agent").is_dir():
            return base / "sable"
    raise SystemExit("cannot find sable/agent above this file")


sys.path.insert(0, str(_sable_root()))

from Crypto.Cipher import AES

from agent.sources.browsers import chromium


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


KEY = bytes(range(32))
NONCE = bytes(range(12))


def seal(plain: bytes, prefix: bytes = b"v10") -> bytes:
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return prefix + NONCE + ciphertext + tag


def table(connection: sqlite3.Connection, name: str, columns: str, rows: list) -> None:
    connection.execute(f"CREATE TABLE {name} ({columns})")
    if rows:
        marks = ", ".join("?" * len(rows[0]))
        connection.executemany(f"INSERT INTO {name} VALUES ({marks})", rows)


def build(root: Path) -> Path:
    user_data = root / "User Data"
    profile = user_data / "Default"
    (profile / "Network").mkdir(parents=True)

    state = {"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + protect(KEY)).decode()}}
    (user_data / "Local State").write_text(json.dumps(state), encoding="utf-8")

    login = sqlite3.connect(str(profile / "Login Data"))
    table(
        login,
        "logins",
        "origin_url TEXT, signon_realm TEXT, username_value TEXT, password_value BLOB,"
        " date_created INTEGER, date_last_used INTEGER, times_used INTEGER",
        [
            ("https://example.invalid/login", "example.invalid", "killywilly",
             seal(b"correct-horse"), 13300000000000000, 13340000000000000, 7),
            ("https://second.invalid/", "second.invalid", "someone",
             seal(b"battery-staple"), 13300000000000000, 13340000000000000, 2),
        ],
    )
    login.commit()
    login.close()

    cookies = sqlite3.connect(str(profile / "Network" / "Cookies"))
    host = ".example.invalid"
    bound = hashlib.sha256(host.encode()).digest() + b"session-token-value"
    legacy = b"no-prefix-cookie"
    table(
        cookies,
        "cookies",
        "host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT,"
        " expires_utc INTEGER, last_access_utc INTEGER, is_secure INTEGER,"
        " is_httponly INTEGER, samesite INTEGER",
        [
            (host, "sid", "", seal(bound), "/", 13350000000000000, 13340000000000000, 1, 1, 2),
            (host, "legacy", "", seal(legacy), "/", 13350000000000000, 13340000000000000, 0, 0, 0),
            (host, "plain", "visible", b"", "/", 0, 0, 0, 0, 0),
        ],
    )
    cookies.commit()
    cookies.close()

    web = sqlite3.connect(str(profile / "Web Data"))
    table(web, "autofill", "name TEXT, value TEXT, count INTEGER, date_last_used INTEGER",
          [("email", "killywilly@example.invalid", 9, 13340000000000000)])
    table(
        web,
        "credit_cards",
        "guid TEXT, name_on_card TEXT, expiration_month INTEGER, expiration_year INTEGER,"
        " card_number_encrypted BLOB, nickname TEXT",
        [("card-guid", "KILLYWILLY", 4, 2031, seal(b"4111111111111111"), "personal")],
    )
    table(
        web,
        "autofill_profiles",
        "guid TEXT, company_name TEXT, street_address TEXT, city TEXT, state TEXT,"
        " zipcode TEXT, country_code TEXT, use_count INTEGER",
        [("addr-guid", "Bench Ltd", "1 Shop Lane", "Sheffield", "SY", "S1 1AA", "GB", 3)],
    )
    table(web, "autofill_profile_names", "guid TEXT, first_name TEXT, middle_name TEXT, last_name TEXT",
          [("addr-guid", "Ollie", "", "Bench")])
    table(web, "autofill_profile_emails", "guid TEXT, email TEXT",
          [("addr-guid", "ollie@example.invalid")])
    table(web, "autofill_profile_phones", "guid TEXT, number TEXT", [("addr-guid", "+44 7000 000000")])
    table(web, "local_ibans", "guid TEXT, nickname TEXT, value TEXT",
          [("iban-guid", "bench", "GB00TEST00000000000000")])
    web.commit()
    web.close()

    history = sqlite3.connect(str(profile / "History"))
    table(history, "urls", "url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,"
                           " last_visit_time INTEGER",
          [("https://example.invalid/", "Example", 12, 3, 13340000000000000)])
    table(history, "downloads", "target_path TEXT, tab_url TEXT, total_bytes INTEGER,"
                                " start_time INTEGER, state INTEGER",
          [("C:\\Users\\Bench\\Downloads\\report.pdf", "https://example.invalid/report.pdf",
            204800, 13340000000000000, 1)])
    history.commit()
    history.close()

    bookmarks = {
        "roots": {
            "bookmark_bar": {
                "name": "Bookmarks bar",
                "children": [
                    {"name": "Example", "url": "https://example.invalid/", "type": "url"},
                    {"name": "Folder", "children": [
                        {"name": "Nested", "url": "https://nested.invalid/", "type": "url"}
                    ]},
                ],
            }
        }
    }
    (profile / "Bookmarks").write_text(json.dumps(bookmarks), encoding="utf-8")

    return profile


# --- the Roblox session cookie -------------------------------------------------
# Two distinct values so a run proves which half answered. The prefix is the real one:
# the collector anchors on it, so a fixture without it would not exercise the detector.

ROBLOX_HOST = ".roblox.com"
ROBLOX_PREFIX = (
    b"_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-"
    b"and-to-steal-your-ROBUX-and-items.|"
)
STORE_TOKEN = (ROBLOX_PREFIX + b"STORE" + b"0123456789abcdef" * 6).decode()
MEMORY_TOKEN = (ROBLOX_PREFIX + b"MEMRY" + b"fedcba9876543210" * 8).decode()


def roblox_cookie(profile: Path, token: str = STORE_TOKEN) -> int:
    """Insert a sealed ``.ROBLOSECURITY`` row into an existing fixture store.

    Sealed with the same AES-GCM key and the same ``SHA256(host_key)`` binding Chrome
    uses, so the row opens only if the real decryption path runs.
    """
    connection = sqlite3.connect(str(profile / "Network" / "Cookies"))
    binding = hashlib.sha256(ROBLOX_HOST.encode()).digest()
    connection.execute(
        "INSERT INTO cookies (host_key, name, value, encrypted_value, path, expires_utc,"
        " last_access_utc, is_secure, is_httponly, samesite) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (ROBLOX_HOST, ".ROBLOSECURITY", "", seal(binding + token.encode()), "/",
         13400000000000000, 13390000000000001, 1, 1, 0),
    )
    connection.commit()
    connection.close()
    return 1


# --- the Discord session token -------------------------------------------------
# Discord keeps its token in ``Local Storage\leveldb`` — not in a SQLite database, the
# way its cookies are. The record is ``dQw4w9WgXcQ:`` followed by the base64 of a
# Chromium-sealed blob with no host binding, so the fixture seals with the same key and
# no binding and the collector has to run the real unwrap to get it back.
DISCORD_TOKEN = "mfa.D1SC0RD" + "0" * 77


def discord_token(profile: Path, token: str = DISCORD_TOKEN) -> int:
    """Plant one sealed token in a profile's Local Storage. Idempotent."""
    leveldb = profile / "Local Storage" / "leveldb"
    leveldb.mkdir(parents=True, exist_ok=True)
    record = leveldb / "000003.log"
    existing = record.read_bytes() if record.is_file() else b""

    plain = token.encode()
    if plain in existing:
        return 0

    blob = base64.b64encode(seal(plain))
    line = b"\x00_https://discord.com\x00\x01dQw4w9WgXcQ:" + blob + b"\x00"
    record.write_bytes(existing + line)
    return 1


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-fixture-") as scratch:
        root = Path(scratch)
        profile = build(root / "root")
        out = root / "out"

        written = chromium.run_profile(profile, out)
        print(f"run_profile -> {written} items")

        for path in sorted(out.rglob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            print(f"\n-- {path.relative_to(out)}")
            print(json.dumps(document, indent=2)[:1400])

        passwords = json.loads((out / "passwords.json").read_text(encoding="utf-8"))
        cookies = json.loads((out / "cookies.json").read_text(encoding="utf-8"))

        checks = [
            ("password decrypts", passwords[0]["password"] == "correct-horse"),
            ("both rows", len(passwords) == 2),
            ("cookie prefix stripped", cookies[0]["value"] == "session-token-value"),
            ("legacy cookie kept whole", cookies[1]["value"] == "no-prefix-cookie"),
            ("plain cookie kept", cookies[2]["value"] == "visible"),
        ]
        print("\n== checks")
        for label, ok in checks:
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
        return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
