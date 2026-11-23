"""Gecko end-to-end: two real key4.db fixtures, legacy and Firefox 144.

Legacy: PBKDF2-HMAC-SHA1 -> 3DES-CBC, 24-byte master key.
144:    PBES2 -> PBKDF2-HMAC-SHA256 -> AES-256-CBC, 32-byte master key, and the
        NSS quirk where the 14-byte IV is stored as an OCTET STRING and the
        16-byte encoding (04 0e + 14 bytes) is what the cipher receives.

Both are built with the same primitives the module uses, so a pass means the DER
walking, the OID routing, the oracle and the field decryption all agree.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, r"C:\Users\Kuzenee\Desktop\55555\sable")

from Crypto.Cipher import AES, DES3

from agent.sources.browsers import gecko

PASSWORD = b""
GLOBAL_SALT = bytes(range(16))
ITERATIONS = 1000

OID_PBES2 = der_bytes = bytes.fromhex("2a864886f70d01050d")
OID_PBKDF2 = bytes.fromhex("2a864886f70d01050c")
OID_AES256 = bytes.fromhex("60864801650304012a")
OID_HMAC_SHA256 = bytes.fromhex("2a864886f70d0209")
OID_LEGACY = bytes.fromhex("2a864886f70d01050a")

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def der(tag: int, payload: bytes) -> bytes:
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + payload


def octets(value: bytes) -> bytes:
    return der(0x04, value)


def sequence(*parts: bytes) -> bytes:
    return der(0x30, b"".join(parts))


def integer(value: int) -> bytes:
    return der(0x02, value.to_bytes(4, "big"))


def oid(value: bytes) -> bytes:
    return der(0x06, value)


NULL = der(0x05, b"")


def pad(data: bytes, block: int) -> bytes:
    amount = block - (len(data) % block)
    return data + bytes([amount]) * amount


def store(profile: Path, item1: bytes, item2: bytes, a11: bytes, logins: dict) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(profile / "key4.db"))
    connection.execute("CREATE TABLE metadata (id TEXT PRIMARY KEY, item1 BLOB, item2 BLOB)")
    connection.execute("INSERT INTO metadata VALUES ('password', ?, ?)", (item1, item2))
    connection.execute("CREATE TABLE nssPrivate (id INTEGER PRIMARY KEY, a11 BLOB)")
    connection.execute("INSERT INTO nssPrivate VALUES (1, ?)", (a11,))
    connection.commit()
    connection.close()
    (profile / "logins.json").write_text(json.dumps(logins), encoding="utf-8")


def login_document(username_blob: bytes, password_blob: bytes) -> dict:
    return {
        "logins": [
            {
                "hostname": "https://example.invalid",
                "formSubmitURL": "https://example.invalid/login",
                "httpRealm": None,
                "encryptedUsername": base64.b64encode(username_blob).decode(),
                "encryptedPassword": base64.b64encode(password_blob).decode(),
                "timeCreated": 1650000000000,
                "timeLastUsed": 1690000000000,
                "timePasswordChanged": 1680000000000,
            }
        ]
    }


# --- legacy -------------------------------------------------------------------


def build_legacy(profile: Path) -> None:
    entry_salt = bytes(range(16, 32))
    iv = bytes(range(8))

    def derive(salt: bytes) -> bytes:
        digest = hashlib.sha1(GLOBAL_SALT + PASSWORD).digest()
        return hashlib.pbkdf2_hmac("sha1", digest, salt, ITERATIONS, 24)

    # pycryptodome rejects a degenerate 3DES key (K1 == K2 or K2 == K3); a fixture
    # searching for a clean salt is cheaper than reasoning about the odds.
    for tweak in range(4096):
        salt = entry_salt + bytes([tweak & 0xFF, (tweak >> 8) & 0xFF])
        pbe_key = derive(salt)
        try:
            DES3.new(pbe_key, DES3.MODE_CBC, iv)
        except ValueError:
            continue
        break
    else:
        raise RuntimeError("no clean salt found")

    master = bytes(range(24))

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        return DES3.new(key, DES3.MODE_CBC, iv).encrypt(pad(plaintext, 8))

    item1 = sequence(octets(GLOBAL_SALT))
    item2 = sequence(
        sequence(oid(OID_LEGACY), octets(salt), integer(ITERATIONS)),
        octets(iv + encrypt(pbe_key, b"password-check\x02")),
    )
    a11 = sequence(octets(iv), octets(encrypt(pbe_key, master)))

    username = sequence(octets(iv), octets(encrypt(master, b"killywilly")))
    password = sequence(octets(iv), octets(encrypt(master, b"correct-horse")))
    store(profile, item1, item2, a11, login_document(username, password))


# --- Firefox 144 --------------------------------------------------------------


def build_modern(profile: Path) -> None:
    salt = bytes(range(32, 64))
    iv_value = bytes(range(14))
    iv = b"\x04\x0e" + iv_value
    assert len(iv) == 16

    pbe_key = hashlib.pbkdf2_hmac("sha256", PASSWORD, salt, ITERATIONS, 32)
    master = bytes(range(100, 132))

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))

    pbkdf2 = sequence(
        oid(OID_PBKDF2),
        sequence(octets(salt), integer(ITERATIONS), integer(32), sequence(oid(OID_HMAC_SHA256), NULL)),
    )
    scheme = sequence(oid(OID_AES256), octets(iv_value))
    item2 = sequence(
        sequence(oid(OID_PBES2), sequence(pbkdf2, scheme)),
        octets(encrypt(pbe_key, b"password-check\x02")),
    )
    item1 = sequence(octets(GLOBAL_SALT))
    a11 = sequence(octets(iv_value), octets(encrypt(pbe_key, master)))

    username = sequence(octets(iv_value), octets(encrypt(master, b"killywilly")))
    password = sequence(octets(iv_value), octets(encrypt(master, b"correct-horse")))
    store(profile, item1, item2, a11, login_document(username, password))


# --- run ----------------------------------------------------------------------


def exercise(label: str, profile: Path, out: Path, expected_candidates: int) -> None:
    handle = sqlite3.connect(str(profile / "key4.db"))
    try:
        item1, item2 = gecko._metadata(handle)
    finally:
        handle.close()

    check(f"{label}: metadata reads", bool(item1 and item2), f"{len(item1)}/{len(item2)} bytes")
    check(f"{label}: global salt", gecko._global_salt(item1) == GLOBAL_SALT, "")

    candidates = gecko._pbe_candidates(item2)
    check(f"{label}: candidates", len(candidates) == expected_candidates, str(len(candidates)))
    if candidates:
        check(f"{label}: scheme", candidates[0].scheme, candidates[0].scheme)

    unlocked = gecko._unlock(GLOBAL_SALT, item2, PASSWORD)
    check(f"{label}: oracle accepts", unlocked is not None, "" if unlocked is None else unlocked[1])
    check(f"{label}: oracle rejects", gecko._unlock(GLOBAL_SALT, item2, b"wrong") is None, "")

    written = gecko.run_profile(profile, out)
    check(f"{label}: run_profile writes", written == 1, f"wrote {written}")
    if not (out / "passwords.json").is_file():
        check(f"{label}: passwords.json", False, "missing")
        return

    entries = json.loads((out / "passwords.json").read_text(encoding="utf-8"))
    check(f"{label}: username", entries[0]["username"] == "killywilly", entries[0]["username"])
    check(f"{label}: password", entries[0]["password"] == "correct-horse", entries[0]["password"])
    check(f"{label}: host", entries[0]["host"] == "https://example.invalid", "")
    check(
        f"{label}: timestamp",
        entries[0]["last_used"] == "2023-07-22T04:26:40+00:00",
        str(entries[0]["last_used"]),
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-gecko-") as scratch:
        root = Path(scratch)
        legacy = root / "legacy"
        modern = root / "modern"
        build_legacy(legacy)
        build_modern(modern)
        exercise("legacy", legacy, root / "out-legacy", 1)
        exercise("144", modern, root / "out-modern", 2)

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
