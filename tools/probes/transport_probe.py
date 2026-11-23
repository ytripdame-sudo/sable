"""Prove both transports from this desk, with the ticket's real credentials.

Uses ``agent.relay``'s own senders, so what is tested is the code the artifact runs and
not a second implementation of the same request. The file is tiny: the point is the
handshake, the credentials and the chat/repository, not the bytes.

    python tools/probes/transport_probe.py telegram
    python tools/probes/transport_probe.py phantom
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import log, relay  # noqa: E402

# Endpoints are ``kind$bind`` and both halves are credentials. They were literals while
# this probe ran for the first time, which is also why the first push was refused: a
# repository is the wrong home for a bot token and a PAT. They come in from the
# environment now, and the probe refuses rather than running against a guess.
TELEGRAM = os.environ.get("SABLE_PROBE_TELEGRAM", "")
PHANTOM = os.environ.get("SABLE_PROBE_PHANTOM", "")
if not TELEGRAM or not PHANTOM:
    raise SystemExit(
        "set SABLE_PROBE_TELEGRAM=<bot_token>$<chat_id> and "
        "SABLE_PROBE_PHANTOM=<owner>/<repo>$<token>, then run this probe"
    )

which = sys.argv[1] if len(sys.argv) > 1 else "telegram"
scratch = Path(r"C:\Users\Kuzenee\AppData\Local\Temp\opencode\transport_probe")
scratch.mkdir(parents=True, exist_ok=True)

target = scratch / f"sable-transport-probe-{time.strftime('%H%M%S')}.zip"
with zipfile.ZipFile(target, "w") as bundle:
    bundle.writestr("README.txt", "transport probe: this file carries no collected data\n")

print(f"probe file {target.name}  {target.stat().st_size} bytes")
print(f"channel    {which}")

started = time.monotonic()
try:
    if which == "telegram":
        relay._send_telegram(TELEGRAM, target, "sable transport probe: telegram primary")
    elif which == "phantom":
        relay._send_phantom(PHANTOM, target, "sable transport probe: phantom fallback")
    else:
        raise SystemExit(f"unknown channel {which}")
except Exception as exc:
    print(f"FAIL  {type(exc).__name__}: {exc}")
    raise SystemExit(1)

print(f"PASS  accepted in {time.monotonic() - started:.2f} s")
