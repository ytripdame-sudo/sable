"""Exercise the large-archive link path with synthetic bytes.

Nothing from the machine is collected and nothing personal leaves it. This exists to
answer two questions a unit test cannot: does the expiring host accept a file this
size, and does the size-scaled timeout survive the transfer.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402

HOOK = sys.argv[1]
MEGABYTES = int(sys.argv[2]) if len(sys.argv) > 2 else 300

out = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out")
out.mkdir(parents=True, exist_ok=True)
archive = out / "sable-large-probe.zip"

if not archive.is_file() or archive.stat().st_size < MEGABYTES * 1024 * 1024:
    print(f"writing {MEGABYTES} MB of random bytes...")
    chunk = os.urandom(1024 * 1024)
    with archive.open("wb") as handle:
        for _ in range(MEGABYTES):
            handle.write(chunk)

size = archive.stat().st_size
host, fields = relay._link_host(size)
timeout = relay._upload_timeout(size)
print(f"archive    {size} bytes ({size / 1024 / 1024:.0f} MB)")
print(f"host       {host}")
print(f"timeout    {timeout:.0f} s")
print(f"fields     {fields}")

started = time.monotonic()
try:
    relay._send_link(HOOK, archive)
except relay.RelayError as exc:
    print(f"FAILED     {exc}")
    raise SystemExit(1) from exc
print(f"delivered  in {time.monotonic() - started:.1f} s")
