"""End-to-end check of the exact client the artifact uses.

curl is not a fair test against catbox: it sends ``curl/8.x`` and Cloudflare answers
403. The artifact sends a browser agent, so the only meaningful test is the same
urllib request the artifact makes.
"""

from __future__ import annotations

import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402

UA = relay._USER_AGENT


def get(url: str, method: str = "GET", range_header: str | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method=method)
    request.add_header("User-Agent", UA)
    if range_header:
        request.add_header("Range", range_header)
    try:
        with urllib.request.urlopen(request, timeout=60, context=relay._SSL) as response:
            return int(response.status), response.read(4096)
    except urllib.error.HTTPError as exc:
        return int(exc.code), b""
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc).encode()


def upload() -> str:
    probe = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out\probe.zip")
    probe.write_bytes(b"PK\x03\x04" + b"sable" * 256)
    body, boundary = relay._multipart(
        {"reqtype": "fileupload", "time": "72h"},
        "fileToUpload",
        probe.name,
        probe.read_bytes(),
        "application/zip",
    )
    request = urllib.request.Request(relay._LITTERBOX, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(len(body)))
    request.add_header("User-Agent", UA)
    with urllib.request.urlopen(request, timeout=120, context=relay._SSL) as response:
        return response.read(4096).decode("utf-8", "replace").strip()


print("1. uploading through the artifact's own client ...")
try:
    url = upload()
except Exception as exc:  # noqa: BLE001
    print(f"   upload failed: {type(exc).__name__}: {exc}")
    raise SystemExit(1)

print(f"   host returned: {url}")
if not url.startswith("http"):
    print("   REFUSED: not a url")
    raise SystemExit(1)

print("2. fetching that exact url back (1 byte) ...")
time.sleep(2)
status, body = get(url, range_header="bytes=0-0")
print(f"   status {status} {body[:80]!r}")

print(f"\nverdict: {'the url works' if status in (200, 206) else 'the url does not work'}")
