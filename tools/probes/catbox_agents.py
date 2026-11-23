"""What catbox does to this client, by user agent.

The link relay uploaded once and then started answering 403. Before changing anything,
measure whether the refusal follows the agent or the address.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402

PROBE = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out\catbox-probe.zip")
PROBE.parent.mkdir(parents=True, exist_ok=True)
PROBE.write_bytes(b"PK\x03\x04" + b"sable" * 256)

AGENTS = (
    ("artifact", relay._USER_AGENT),
    ("curl", "curl/8.9.1"),
    ("none", None),
)


def upload(agent: str | None, label: str) -> None:
    body, boundary = relay._multipart(
        {"reqtype": "fileupload"},
        "fileToUpload",
        PROBE.name,
        PROBE.read_bytes(),
        "application/zip",
    )
    request = urllib.request.Request(relay._CATBOX, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(len(body)))
    if agent is not None:
        request.add_header("User-Agent", agent)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            answer = response.read(200).decode("utf-8", "replace").strip()
            print(f"{label:9} {response.status}  {answer}", flush=True)
    except urllib.error.HTTPError as exc:
        print(f"{label:9} http {exc.code}  {exc.read(160)[:160]!r}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"{label:9} {type(exc).__name__}: {exc}", flush=True)


for label, agent in AGENTS:
    upload(agent, label)
