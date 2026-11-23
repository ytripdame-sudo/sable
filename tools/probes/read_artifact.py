"""Read back what an already-built artifact is pointed at.

Useful when a file appears and nobody remembers which build it was. Secrets are
reduced to a host so nothing lands in a transcript.
"""

from __future__ import annotations

import io
import json
import struct
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import loader  # noqa: E402

TARGET = Path(sys.argv[1])
data = TARGET.read_bytes()

FOOTER = loader.FOOTER_SIZE
TRAILER = loader.TRAILER_SIZE

footer = data[-FOOTER:]
print(f"footer magic   {footer[:4]!r}")
offset = struct.unpack("<Q", footer[4:])[0]
print(f"archive offset {offset}")
print(f"file size      {len(data)}")

trailer = data[-FOOTER - TRAILER: -FOOTER]
print(f"trailer magic  {trailer[:4]!r}")
key = trailer[4:4 + loader.KEY_SLOT].decode("utf-8", "replace")
print(f"key            {key!r}")

sealed = data[offset: -FOOTER - TRAILER]
archive = loader._open_sealed(sealed, key)
print(f"opened zip     {len(archive)} bytes")

with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
    print(f"members        {len(bundle.namelist())}")
    cfg = json.loads(bundle.read("cfg.json"))
    relay = cfg["relay"]

    def host(url: str) -> str:
        if not url:
            return "(empty)"
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    print(f"kind           {relay['kind']}")
    print(f"endpoint       {host(relay['endpoint'])}")
    print(f"status webhook {host(relay.get('ping', ''))}")
    print(f"mention        {relay.get('mention', '')!r}")
    print(f"self_remove    {cfg['self_remove']}")
    print(f"sources        {', '.join(sorted(k for k, v in cfg['sources'].items() if v))}")
