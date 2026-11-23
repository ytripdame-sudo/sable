"""Elevated command runner for the SABLE build harness.

Registered once as a scheduled task with /rl HIGHEST, so every later invocation
runs with an elevated token and no consent prompt. Reads the command from run.txt
beside this file, writes out.txt and rc.txt, and nothing else.

The task is registered /ru <current user>, not /ru SYSTEM: the DPAPI unwrap needs
the operator's own profile loaded, which a SYSTEM task would not have.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
RUN = BASE / "run.txt"
OUT = BASE / "out.txt"
RC = BASE / "rc.txt"
DONE = BASE / "done.txt"


def main() -> int:
    if not RUN.is_file():
        return 2

    command = RUN.read_text(encoding="utf-8").strip()
    if not command:
        return 2

    started = time.time()
    DONE.unlink(missing_ok=True)
    OUT.write_text("", encoding="utf-8")

    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=600,
            cwd=str(BASE),
        )
        body = (completed.stdout or "") + (completed.stderr or "")
        code = completed.returncode
    except subprocess.TimeoutExpired:
        body = "runner: command exceeded 600 s"
        code = 124
    except OSError as exc:
        body = f"runner: {exc}"
        code = 1

    OUT.write_text(body, encoding="utf-8")
    RC.write_text(str(code), encoding="utf-8")
    DONE.write_text(f"{started:.3f}", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
