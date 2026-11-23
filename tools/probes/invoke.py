"""Invoke the persistent elevated runner. No consent prompt, ever.

Usage:
    python invoke.py "<command>"
    python invoke.py --file commands.txt

Writes the command to run.txt, starts the SABLE-ELEVATED task, waits for
done.txt, then prints the runner's stdout/stderr and exit code.

The task itself is registered once with /rl HIGHEST. Everything after that is a
plain schtasks /run, which needs no elevation and raises no UAC dialog.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
RUN = BASE / "run.txt"
OUT = BASE / "out.txt"
RC = BASE / "rc.txt"
DONE = BASE / "done.txt"
LOCK = BASE / "lock"

TASK = "SABLE-ELEVATED"
TIMEOUT = 900.0
POLL = 0.15
LOCK_TIMEOUT = 60.0
LOCK_STALE = 1800.0


class _Lock:
    """Exclusive claim on the runner. The task runs one command at a time.

    A crashed invoker leaves the file behind, so a claim older than LOCK_STALE is
    taken over rather than blocking every later call.
    """

    def __init__(self) -> None:
        self._held = False

    def __enter__(self) -> "_Lock":
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                fd = None
            if fd is not None:
                try:
                    os.write(fd, f"{os.getpid()} {time.time():.3f}".encode("ascii"))
                finally:
                    os.close(fd)
                self._held = True
                return self
            try:
                age = time.time() - LOCK.stat().st_mtime
            except FileNotFoundError:
                continue
            if age > LOCK_STALE:
                try:
                    LOCK.unlink()
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"runner lock held for {age:.0f}s")
            time.sleep(POLL)

    def __exit__(self, *_: object) -> None:
        if self._held:
            try:
                LOCK.unlink()
            except FileNotFoundError:
                pass
            self._held = False


def _clear() -> None:
    for path in (DONE, RC, OUT):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _start() -> bool:
    completed = subprocess.run(
        ["schtasks", "/run", "/tn", TASK],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: invoke.py \"<command>\" | --file <path>", file=sys.stderr)
        return 2

    if argv[0] == "--file":
        if len(argv) != 2:
            return 2
        command = Path(argv[1]).read_text(encoding="utf-8").strip()
    else:
        command = " ".join(argv).strip()

    if not command:
        print("empty command", file=sys.stderr)
        return 2

    with _Lock():
        _clear()
        RUN.write_text(command, encoding="utf-8")

        if not _start():
            print("schtasks /run failed", file=sys.stderr)
            return 3

        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if DONE.is_file():
                break
            time.sleep(POLL)
        else:
            print(f"runner did not finish within {TIMEOUT:.0f}s", file=sys.stderr)
            return 124

        body = OUT.read_text(encoding="utf-8", errors="replace") if OUT.is_file() else ""
        code = RC.read_text(encoding="utf-8").strip() if RC.is_file() else "?"

    sys.stdout.write(body)
    if body and not body.endswith("\n"):
        sys.stdout.write("\n")
    # Stdout, not stderr: PowerShell turns redirected stderr from a native process
    # into a NativeCommandError record, which buries the real exit code.
    print(f"[exit={code}]")
    try:
        return int(code)
    except ValueError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
