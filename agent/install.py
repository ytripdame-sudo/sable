"""Where the image lives, and how it gets there.

A one-file artifact is one file, so staging it is ``shutil.copyfile``. A one-directory
artifact is a tree: the exe is a bootstrap and the interpreter it loads sits in
``_internal`` beside it. Copying only the exe out of that tree produces a file that dies
inside the PyInstaller bootloader with "Failed to load Python DLL" and exit code -1,
before ``agent.loader`` is ever imported. Every trailer check still passes, because the
trailer is intact; there is simply no interpreter to read it.

That failure is why this module exists rather than one more ``copyfile`` at the call site.
The unit of a staged image is the **shape** of the running image, not the exe.

Two things live here:

``stage_image``
    Put a runnable copy of this image somewhere and report whether it is runnable. Used by
    ``util.install_persistence``, which needs a copy that survives the original's
    self-remove.

``install`` / ``uninstall``
    The per-user install: a folder under ``%LOCALAPPDATA%\\Programs``, an entry in
    Add/Remove Programs under HKCU, and one removal path that takes back everything it
    wrote. No admin, no UAC, no machine-wide state.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Final

from . import log, winapi

# The folder a one-directory freeze keeps its interpreter in. Its presence beside the
# running exe is what says "this image is a tree" without asking PyInstaller.
INTERNAL_DIR: Final[str] = "_internal"

# The removal script written beside the image and named by the ARP entry.
UNINSTALL_SCRIPT: Final[str] = "uninstall.cmd"

# Add/Remove Programs, per user. Machine-wide uninstall entries need admin; these do not.
ARP_ROOT: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

_PROGRAMS: Final[Path] = (
    Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "Programs"
)


def tree_root() -> Path | None:
    """The frozen tree this process is running out of, or None.

    None means "one file, or not frozen at all". Both are handled by copying a single
    file, so the caller does not need to tell them apart.
    """
    if not getattr(sys, "frozen", False):
        return None
    directory = Path(sys.executable).resolve().parent
    if (directory / INTERNAL_DIR).is_dir():
        return directory
    return None


def programs_root() -> Path:
    """Where per-user installs live. Read at call time so a redirect is respected."""
    return Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "Programs"


def _inventory(root: Path) -> tuple[int, int]:
    """``(file count, total bytes)``. Used to verify a copy that reported success."""
    count = 0
    total = 0
    for item in root.rglob("*"):
        if item.is_file():
            count += 1
            try:
                total += item.stat().st_size
            except OSError:
                # A file that vanished mid-walk makes the totals disagree, which is the
                # answer this function exists to give. Counting it as zero is honest.
                continue
    return count, total


def copy_tree(source: Path, destination: Path) -> bool:
    """Copy a whole frozen tree and verify it landed. False on any disagreement.

    The verification is a count and a byte total, not a hash: the point is to catch a
    partial copy, and hashing 22 MB to catch a truncated file is work for no extra
    answer.
    """
    try:
        want = _inventory(source)
    except OSError:
        log.logger.debug("install: cannot inventory %s", source)
        return False

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
    except FileExistsError:
        # Already staged. The caller decides whether that is success; a second copy is
        # never attempted on top of a live one.
        try:
            return _inventory(destination) == want
        except OSError:
            return False
    except OSError:
        log.logger.debug("install: could not copy %s", source, exc_info=True)
        return False

    try:
        if _inventory(destination) != want:
            log.logger.debug("install: short copy, want %s got %s", want, _inventory(destination))
            shutil.rmtree(destination, ignore_errors=True)
            return False
    except OSError:
        return False
    return True


def stage_image(executable: Path, destination: Path) -> Path | None:
    """Put a runnable copy of the running image at ``destination`` (a directory).

    A tree is staged whole. A one-file image is staged as the single exe inside it. The
    returned path is the file to run, or None when nothing runnable landed.
    """
    root = tree_root()
    if root is not None:
        exe_name = Path(sys.executable).name
        if not copy_tree(root, destination):
            return None
        staged = destination / exe_name
        return staged if staged.is_file() else None

    try:
        want = executable.stat().st_size
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / executable.name
        shutil.copyfile(executable, target)
        if target.stat().st_size != want:
            target.unlink(missing_ok=True)
            return None
        return target
    except OSError:
        log.logger.debug("install: could not stage %s", executable, exc_info=True)
        return None


def arp_key(identifier: str) -> str:
    """The HKCU uninstall subkey for one installed product."""
    return f"{ARP_ROOT}\\{identifier}"


def register(
    destination: Path,
    *,
    identifier: str,
    display_name: str,
    uninstall_command: str,
    version: str = "",
    publisher: str = "",
) -> bool:
    """Write the Add/Remove Programs record for a folder that is already staged.

    Separate from ``install`` because the persistence path stages into its own folder and
    then registers it: one folder, one Run value, one record, one removal. Two staging
    routines writing two folders is how a host ends up with software nobody can find.
    """
    if sys.platform != "win32":
        return False

    key = arp_key(identifier)
    if not winapi.registry_create_key(winapi.HKEY_CURRENT_USER, key):
        return False

    count, total = _inventory(destination)
    entries: list[tuple[str, str]] = [
        ("DisplayName", display_name),
        ("DisplayIcon", str(destination)),
        ("UninstallString", uninstall_command),
        # The user can neither change nor repair it, which is what stops the
        # "Modify" button appearing on a program that has no maintenance mode.
        ("NoModify", "1"),
        ("NoRepair", "1"),
        # In KB, which is the unit this key is documented in. A tree of 79 files
        # rounds to zero in MB on some builds, and a zero size draws attention.
        ("EstimatedSize", str(max(1, total // 1024))),
    ]
    if version:
        entries.append(("DisplayVersion", version))
    if publisher:
        entries.append(("Publisher", publisher))

    wrote = all(
        winapi.registry_set_string(winapi.HKEY_CURRENT_USER, key, name, value)
        for name, value in entries
    )
    if not wrote:
        # A half-built ARP entry is worse than none: it names a folder that may not be
        # there and an uninstall string nothing guarantees. Take the record back and
        # leave the staged image for the caller to decide about.
        winapi.registry_delete_key(winapi.HKEY_CURRENT_USER, key)
        return False

    log.logger.debug("install: %d files, %d bytes at %s", count, total, destination)
    return True


def install(
    destination: Path,
    *,
    identifier: str,
    display_name: str,
    uninstall_command: str,
    version: str = "",
    publisher: str = "",
) -> Path | None:
    """Stage this image into ``destination`` and register it for removal.

    Returns the path to run, or None. The Run-key entry is the caller's business: this
    function owns the folder and the Add/Remove Programs record, nothing else.
    """
    staged = stage_image(Path(sys.executable).resolve(), destination)
    if staged is None:
        return None

    if not register(
        destination,
        identifier=identifier,
        display_name=display_name,
        uninstall_command=uninstall_command,
        version=version,
        publisher=publisher,
    ):
        return None
    return staged


def uninstall(
    destination: Path,
    *,
    identifier: str,
    run_value: str | None = None,
    tasks: tuple[str, ...] = (),
) -> bool:
    """Remove everything ``install`` wrote. True when the folder is gone.

    Order is deliberate: the registration goes first so a failure halfway cannot leave a
    removal path pointing at nothing, then the tasks, then the files. A partial uninstall
    that still leaves a working entry is the failure mode worth avoiding.
    """
    if sys.platform != "win32":
        return False

    winapi.registry_delete_key(winapi.HKEY_CURRENT_USER, arp_key(identifier))

    if run_value is not None:
        winapi.registry_delete_value(
            winapi.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            run_value,
        )

    for task in tasks:
        _delete_task(task)

    shutil.rmtree(destination, ignore_errors=True)
    return not destination.exists()


def _delete_task(name: str) -> bool:
    """Remove one scheduled task by absolute path to ``schtasks``.

    Same reason as ``util._schtasks``: a bare name is resolved off PATH, and a removal
    that runs somebody else's binary is not a removal.
    """
    system32 = Path(os.environ.get("SYSTEMROOT") or r"C:\Windows") / "System32"
    from . import util  # local: util imports nothing from here, but keep the cycle flat

    done = util.run_hidden(
        [system32 / "schtasks.exe", "/delete", "/tn", name, "/f"], timeout=20
    )
    return done is not None and done.returncode == 0


def uninstall_batch(
    destination: Path, *, identifier: str, run_value: str | None, tasks: tuple[str, ...]
) -> str:
    """A batch file that performs the uninstall, for the ARP ``UninstallString``.

    Add/Remove Programs runs its command in whatever directory the shell happens to be
    in, and a bare relative path is not resolvable there. A ``.cmd`` written beside the
    image carries absolute paths and leaves nothing behind.

    The prologue is not decoration. ``cmd.exe`` holds a batch file open while it reads
    it, so a batch that deletes its own folder from inside that folder fails on the last
    line — the one that matters. Copying to ``%TEMP%`` and re-running from there puts the
    running script outside the tree it is deleting, and the marker in the environment
    keeps the copy from copying itself again.
    """
    lines = ["@echo off", "setlocal"]
    lines.append('if defined SABLE_UNINSTALL_TEMP goto :run')
    lines.append('copy /y "%~f0" "%TEMP%\\~sable-uninstall.cmd" >nul 2>&1')
    lines.append('if not exist "%TEMP%\\~sable-uninstall.cmd" goto :run')
    lines.append('set "SABLE_UNINSTALL_TEMP=1"')
    lines.append('start "" /wait "%TEMP%\\~sable-uninstall.cmd"')
    lines.append('del "%TEMP%\\~sable-uninstall.cmd" >nul 2>&1')
    lines.append("exit /b")
    lines.append(":run")
    lines.append(f'reg delete "HKCU\\{arp_key(identifier)}" /f >nul 2>&1')
    if run_value is not None:
        lines.append(
            f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            f'/v "{run_value}" /f >nul 2>&1'
        )
    for task in tasks:
        lines.append(f'schtasks /delete /tn "{task}" /f >nul 2>&1')
    lines.append("timeout /t 2 /nobreak >nul 2>&1")
    lines.append(f'rmdir /s /q "{destination}" >nul 2>&1')
    lines.append('(goto) 2>nul & del "%~f0"')
    return "\r\n".join(lines) + "\r\n"


def write_uninstaller(
    destination: Path,
    *,
    identifier: str,
    run_value: str | None,
    tasks: tuple[str, ...],
) -> str | None:
    """Write the uninstall batch beside the image and return the command that runs it.

    The command goes through ``cmd.exe`` explicitly. Add/Remove Programs will not run a
    ``.cmd`` directly on every Windows build, and a quoted command line through ``/c`` is
    the form that does not depend on the file association being intact.
    """
    script = destination / UNINSTALL_SCRIPT
    try:
        destination.mkdir(parents=True, exist_ok=True)
        script.write_bytes(
            uninstall_batch(
                destination, identifier=identifier, run_value=run_value, tasks=tasks
            ).encode("mbcs")
        )
    except OSError:
        log.logger.debug("install: could not write %s", script, exc_info=True)
        return None
    return f'cmd.exe /c ""{script}""'


__all__ = [
    "ARP_ROOT",
    "INTERNAL_DIR",
    "UNINSTALL_SCRIPT",
    "arp_key",
    "copy_tree",
    "install",
    "programs_root",
    "register",
    "stage_image",
    "tree_root",
    "uninstall",
    "uninstall_batch",
    "write_uninstaller",
]
