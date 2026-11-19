"""Virtual-host gate.

Eleven checks, two hits to declare virtual. The verdict is stamped and the run
proceeds; it never stops collection. A single hit is a coincidence, and the original
design used OR-logic across checks, one of which was "the cursor did not move in
500 ms", which is true on every idle desktop. A human tester is in a VM half the
time, so a silent exit is the one outcome that teaches nobody anything.
"""

from __future__ import annotations

import os
from typing import Callable, Final, NamedTuple

from . import log, winapi

_THRESHOLD: Final[int] = 2
_GIB: Final[int] = 1024 ** 3

_MIN_DISK_BYTES: Final[int] = 60 * _GIB
_MIN_RAM_BYTES: Final[int] = 4 * _GIB
_MIN_UPTIME_MS: Final[int] = 20 * 60 * 1000
_SMALL_MODES: Final[tuple[tuple[int, int], ...]] = ((1024, 768), (800, 600))

_HYPERVISOR_OUIS: Final[frozenset[str]] = frozenset(
    {
        "000569",
        "000c29",
        "001c14",
        "005056",
        "080027",
        "0003ff",
        "00155d",
    }
)

_HYPERVISOR_PROCESSES: Final[tuple[str, ...]] = (
    "vmtoolsd.exe",
    "vboxservice.exe",
    "vboxservice",
    "qemu-ga.exe",
    "xenservice.exe",
)

_SMBIOS_VENDORS: Final[tuple[str, ...]] = ("vmware", "virtualbox", "qemu", "xen")
_ACPI_VENDORS: Final[tuple[str, ...]] = ("VBOX", "QEMU", "BOCHS")

_HYPERVISOR_KEYS: Final[tuple[str, ...]] = (
    "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
)

_DEFAULT_USERNAMES: Final[frozenset[str]] = frozenset(
    {"user", "admin", "administrator", "test", "john", "sandbox", "wdagent"}
)


class Verdict(NamedTuple):
    virtual: bool
    hits: tuple[int, ...]
    reasons: tuple[str, ...]


def _system_drive() -> str:
    try:
        root = os.environ["SystemDrive"]
    except KeyError:
        root = "C:"
    return root + "\\"


def _check_mac() -> str | None:
    mac = winapi.first_physical_mac()
    if mac is None:
        return None
    oui = mac.replace(":", "").lower()[:6]
    if oui in _HYPERVISOR_OUIS:
        return f"mac {mac} is a hypervisor OUI"
    return None


def _check_processes() -> str | None:
    names = winapi.process_names()
    for candidate in _HYPERVISOR_PROCESSES:
        if candidate in names:
            return f"process {candidate} is running"
    return None


def _check_smbios() -> str | None:
    info = winapi.smbios_type1()
    if info is None:
        return None
    manufacturer = info["manufacturer"].lower()
    for vendor in _SMBIOS_VENDORS:
        if vendor in manufacturer:
            return f"smbios manufacturer {info['manufacturer']!r}"
    return None


def _check_acpi() -> str | None:
    for text in winapi.acpi_vendor_strings():
        upper = text.upper()
        for vendor in _ACPI_VENDORS:
            if vendor in upper:
                return f"acpi vendor {text!r}"
    return None


def _check_disk() -> str | None:
    total = winapi.disk_total_bytes(_system_drive())
    if total is None:
        return None
    if total < _MIN_DISK_BYTES:
        return f"disk {total / _GIB:.1f} GiB"
    return None


def _check_ram() -> str | None:
    status = winapi.memory_status()
    if status is None:
        return None
    if status.total_phys < _MIN_RAM_BYTES:
        return f"ram {status.total_phys / _GIB:.1f} GiB"
    return None


def _check_uptime() -> str | None:
    uptime = winapi.uptime_ms()
    if uptime is None:
        return None
    if uptime < _MIN_UPTIME_MS:
        return f"uptime {uptime // 1000} s"
    return None


def _check_display() -> str | None:
    """Exact match against the two default modes, never a range.

    A VM at 1280x720 does not hit and is not supposed to: 1024x768 and 800x600 are
    the sandbox and installer defaults. A tolerance would also fire on every
    1366x768 laptop, which is a real machine.
    """
    for monitor in winapi.monitors():
        mode = (monitor.right - monitor.left, monitor.bottom - monitor.top)
        if mode in _SMALL_MODES:
            return f"display {mode[0]}x{mode[1]}"
    return None


def _check_registry() -> str | None:
    for subkey in _HYPERVISOR_KEYS:
        if winapi.registry_key_exists(winapi.HKEY_LOCAL_MACHINE, subkey):
            return f"registry {subkey}"
    return None


def _check_cores() -> str | None:
    info = winapi.native_system_info()
    if info is None:
        return None
    if info.processors <= 1:
        return f"cores {info.processors}"
    return None


def _check_username() -> str | None:
    name = winapi.user_name()
    if name is None:
        return None
    if name.lower() in _DEFAULT_USERNAMES:
        return f"username {name!r}"
    return None


_CHECKS: Final[tuple[Callable[[], str | None], ...]] = (
    _check_mac,
    _check_processes,
    _check_smbios,
    _check_acpi,
    _check_disk,
    _check_ram,
    _check_uptime,
    _check_display,
    _check_registry,
    _check_cores,
    _check_username,
)


def evaluate() -> Verdict:
    """Run all eleven checks. A check that raises is a check that did not fire."""
    hits: list[int] = []
    reasons: list[str] = []

    for number, check in enumerate(_CHECKS, start=1):
        try:
            reason = check()
        except Exception:
            log.logger.debug("gate check %d raised", number, exc_info=True)
            continue
        if reason is None:
            continue
        hits.append(number)
        reasons.append(reason)

    return Verdict(
        virtual=len(hits) >= _THRESHOLD,
        hits=tuple(hits),
        reasons=tuple(reasons),
    )


def is_virtual() -> bool:
    """Convenience wrapper. The caller that stamps the result wants evaluate()."""
    return evaluate().virtual


__all__ = ["Verdict", "evaluate", "is_virtual"]
