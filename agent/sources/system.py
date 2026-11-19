"""System inventory.

One artifact, ``system.json``: firmware identity out of SMBIOS, CPU and GPU strings
out of the registry, physical memory, OS build, machine name, uptime and user.

``virtual.txt`` is not written here. The gate owns that verdict and ``entry.py``
stamps it before collection starts; a collector that also wrote it would race the
gate and could overwrite a real verdict with a stale one.

Every section is optional. A machine with no SMBIOS access, a registry key the
build does not have, or a memory query that fails drops that section and keeps the
rest, so the artifact is never empty just because one API said no.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final

from .. import util, winapi

_GIB: Final[int] = 1024 ** 3

_CPU_KEY: Final[str] = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
_OS_KEY: Final[str] = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_COMPUTER_KEY: Final[str] = r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"

# GPU class GUID is fixed by Windows; the child slots are 0000..000N and a desktop
# has at most a handful. Bounded rather than enumerated because winapi has no
# subkey enumeration and four slots covers every machine this runs on.
_GPU_CLASS: Final[str] = (
    r"SYSTEM\CurrentControlSet\Control\Class"
    r"\{4d36e968-e325-11ce-bfc1-08002be10318}"
)
_GPU_SLOTS: Final[tuple[str, ...]] = ("0000", "0001", "0002", "0003")

_ARCHITECTURES: Final[dict[int, str]] = {
    0: "x86",
    5: "arm",
    6: "ia64",
    9: "x64",
    12: "arm64",
}


def _text(root: int, subkey: str, name: str) -> str | None:
    """A non-empty string value, or None. Never returns whitespace."""
    value = winapi.registry_value(root, subkey, name)
    if isinstance(value, str):
        text = value.strip()
        if text:
            return text
    return None


def _dword(root: int, subkey: str, name: str) -> int | None:
    value = winapi.registry_value(root, subkey, name)
    if isinstance(value, int):
        return int(value)
    return None


def machine_name() -> str | None:
    """Computer name from the registry, falling back to the environment."""
    name = _text(winapi.HKEY_LOCAL_MACHINE, _COMPUTER_KEY, "ComputerName")
    if name is not None:
        return name
    try:
        fallback = os.environ["COMPUTERNAME"]
    except KeyError:
        return None
    fallback = fallback.strip()
    return fallback or None


def _human_uptime(milliseconds: int) -> str:
    seconds = milliseconds // 1000
    days, remainder = divmod(seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes = remainder // 60
    return f"{days}d {hours}h {minutes}m"


def _firmware() -> dict[str, str] | None:
    info = winapi.smbios_type1()
    if info is None:
        return None
    fields = ("manufacturer", "product", "version", "serial", "uuid")
    trimmed = {name: info[name].strip() for name in fields}
    if not any(trimmed.values()):
        return None
    return trimmed


def _cpu() -> dict[str, Any] | None:
    payload: dict[str, Any] = {}

    name = _text(winapi.HKEY_LOCAL_MACHINE, _CPU_KEY, "ProcessorNameString")
    if name is not None:
        payload["name"] = name
    identifier = _text(winapi.HKEY_LOCAL_MACHINE, _CPU_KEY, "Identifier")
    if identifier is not None:
        payload["identifier"] = identifier
    vendor = _text(winapi.HKEY_LOCAL_MACHINE, _CPU_KEY, "VendorIdentifier")
    if vendor is not None:
        payload["vendor"] = vendor
    mhz = _dword(winapi.HKEY_LOCAL_MACHINE, _CPU_KEY, "~MHz")
    if mhz is not None:
        payload["mhz"] = mhz

    info = winapi.native_system_info()
    if info is not None:
        payload["logical_processors"] = info.processors
        payload["page_size"] = info.page_size
        if info.architecture in _ARCHITECTURES:
            payload["architecture"] = _ARCHITECTURES[info.architecture]
        else:
            payload["architecture"] = f"arch_{info.architecture}"

    return payload or None


def _gpu() -> list[dict[str, str]]:
    found: list[dict[str, str]] = []

    for slot in _GPU_SLOTS:
        subkey = _GPU_CLASS + "\\" + slot
        name = _text(winapi.HKEY_LOCAL_MACHINE, subkey, "DriverDesc")
        if name is None:
            continue
        entry = {"slot": slot, "name": name}
        provider = _text(winapi.HKEY_LOCAL_MACHINE, subkey, "ProviderName")
        if provider is not None:
            entry["provider"] = provider
        driver = _text(winapi.HKEY_LOCAL_MACHINE, subkey, "DriverVersion")
        if driver is not None:
            entry["driver"] = driver
        found.append(entry)

    return found


def _os() -> dict[str, Any] | None:
    payload: dict[str, Any] = {}

    product = _text(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "ProductName")
    if product is not None:
        payload["product"] = product
    display = _text(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "DisplayVersion")
    if display is not None:
        payload["display_version"] = display
    edition = _text(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "EditionID")
    if edition is not None:
        payload["edition"] = edition

    build = _text(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "CurrentBuildNumber")
    if build is not None:
        revision = _dword(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "UBR")
        payload["build"] = build if revision is None else f"{build}.{revision}"

    installed = _dword(winapi.HKEY_LOCAL_MACHINE, _OS_KEY, "InstallDate")
    if installed is not None:
        stamp = util.unix_time(installed)
        if stamp is not None:
            payload["installed"] = stamp

    return payload or None


def _memory() -> dict[str, Any] | None:
    status = winapi.memory_status()
    if status is None:
        return None
    return {
        "total_bytes": status.total_phys,
        "available_bytes": status.avail_phys,
        "load_percent": status.load_percent,
        "total_gib": round(status.total_phys / _GIB, 2),
    }


def _uptime() -> dict[str, Any] | None:
    milliseconds = winapi.uptime_ms()
    if milliseconds is None or milliseconds < 0:
        return None
    return {
        "milliseconds": milliseconds,
        "seconds": milliseconds // 1000,
        "human": _human_uptime(milliseconds),
    }


def _machine() -> dict[str, str] | None:
    host = machine_name()
    if host is None:
        return None
    return {"hostname": host}


def _user() -> dict[str, str] | None:
    name = winapi.user_name()
    if name is None:
        return None
    text = name.strip()
    if not text:
        return None
    return {"name": text}


def run(out_dir: Path, cfg: Any) -> int:
    """Write ``system.json``. Returns the number of sections that carried data.

    ``cfg`` is unused: the flag that decided this module runs was checked by the
    registry in ``sources/__init__.py`` before the call.
    """
    payload: dict[str, Any] = {}
    written = 0

    sections: tuple[tuple[str, Any], ...] = (
        ("firmware", _firmware()),
        ("cpu", _cpu()),
        ("gpu", _gpu()),
        ("os", _os()),
        ("memory", _memory()),
        ("uptime", _uptime()),
        ("machine", _machine()),
        ("user", _user()),
    )

    for name, value in sections:
        if not value:
            continue
        payload[name] = value
        written += 1

    if written == 0:
        return 0
    if not util.write_json(out_dir / "system.json", payload):
        return 0
    return written


__all__ = ["machine_name", "run"]
