# SIGNATURES

Every Win32 entry point `agent/winapi.py` is allowed to call, with the exact ctypes
declaration it must carry. Nothing in this project calls a Win32 function that is
not listed here. Signatures are written before implementation, and the
implementation matches them byte for byte.

## Conventions

- One module-level handle per library, all created with `use_last_error=True`:

  ```python
  _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
  _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
  _user32 = ctypes.WinDLL("user32", use_last_error=True)
  _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
  _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
  ```

- `ctypes.windll.<dll>` is banned. It implies `use_last_error=False`, which makes
  `ctypes.get_last_error()` return 0 forever and turns the mutex guard into a no-op.
  That is a real defect in the source repository, not a style note.
- Error retrieval is always `ctypes.get_last_error()`, immediately after the call,
  with nothing in between. Never `_k32.GetLastError()` — the two are not
  interchangeable once `use_last_error=True` is set.
- Every wrapper returns a typed Python value or `None`. No wrapper returns a raw
  `GetLastError()` code to its caller.
- Every function that writes into a caller buffer is declared with a `POINTER(...)`
  argtype, never `c_void_p`, so ctypes cannot silently accept the wrong object.
- Pointer-width types use `wintypes` (`HANDLE`, `HMODULE`, `DWORD`, `ULONG`,
  `LONG`, `BOOL`, `WCHAR`, `LPWSTR`, `LPCWSTR`, `LPVOID`, `SIZE_T`, `ULONG_PTR`).
  `GetProcAddress` and `CreateMutexW` are the two that must not use the default
  `c_int` restype.
- `wintypes` is not complete. `LSTATUS` and `HMONITOR` do not exist there and are
  written as `wintypes.LONG` and `wintypes.HANDLE`. Every `wintypes.*` name below
  was checked against `ctypes.wintypes` before it was written down; a missing
  attribute is an `AttributeError` at import, before a single line runs.

## Structures

Defined once in `agent/winapi.py`, never duplicated per module.

```python
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

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
    _fields_ = [("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG)]

class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", RECT),
                ("rcWork", RECT), ("dwFlags", wintypes.DWORD),
                ("szDevice", wintypes.WCHAR * 32)]

class SOCKADDR(ctypes.Structure):
    _fields_ = [("sa_family", wintypes.USHORT), ("sa_data", ctypes.c_char * 14)]

class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass

class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass

IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKADDR),
    # remaining members are not read; the struct is only walked by pointer
]

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
    # trailing members are not read
]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
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
```

`MEMORY_BASIC_INFORMATION64` carries the two `DWORD` alignment pads the 64-bit layout
has. Without them `RegionSize` lands four bytes early and every address walked after the
first non-empty region is wrong — a fault that produces plausible-looking output, which
is the worst kind.

`MAX_ADAPTER_ADDRESS_LENGTH` is 8 on Windows; the fixed 8-byte array is the
documented maximum and the length is always checked against it before slicing.

---

## kernel32

### GetSystemFirmwareTable
- C: `UINT GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);`
- argtypes: `[wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]`
- restype: `wintypes.UINT`
- failure: returns 0; `GetLastError()` is 122 (`ERROR_INSUFFICIENT_BUFFER`) on the
  size probe, which is the normal first call and not an error. Wrapper: probe with
  `None`/0, allocate a `bytearray` of the returned size, call again, return `bytes`
  on a non-zero second return, otherwise `None`.

### EnumSystemFirmwareTables
- C: `UINT EnumSystemFirmwareTables(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableEnumBuffer, DWORD BufferSize);`
- argtypes: `[wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]`
- restype: `wintypes.UINT`
- failure: returns 0 with 122 on the probe. Wrapper returns a `tuple[bytes, ...]` of
  4-byte table signatures, empty tuple on any other failure.

### RegOpenKeyExW
- DLL: advapi32
- C: `LSTATUS RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);`
- argtypes: `[wintypes.HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HKEY)]`
- restype: `wintypes.LONG` (`LSTATUS` is a `LONG`; `wintypes.LSTATUS` does not exist)
- failure: returns non-zero `LSTATUS` (2 `ERROR_FILE_NOT_FOUND`, 5
  `ERROR_ACCESS_DENIED`). Wrapper returns `None` and logs the code at DEBUG; the
  caller never sees it.

### RegQueryValueExW
- DLL: advapi32
- C: `LSTATUS RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);`
- argtypes: `[wintypes.HKEY, wintypes.LPCWSTR, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD)]`
- restype: `wintypes.LONG`
- note: `lpReserved` is a reserved `LPVOID` and is always passed as `None`.
  Declaring it `POINTER(DWORD)` happens to work and misdescribes the parameter.
- failure: 2 when the value is absent, 234 (`ERROR_MORE_DATA`) when the buffer was
  too small. Wrapper: query type and size with `None`/0, then read into a bytearray
  and decode per type (`REG_SZ`/`REG_EXPAND_SZ` as UTF-16LE, `REG_DWORD` as int).
  Returns `str | int | bytes | None`.

### RegCloseKey
- DLL: advapi32
- C: `LSTATUS RegCloseKey(HKEY hKey);`
- argtypes: `[wintypes.HKEY]`
- restype: `wintypes.LONG`
- failure: non-zero on an invalid handle. Wrapper returns `None`; called in `finally`.

### GetAdaptersAddresses
- DLL: iphlpapi
- C: `ULONG GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);`
- argtypes: `[wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID, wintypes.LPVOID, ctypes.POINTER(wintypes.ULONG)]`
- restype: `wintypes.ULONG`
- note: `AdapterAddresses` is `LPVOID` because the wrapper hands it a
  `create_string_buffer`; the block is cast to `POINTER(IP_ADAPTER_ADDRESSES)` for
  the walk. Declaring it `POINTER(IP_ADAPTER_ADDRESSES)` works only while every
  caller remembers to cast, and the one place that forgets is a crash.
- failure: 111 (`ERROR_BUFFER_OVERFLOW`) on the size probe, 232
  (`ERROR_NO_DATA`) when no adapter exists. Wrapper loops at most three times,
  growing the buffer to the reported size, returns `list[AdapterInfo]`, empty list
  on 232 or any unrecoverable code.

### GlobalMemoryStatusEx
- C: `BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer);`
- argtypes: `[ctypes.POINTER(MEMORYSTATUSEX)]`
- restype: `wintypes.BOOL`
- failure: 0 with `GetLastError()` 87 (`ERROR_INVALID_PARAMETER`) when `dwLength`
  is wrong. Wrapper sets `dwLength = sizeof(MEMORYSTATUSEX)` first, returns `None`
  on 0.

### EnumDisplayMonitors
- DLL: user32
- C: `BOOL EnumDisplayMonitors(HDC hdc, LPCRECT lprcClip, MONITORENUMPROC lpfnEnum, LPARAM dwData);`
- argtypes: `[wintypes.HDC, ctypes.POINTER(RECT), MONITORENUMPROC, wintypes.LPARAM]`
- restype: `wintypes.BOOL`
- `MONITORENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.HDC, ctypes.POINTER(RECT), wintypes.LPARAM)`
- note: `wintypes.HMONITOR` does not exist; `HMONITOR` is a `HANDLE`. `WINFUNCTYPE`
  is absent on non-Windows, so the module binds
  `getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)` and imports cleanly everywhere.
- failure: returns 0 if the callback never ran or the callback returned 0. Wrapper
  collects into a list held alive for the duration of the call and returns
  `list[tuple[int, int]]` of monitor rectangles.

### GetMonitorInfoW
- DLL: user32
- C: `BOOL GetMonitorInfoW(HMONITOR hMonitor, LPMONITORINFO lpmi);`
- argtypes: `[wintypes.HANDLE, ctypes.POINTER(MONITORINFOEXW)]`
- restype: `wintypes.BOOL`
- failure: 0 with 87 when `cbSize` is wrong. Wrapper returns `None`; caller skips
  that monitor and keeps the rest.

### GetTickCount64
- C: `ULONGLONG GetTickCount64(void);`
- argtypes: `[]`
- restype: `ctypes.c_ulonglong`
- failure: cannot fail; wraps after 584 million years. `c_ulonglong` is mandatory —
  the default `c_int` restype truncates the high dword and reports a machine that
  has been up for three days as being up for three minutes.

### GetNativeSystemInfo
- C: `void GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);`
- argtypes: `[ctypes.POINTER(SYSTEM_INFO)]`
- restype: `None`
- failure: none. Returns a filled `SYSTEM_INFO`; `dwNumberOfProcessors` is the
  core count for gate check 10.

### GetDiskFreeSpaceExW
- C: `BOOL GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);`
- argtypes: `[wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]`
- restype: `wintypes.BOOL`
- failure: 0 with 3 (`ERROR_PATH_NOT_FOUND`) on a bad drive. Wrapper returns total
  bytes as `int | None`.

### GetUserNameW
- C: `BOOL GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);`
- argtypes: `[wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]`
- restype: `wintypes.BOOL`
- failure: 0 with 122 when the buffer is short. Wrapper passes a 257-char buffer,
  returns `str | None`. Used instead of `os.getlogin()`, which raises when the
  process has no console.

### CreateMutexW
- C: `HANDLE CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);`
- argtypes: `[wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]`
- restype: `wintypes.HANDLE` — declared as `ctypes.c_void_p` so a truncated handle
  cannot be mistaken for success on x64.
- failure: returns `NULL` on failure, and a valid handle when the mutex already
  exists. Existence is `ctypes.get_last_error() == 183` (`ERROR_ALREADY_EXISTS`),
  read immediately after the call. Wrapper returns `(handle, created)`; the loader
  exits 0 silently when `created` is False, and never closes the handle (the OS
  releases it at process exit, and closing it would drop the guard).

### CreateToolhelp32Snapshot
- C: `HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);`
- argtypes: `[wintypes.DWORD, wintypes.DWORD]`
- restype: `wintypes.HANDLE`
- failure: `INVALID_HANDLE_VALUE` (-1) with a `GetLastError()` code. Wrapper returns
  `None` on `INVALID_HANDLE_VALUE`; compare against
  `ctypes.c_void_p(-1).value`, not against `0`.

### Process32FirstW
- C: `BOOL Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);`
- argtypes: `[wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]`
- restype: `wintypes.BOOL`
- failure: 0 with 18 (`ERROR_NO_MORE_FILES`) on an empty snapshot. Wrapper returns
  `bool`.

### Process32NextW
- C: `BOOL Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);`
- argtypes: `[wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]`
- restype: `wintypes.BOOL`
- failure: 0 with 18 at the end of the enumeration, which is the normal exit.
  Wrapper: `dwSize` is set before every call, the loop is capped at 4096 entries,
  returns `frozenset[str]` of lowercased basenames.

### CloseHandle
- C: `BOOL CloseHandle(HANDLE hObject);`
- argtypes: `[wintypes.HANDLE]`
- restype: `wintypes.BOOL`
- failure: 0 with 6 (`ERROR_INVALID_HANDLE`). Wrapper returns `None`; called in
  `finally` for the snapshot handle.

### OpenProcess
- C: `HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);`
- argtypes: `[wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]`
- restype: `wintypes.HANDLE`
- failure: `NULL` with 5 (`ERROR_ACCESS_DENIED`) when the target runs at a higher
  integrity level, or 87 for a dead pid. `RemoteProcess.__enter__` asks for
  `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` and retries with
  `PROCESS_VM_READ | PROCESS_QUERY_LIMITED`; if both refuse, the wrapper reports the
  handle as absent rather than raising, because one unreadable browser child is not the
  end of the scan.

### VirtualQueryEx
- C: `SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress,
  PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);`
- argtypes: `[wintypes.HANDLE, ctypes.c_ulonglong,
  ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t]`
- restype: `ctypes.c_size_t`
- failure: 0, which means the address is past the last region and is the normal exit
  from the walk. The wrapper advances by `BaseAddress + RegionSize` and stops at
  `1 << 47`, so a malformed length cannot spin.

### ReadProcessMemory
- C: `BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer,
  SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);`
- argtypes: `[wintypes.HANDLE, ctypes.c_ulonglong, wintypes.LPVOID, ctypes.c_size_t,
  ctypes.POINTER(ctypes.c_size_t)]`
- restype: `wintypes.BOOL`
- failure: 0 with 299 (`ERROR_PARTIAL_COPY`) on a page that went unreadable between the
  query and the read. `RemoteProcess.read_into` returns the byte count on success and 0
  on failure; 0 ends the region, never the process.

### K32GetProcessMemoryInfo
- C: `BOOL K32GetProcessMemoryInfo(HANDLE Process,
  PPROCESS_MEMORY_COUNTERS_EX ppsmemCounters, DWORD cb);`
- argtypes: `[wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
  wintypes.DWORD]`
- restype: `wintypes.BOOL`
- failure: 0 with 87 when `cb` does not match the struct. Bound as
  `K32GetProcessMemoryInfo` and not `GetProcessMemoryInfo`, which lives in
  `psapi.dll` on the target range. Wrapper returns `int | None`; `None` sorts last in
  the scan order instead of inheriting a sentinel number.

### GetModuleHandleW
- C: `HMODULE GetModuleHandleW(LPCWSTR lpModuleName);`
- argtypes: `[wintypes.LPCWSTR]`
- restype: `wintypes.HMODULE`
- failure: `NULL` with 126 (`ERROR_MOD_NOT_FOUND`). Wrapper returns `int | None`
  after `ctypes.cast(handle, ctypes.c_void_p).value`.

### LoadLibraryW
- C: `HMODULE LoadLibraryW(LPCWSTR lpLibFileName);`
- argtypes: `[wintypes.LPCWSTR]`
- restype: `wintypes.HMODULE`
- failure: `NULL` with 126 or 193 (`ERROR_BAD_EXE_FORMAT`). Wrapper returns
  `int | None`.

### GetProcAddress
- C: `FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);`
- argtypes: `[wintypes.HMODULE, wintypes.LPCSTR]`
- restype: `ctypes.c_void_p` — mandatory. The default `c_int` restype truncates the
  64-bit pointer to 32 bits, and any write through the result lands in the wrong
  address space. This is the single most damaging line in the source repository.
- failure: `NULL` with 127 (`ERROR_PROC_NOT_FOUND`). Wrapper returns `int | None`.

### LocalFree
- C: `HLOCAL LocalFree(HLOCAL hMem);`
- argtypes: `[wintypes.HLOCAL]`
- restype: `wintypes.HLOCAL`
- failure: returns the handle unchanged on failure. Wrapper ignores the return and
  is called in `finally` after `CryptUnprotectData`.

### VirtualProtect
- C: `BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);`
- argtypes: `[wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]`
- restype: `wintypes.BOOL`
- failure: 0 with 87 (`ERROR_INVALID_PARAMETER`) on a bad address or protection
  value. Wrapper returns the previous protection as `int | None`; the caller writes,
  then restores with a second `VirtualProtect` call. A wrapper that leaves the page
  executable-writable is a worse defect than the patch it enables.
- constant: `PAGE_EXECUTE_READWRITE` 0x40.

## crypt32

### CryptUnprotectData
- C: `BOOL CryptUnprotectData(DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, DWORD dwFlags, DATA_BLOB *pDataOut);`
- argtypes: `[ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DATA_BLOB), wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]`
- restype: `wintypes.BOOL`
- failure: 0 with 13 (`ERROR_INVALID_DATA`) on a blob this user cannot unwrap, or
  87. Wrapper copies the input into a ctypes buffer, calls with
  `pOptionalEntropy=None`, `dwFlags=0`, copies `pDataOut` to `bytes`, frees
  `pDataOut.pbData` with `LocalFree`, returns `bytes | None`. The input buffer is
  kept referenced for the duration of the call — a temporary freed before the call
  returns is the classic silent-corruption bug here.

## Constants

`ERROR_SUCCESS` 0, `ERROR_FILE_NOT_FOUND` 2, `ERROR_PATH_NOT_FOUND` 3,
`ERROR_INVALID_HANDLE` 6, `ERROR_INVALID_DATA` 13, `ERROR_NO_MORE_FILES` 18,
`ERROR_INVALID_PARAMETER` 87, `ERROR_INSUFFICIENT_BUFFER` 122,
`ERROR_MOD_NOT_FOUND` 126, `ERROR_PROC_NOT_FOUND` 127, `ERROR_ALREADY_EXISTS` 183,
`ERROR_NO_DATA` 232, `ERROR_MORE_DATA` 234, `ERROR_BUFFER_OVERFLOW` 111.

`PAGE_EXECUTE_READWRITE` 0x40, `PAGE_READWRITE` 0x04.

`PROCESS_VM_READ` 0x0010, `PROCESS_QUERY_INFORMATION` 0x0400,
`PROCESS_QUERY_LIMITED_INFORMATION` 0x1000. `MEM_COMMIT` 0x1000,
`PAGE_GUARD` 0x100, `PAGE_NOACCESS` 0x01. Readable base protections: 0x02 read,
0x04 read/write, 0x08 write-copy, 0x20 execute-read, 0x40 execute-read/write,
0x80 execute-write-copy.

`TH32CS_SNAPPROCESS` 0x00000002.
`AF_UNSPEC` 0, `GAA_FLAG_SKIP_ANYCAST` 0x2, `GAA_FLAG_SKIP_MULTICAST` 0x4,
`GAA_FLAG_SKIP_DNS_SERVER` 0x8.

## Not used, and why

- `wmic`, `tasklist`, `getmac`, `reg.exe` — deprecated or absent on the target
  range, and all four are shell wrappers around the calls above.
- `pywin32` — a third-party dependency for functions ctypes already reaches.
- `zipimporter.load_module` — deprecated in 3.12; `importlib.util` with
  `exec_module` is the supported path.
- `IsDebuggerPresent`, `NtQueryInformationProcess` — the source repository's
  anti-debug class was never called; nothing here replaces it.
