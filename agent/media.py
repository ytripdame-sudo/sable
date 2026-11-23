"""One frame off the first real camera, through Media Foundation.

The only COM in the payload, and it is here because every alternative is worse. VFW's
``capCreateCaptureWindow`` needs a window, a message pump and a driver dialog on a
desktop nobody is watching. DirectShow's ``ICreateDevEnum`` plus a sample grabber needs
``qedit.dll``, which is deprecated and absent on some installs. The Media Foundation
source reader is three interfaces deep and needs no window at all.

The vtable indices are the part of this file that has to be exactly right, so they are
written with the index next to the name and were checked against the interface
declarations rather than remembered:

    IMFAttributes    GetUINT32 7    GetUINT64 8    GetAllocatedString 13
                     SetUINT32 21   SetGUID 24     SetString 25    Release 2
    IMFMediaBuffer   Lock 3         Unlock 4       GetCurrentLength 5
    IMFSample        ConvertToContiguousBuffer 41
    IMFSourceReader  GetCurrentMediaType 6   SetCurrentMediaType 7   ReadSample 9

Device selection is by symbolic link rather than by activating an ``IMFActivate``: the
link is a string, ``MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK`` pins the
source to exactly that device, and the activate array is released in one loop without a
second interface to get wrong.

Virtual cameras are filtered out by friendly name. OBS, Snap, ManyCam and NVIDIA
Broadcast all install as capture devices, and a frame of somebody's OBS scene is not a
picture of the room the machine is in.
"""

from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from . import gdi, log

_WINDOWS: Final[bool] = sys.platform == "win32"

MF_VERSION: Final[int] = 0x00020070  # MF_SDK_VERSION 2, MF_API_VERSION 0x70
MFSTARTUP_FULL: Final[int] = 0

# MF_SOURCE_READER_FIRST_VIDEO_STREAM is 0xFFFFFFFC; kept unsigned so it can be passed
# through a DWORD argument without a signedness conversion.
FIRST_VIDEO_STREAM: Final[int] = 0xFFFFFFFC

# Outcome names. These travel in camera.json and are never collapsed: "no camera on this
# laptop" and "the privacy setting refused the request" are different reports, and the
# second one is a fact about the machine's configuration.
NO_DEVICE: Final[str] = "no device"
BLOCKED: Final[str] = "blocked"
BUSY: Final[str] = "busy"
OK: Final[str] = "ok"
ERROR: Final[str] = "error"
TIMEOUT: Final[str] = "timeout"

# Friendly-name fragments that mean "this is not a camera pointed at a room".
_VIRTUAL_NAMES: Final[tuple[str, ...]] = (
    "obs virtual",
    "obs-camera",
    "virtual camera",
    "snap camera",
    "manycam",
    "e2esoft",
    "vcam",
    "nvidia broadcast",
    "droidcam",
    "iriun",
    "xsplit",
    "youcam",
    "splitcam",
    "webcammax",
)

_WANT_WIDTH: Final[int] = 1280
_WANT_HEIGHT: Final[int] = 720
_WANT_FPS: Final[int] = 30

# Empty reads before giving up. A camera that has just been opened needs a few hundred
# milliseconds to deliver its first sample, and the reader answers with no sample rather
# than blocking, so the wait is a poll with a ceiling.
_READ_ATTEMPTS: Final[int] = 40
_READ_SLEEP: Final[float] = 0.05

if _WINDOWS:
    _mfplat = ctypes.WinDLL("mfplat", use_last_error=True)
    # Device enumeration and device source creation are in mf.dll, not mfplat.dll.
    _mf = ctypes.WinDLL("mf", use_last_error=True)
    _mfreadwrite = ctypes.WinDLL("mfreadwrite", use_last_error=True)
    _ole32 = ctypes.WinDLL("ole32", use_last_error=True)
else:  # pragma: no cover - the Linux import test
    _mfplat = None
    _mf = None
    _mfreadwrite = None
    _ole32 = None


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid(data1: int, data2: int, data3: int, tail: str) -> GUID:
    value = GUID()
    value.Data1 = data1
    value.Data2 = data2
    value.Data3 = data3
    for index, byte in enumerate(bytes.fromhex(tail)):
        value.Data4[index] = byte
    return value


MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE = _guid(0xC60AC5FE, 0x252A, 0x478F, "a0efbc8fa5f7cad3")
MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID = _guid(
    0x8AC3587A, 0x4AE7, 0x42D8, "99e00a6013eef90f"
)
MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK = _guid(
    0x58F0AAD8, 0x22BF, 0x4F8A, "bb3dd2c4978c6e2f"
)
MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME = _guid(0x60D0E559, 0x52F8, 0x4FA2, "bbceacdb34a8ec01")

MF_MT_MAJOR_TYPE = _guid(0x48EBA18E, 0xF8C9, 0x4687, "bf110a74c9f96a8f")
MF_MT_SUBTYPE = _guid(0xF7E34C9A, 0x42E8, 0x4714, "b74bcb29d72c35e5")
MF_MT_FRAME_SIZE = _guid(0x1652C33D, 0xD6B2, 0x4012, "b83472030849a37d")
MF_MT_FRAME_RATE = _guid(0xC459A2E8, 0x3D2C, 0x4E44, "b132fee5156c7bb0")
MF_MT_DEFAULT_STRIDE = _guid(0x644B4E48, 0x1E02, 0x4516, "b0ebc01ca9d49ac6")

MFMediaType_Video = _guid(0x73646976, 0x0000, 0x0010, "800000aa00389b71")
MFVideoFormat_RGB32 = _guid(0x00000016, 0x0000, 0x0010, "800000aa00389b71")

MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING = _guid(0xFB394F3D, 0xCCF1, 0x42EE, "bbb3f9b845d5681d")
MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING = _guid(
    0x0F81DA2C, 0xB537, 0x4672, "a8b2a681b17307a3"
)

_REASON_BY_CODE: Final[dict[int, str]] = {
    0x80070005: BLOCKED,  # E_ACCESSDENIED, which is also the camera privacy setting
    0x800700AA: BUSY,  # ERROR_BUSY, another app holds the device
    0x80070020: BUSY,  # ERROR_SHARING_VIOLATION
    0x80070490: NO_DEVICE,  # ELEMENT_NOT_FOUND
    0x80070002: NO_DEVICE,  # ERROR_FILE_NOT_FOUND
    0xC00DABE0: NO_DEVICE,  # MF_E_NO_CAPTURE_DEVICES_INSTALLED
    0xC00D3E82: BUSY,  # MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED
    0xC00D3E84: BUSY,  # MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED
    0xC00D3704: BUSY,  # MF_E_DEVICE_IN_USE
}

# --- COM plumbing -------------------------------------------------------------

_ReleaseProto = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
_GetUINT32Proto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(wintypes.UINT)
)
_GetUINT64Proto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_ulonglong)
)
_GetAllocatedStringProto = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.POINTER(GUID),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(wintypes.UINT),
)
_SetUINT32Proto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.UINT
)
_SetUINT64Proto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.c_ulonglong
)
_SetGUIDProto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(GUID)
)
_SetStringProto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.LPCWSTR
)
_GetMediaTypeProto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
)
_SetMediaTypeProto = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
)
_ReadSampleProto = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(ctypes.c_longlong),
    ctypes.POINTER(ctypes.c_void_p),
)
_ConvertProto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
_LockProto = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
)
_UnlockProto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)


def _declare() -> None:
    _mfplat.MFStartup.argtypes = [wintypes.ULONG, wintypes.DWORD]
    _mfplat.MFStartup.restype = ctypes.c_long
    _mfplat.MFShutdown.argtypes = []
    _mfplat.MFShutdown.restype = ctypes.c_long

    _mfplat.MFCreateAttributes.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.UINT]
    _mfplat.MFCreateAttributes.restype = ctypes.c_long

    _mfplat.MFCreateMediaType.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _mfplat.MFCreateMediaType.restype = ctypes.c_long

    _mf.MFCreateDeviceSource.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    _mf.MFCreateDeviceSource.restype = ctypes.c_long

    _mf.MFEnumDeviceSources.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ctypes.POINTER(wintypes.UINT),
    ]
    _mf.MFEnumDeviceSources.restype = ctypes.c_long

    _mfreadwrite.MFCreateSourceReaderFromMediaSource.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _mfreadwrite.MFCreateSourceReaderFromMediaSource.restype = ctypes.c_long

    _ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _ole32.CoInitializeEx.restype = ctypes.c_long
    _ole32.CoUninitialize.argtypes = []
    _ole32.CoUninitialize.restype = None
    _ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    _ole32.CoTaskMemFree.restype = None


if _WINDOWS:
    _declare()


def _invoke(pointer: int, index: int, prototype: object, *args: object) -> int:
    """Call ``vtable[index]`` on a COM interface with ``This`` prepended."""
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0]
    if not table:
        return -2147467261  # E_POINTER
    address = ctypes.cast(table, ctypes.POINTER(ctypes.c_void_p))[index]
    if not address:
        return -2147467261
    function = prototype(address)  # type: ignore[operator]
    return int(function(pointer, *args))


def _release(pointer: int | None) -> None:
    if pointer:
        _invoke(pointer, 2, _ReleaseProto)


def _status(code: int) -> str:
    return _REASON_BY_CODE.get(code & 0xFFFFFFFF, ERROR)


def _set_guid(interface: int, key: GUID, value: GUID) -> int:
    return _invoke(interface, 24, _SetGUIDProto, ctypes.byref(key), ctypes.byref(value))


def _set_uint32(interface: int, key: GUID, value: int) -> int:
    return _invoke(interface, 21, _SetUINT32Proto, ctypes.byref(key), value)


def _set_string(interface: int, key: GUID, value: str) -> int:
    return _invoke(interface, 25, _SetStringProto, ctypes.byref(key), value)


def _set_size(interface: int, key: GUID, high: int, low: int) -> int:
    """Pack two 32-bit values into the 64-bit attribute Media Foundation expects.

    ``MFSetAttributeSize`` is an inline function with no export, so the packing is done
    here and written with ``SetUINT64``: high half first, exactly as the inline body does.
    """
    packed = ((int(high) & 0xFFFFFFFF) << 32) | (int(low) & 0xFFFFFFFF)
    return _invoke(interface, 22, _SetUINT64Proto, ctypes.byref(key), packed)


def _get_uint32(interface: int, key: GUID) -> int | None:
    value = wintypes.UINT(0)
    if _invoke(interface, 7, _GetUINT32Proto, ctypes.byref(key), ctypes.byref(value)) != 0:
        return None
    return int(value.value)


def _get_allocated_string(interface: int, key: GUID) -> str:
    text = wintypes.LPWSTR()
    length = wintypes.UINT(0)
    code = _invoke(
        interface, 13, _GetAllocatedStringProto, ctypes.byref(key), ctypes.byref(text),
        ctypes.byref(length),
    )
    if code != 0 or not text.value:
        return ""
    value = str(text.value)
    if _ole32 is not None:
        _ole32.CoTaskMemFree(ctypes.cast(text, ctypes.c_void_p))
    return value


@dataclass(slots=True)
class Outcome:
    status: str = NO_DEVICE
    reason: str = ""
    code: int = 0
    device: str = ""
    width: int = 0
    height: int = 0
    bytes: int = 0
    millis: int = 0
    devices: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "hresult": f"0x{self.code & 0xFFFFFFFF:08X}" if self.code else "",
            "device": self.device,
            "width": self.width,
            "height": self.height,
            "bytes": self.bytes,
            "millis": self.millis,
            "devices": self.devices,
        }


def devices() -> list[tuple[str, str]]:
    """``(friendly name, symbolic link)`` for every capture device. Empty on refusal."""
    if not _WINDOWS:
        return []
    attributes = ctypes.c_void_p(0)
    if _mfplat.MFCreateAttributes(ctypes.byref(attributes), 2) != 0 or not attributes.value:
        return []

    found: list[tuple[str, str]] = []
    array = ctypes.POINTER(ctypes.c_void_p)()
    count = wintypes.UINT(0)
    try:
        if _set_guid(
            attributes.value,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        ) != 0:
            return []
        if _mf.MFEnumDeviceSources(attributes, ctypes.byref(array), ctypes.byref(count)) != 0:
            return []
        for index in range(int(count.value)):
            activate = int(array[index] or 0)
            if not activate:
                continue
            try:
                found.append(
                    (
                        _get_allocated_string(activate, MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME),
                        _get_allocated_string(
                            activate,
                            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                        ),
                    )
                )
            finally:
                _release(activate)
    finally:
        if array and _ole32 is not None:
            _ole32.CoTaskMemFree(ctypes.cast(array, ctypes.c_void_p))
        _release(attributes.value)
    return found


def _is_virtual(name: str) -> bool:
    folded = name.casefold()
    return any(fragment in folded for fragment in _VIRTUAL_NAMES)


def _current_format(reader: int) -> tuple[int, int, int] | None:
    """``(width, height, stride)`` of the type the reader settled on."""
    media = ctypes.c_void_p(0)
    if _invoke(reader, 6, _GetMediaTypeProto, FIRST_VIDEO_STREAM, ctypes.byref(media)) != 0:
        return None
    if not media.value:
        return None
    try:
        packed = ctypes.c_ulonglong(0)
        if (
            _invoke(
                media.value, 8, _GetUINT64Proto, ctypes.byref(MF_MT_FRAME_SIZE),
                ctypes.byref(packed),
            )
            != 0
        ):
            return None
        width = int(packed.value >> 32)
        height = int(packed.value & 0xFFFFFFFF)
        stride = _get_uint32(media.value, MF_MT_DEFAULT_STRIDE)
        if width <= 0 or height <= 0:
            return None
        # RGB32 is four bytes a pixel. The attribute is authoritative when the source
        # sets it, and the default is only a fallback for a source that omits it.
        return width, height, stride if stride else width * 4
    finally:
        _release(media.value)


def _read_sample(reader: int) -> bytes | None:
    """One sample's pixels, or None when the read window closed without a frame."""
    actual = wintypes.DWORD(0)
    flags = wintypes.DWORD(0)
    timestamp = ctypes.c_longlong(0)
    sample = ctypes.c_void_p(0)

    for _attempt in range(_READ_ATTEMPTS):
        code = _invoke(
            reader,
            9,
            _ReadSampleProto,
            FIRST_VIDEO_STREAM,
            0,
            ctypes.byref(actual),
            ctypes.byref(flags),
            ctypes.byref(timestamp),
            ctypes.byref(sample),
        )
        if code != 0:
            log.logger.debug("camera: ReadSample -> 0x%08X", code & 0xFFFFFFFF)
            return None
        if sample.value:
            break
        time.sleep(_READ_SLEEP)
    else:
        return None

    buffer = ctypes.c_void_p(0)
    try:
        if _invoke(sample.value, 41, _ConvertProto, ctypes.byref(buffer)) != 0:
            return None
        if not buffer.value:
            return None

        locked = ctypes.c_void_p(0)
        maximum = wintypes.DWORD(0)
        length = wintypes.DWORD(0)
        try:
            if (
                _invoke(
                    buffer.value,
                    3,
                    _LockProto,
                    ctypes.byref(locked),
                    ctypes.byref(maximum),
                    ctypes.byref(length),
                )
                != 0
            ):
                return None
            if not locked.value or int(length.value) < 16:
                return None
            return ctypes.string_at(locked.value, int(length.value))
        finally:
            if locked.value:
                _invoke(buffer.value, 4, _UnlockProto)
    finally:
        _release(buffer.value)
        _release(sample.value)


def _top_down(rows: bytes, width: int, height: int, stride: int) -> bytes:
    """Normalise a frame so row 0 is the visual top and the stride is positive."""
    row_bytes = width * 4
    if stride < 0:
        # Negative stride describes a buffer whose first row is the bottom of the image.
        # Flipping here is cheaper than teaching the encoder about it.
        step = -stride
        if len(rows) < step * height:
            return b""
        flipped = bytearray(step * height)
        for y in range(height):
            source_slice = rows[y * step : (y + 1) * step]
            flipped[(height - 1 - y) * step : (height - y) * step] = source_slice
        return bytes(flipped)
    if stride < row_bytes or len(rows) < stride * height:
        return b""
    return rows[: stride * height]


def grab(destination: Path) -> Outcome:
    """Open the first real camera, take one frame, encode it to ``destination``.

    Synchronous and unbounded: the caller owns the wall clock. Every failure is an
    ``Outcome`` with a status, never an exception, because a run with no camera is a
    normal run and the report has to say which kind of no-camera it was.
    """
    started = time.perf_counter()
    outcome = Outcome()

    if not _WINDOWS:
        outcome.reason = "not windows"
        return outcome

    # COM is per thread. The collector runs on a pool thread, so this is the first and
    # only place that knows it needs an apartment.
    initialised = _ole32.CoInitializeEx(None, 0x2)  # COINIT_APARTMENTTHREADED
    try:
        listed = devices()
        outcome.devices = [name for name, _link in listed if name]

        if not listed:
            outcome.status = NO_DEVICE
            outcome.reason = "no capture device installed"
            return outcome

        chosen: tuple[str, str] | None = None
        for name, link in listed:
            if link and not _is_virtual(name):
                chosen = (name, link)
                break
        if chosen is None:
            outcome.status = NO_DEVICE
            outcome.reason = "only virtual cameras installed"
            return outcome

        outcome.device = chosen[0]

        startup = int(_mfplat.MFStartup(MF_VERSION, MFSTARTUP_FULL))
        if startup != 0:
            outcome.status = ERROR
            outcome.code = startup
            outcome.reason = "mf startup refused"
            return outcome

        attributes = ctypes.c_void_p(0)
        config = ctypes.c_void_p(0)
        source = ctypes.c_void_p(0)
        reader = ctypes.c_void_p(0)
        media = ctypes.c_void_p(0)
        try:
            if _mfplat.MFCreateAttributes(ctypes.byref(attributes), 2) != 0:
                outcome.status = ERROR
                outcome.reason = "attribute store refused"
                return outcome
            _set_guid(
                attributes.value,
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
            )
            _set_string(
                attributes.value,
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                chosen[1],
            )

            code = int(_mf.MFCreateDeviceSource(attributes, ctypes.byref(source)))
            if code != 0 or not source.value:
                outcome.status = _status(code)
                outcome.code = code
                outcome.reason = "device source refused"
                return outcome

            # The reader's config attributes are what tell it to convert whatever the
            # device speaks into the RGB32 that is asked for. Without them a camera that
            # advertises only NV12 refuses the type and no frame ever arrives.
            #
            # Only the legacy converter is set. The advanced one is refused with
            # E_INVALIDARG by MFCreateSourceReaderFromMediaSource on this build whether
            # its value is written as a UINT32 or a GUID — measured against three devices
            # — and the legacy path does the same colour conversion at these resolutions.
            if _mfplat.MFCreateAttributes(ctypes.byref(config), 1) == 0:
                _set_uint32(config.value, MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, 1)

            code = int(
                _mfreadwrite.MFCreateSourceReaderFromMediaSource(
                    source, config if config.value else None, ctypes.byref(reader)
                )
            )
            if code != 0 or not reader.value:
                outcome.status = _status(code)
                outcome.code = code
                outcome.reason = "source reader refused"
                return outcome

            if _mfplat.MFCreateMediaType(ctypes.byref(media)) != 0:
                outcome.status = ERROR
                outcome.reason = "media type refused"
                return outcome
            _set_guid(media.value, MF_MT_MAJOR_TYPE, MFMediaType_Video)
            _set_guid(media.value, MF_MT_SUBTYPE, MFVideoFormat_RGB32)
            _set_size(media.value, MF_MT_FRAME_SIZE, _WANT_WIDTH, _WANT_HEIGHT)
            _set_size(media.value, MF_MT_FRAME_RATE, _WANT_FPS, 1)

            code = _invoke(
                reader.value, 7, _SetMediaTypeProto, FIRST_VIDEO_STREAM, None, media.value
            )
            if code != 0:
                outcome.status = _status(code)
                outcome.code = code
                outcome.reason = "rgb32 type refused"
                return outcome

            shape = _current_format(reader.value)
            if shape is None:
                outcome.status = ERROR
                outcome.reason = "negotiated format unreadable"
                return outcome
            width, height, stride = shape

            rows = _read_sample(reader.value)
            if rows is None:
                outcome.status = ERROR
                outcome.reason = "no frame inside the read window"
                return outcome

            normalised = _top_down(rows, width, height, stride)
            if not normalised:
                outcome.status = ERROR
                outcome.reason = "frame shorter than its own geometry"
                return outcome

            if not gdi.save_bytes(
                normalised, width, height, abs(stride), destination, "image/jpeg"
            ):
                outcome.status = ERROR
                outcome.reason = "encode failed"
                return outcome

            outcome.status = OK
            outcome.width = width
            outcome.height = height
            try:
                outcome.bytes = destination.stat().st_size
            except OSError:
                outcome.bytes = 0
            if outcome.bytes == 0:
                outcome.status = ERROR
                outcome.reason = "empty file"
            return outcome
        finally:
            _release(media.value)
            _release(reader.value)
            _release(source.value)
            _release(config.value)
            _release(attributes.value)
            _mfplat.MFShutdown()
            outcome.millis = round((time.perf_counter() - started) * 1000)
    finally:
        if initialised >= 0:
            _ole32.CoUninitialize()


__all__ = [
    "BLOCKED",
    "BUSY",
    "ERROR",
    "NO_DEVICE",
    "OK",
    "TIMEOUT",
    "Outcome",
    "devices",
    "grab",
]
