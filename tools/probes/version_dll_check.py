"""Acceptance check for `native/version-dll`. GUEST ONLY — this loads a DLL into its own process.

Three things are being proven, and each one is the sort of thing that looks fine in a listing and
is dead in practice:

1. **The loader runs the attach callback.** The DLL builds its export table from `#[no_mangle]`
   items and defines `DllMain` in `global_asm!` with `--entry=DllMain`. If that wiring is wrong,
   every export still resolves and the launcher never starts. So the check looks for the
   launcher, not for the DLL.
2. **Every export resolves and answers.** A proxy that is missing a name breaks its host; a proxy
   whose thunks point at the wrong address answers garbage. `GetProcAddress` on all seventeen
   names proves resolution, and `VerLanguageNameW` is called through our module *and* through the
   system copy and the two answers are compared. It is the one export here that takes no
   structure and returns a short string, so it can be called from here without building a
   version resource first.
3. **The carrier flag reaches the launcher.** `--carrier <picture>` is how a picture in the same
   directory gets welded onto the launch. The recorder writes its own argv, so the argument is
   read out of the launcher's own process rather than inferred.

**Where this runs.** On `VUURTH` or inside `SABLE-CLEAN`, never on the build machine. It compiles
a small recorder with `rustc` and then executes it by loading the DLL: that is a live run, and
live runs belong to the guests.

Usage, from the repo root, on a guest:

    python tools/probes/version_dll_check.py --rustc C:\\path\\to\\rustc.exe
    python tools/probes/version_dll_check.py --dll native/version-dll/target/release/version.dll

Exit code 0 means every check passed. Anything else prints which one failed.
"""

from __future__ import annotations

import argparse
import ctypes
import shutil
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DLL = REPO_ROOT / "native" / "version-dll" / "target" / "release" / "version.dll"
RECORDER = REPO_ROOT / "native" / "version-dll" / "guest" / "recorder.rs"
SYSTEM_VERSION = Path(r"C:\Windows\System32\version.dll")

# The seventeen exports `C:\Windows\System32\version.dll` has, as read by `dll_exports.py`. Hard
# coded here on purpose: a check that derives its expectations from the artifact under test agrees
# with it by construction.
EXPORTS = (
    "GetFileVersionInfoA",
    "GetFileVersionInfoW",
    "GetFileVersionInfoByHandle",
    "GetFileVersionInfoExA",
    "GetFileVersionInfoExW",
    "GetFileVersionInfoSizeA",
    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoSizeExA",
    "GetFileVersionInfoSizeExW",
    "VerFindFileA",
    "VerFindFileW",
    "VerInstallFileA",
    "VerInstallFileW",
    "VerLanguageNameA",
    "VerLanguageNameW",
    "VerQueryValueA",
    "VerQueryValueW",
)

LOAD_WITH_ALTERED_SEARCH_PATH = 0x0000_0008
LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x0000_0100
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x0000_0800

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
kernel32.LoadLibraryExW.restype = wintypes.HMODULE
kernel32.GetProcAddress.argtypes = (wintypes.HMODULE, wintypes.LPCSTR)
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.FreeLibrary.argtypes = (wintypes.HMODULE,)
kernel32.FreeLibrary.restype = wintypes.BOOL


def load(path: Path, flags: int) -> int:
    handle = kernel32.LoadLibraryExW(str(path), None, flags)
    if not handle:
        raise OSError(ctypes.get_last_error(), f"LoadLibraryExW refused {path}")
    return handle


def language_name(handle: int, lang: int, buffer: ctypes.Array) -> str:
    """Call `VerLanguageNameA` through the given module and return what it wrote."""
    address = kernel32.GetProcAddress(handle, b"VerLanguageNameA")
    if not address:
        raise RuntimeError("VerLanguageNameA did not resolve")
    call = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, ctypes.c_char_p, wintypes.DWORD)(
        address
    )
    written = call(lang, ctypes.cast(buffer, ctypes.c_char_p), len(buffer))
    if written == 0:
        raise RuntimeError(f"VerLanguageNameA({lang:#x}) returned 0")
    return buffer.value.decode("ascii", "replace")


def wait_for_record(path: Path, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            if text.strip():
                return text
        time.sleep(0.1)
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, default=DEFAULT_DLL)
    parser.add_argument("--rustc", default="rustc", help="rustc that can build the recorder")
    parser.add_argument("--keep", action="store_true", help="leave the workspace in place")
    options = parser.parse_args(argv)

    if not options.dll.is_file():
        print(f"FAIL  no DLL at {options.dll}")
        return 2

    workspace = Path(tempfile.mkdtemp(prefix="sable-sideload-"))
    try:
        proxy = workspace / "version.dll"
        shutil.copy2(options.dll, proxy)
        launcher = workspace / "sable-launcher.exe"

        print(f"building the recorder with {options.rustc}")
        built = subprocess.run(
            [options.rustc, "-O", "-o", str(launcher), str(RECORDER)],
            capture_output=True,
            text=True,
        )
        if built.returncode != 0:
            print("FAIL  the recorder did not build")
            print(built.stderr.strip()[:2000])
            return 2

        failures: list[str] = []

        handle = load(proxy, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_WITH_ALTERED_SEARCH_PATH)
        print(f"loaded   {proxy} at 0x{handle:X}")

        # 1 - the attach callback ran and started the launcher.
        recorded = wait_for_record(workspace / "launcher.txt", timeout=10.0)
        if recorded is None:
            failures.append("the launcher never started: DllMain did not run, or found nothing")
        else:
            lines = recorded.splitlines()
            print(f"started  {lines[0] if lines else '(no argv)'}")
            if lines and Path(lines[0]).suffix.lower() != ".exe":
                failures.append(f"argv[0] is not the launcher: {lines[0]!r}")
            if any("--carrier" in line for line in lines):
                failures.append("--carrier was passed with no picture in the directory")

        # 2 - every export resolves.
        unresolved = [
            name for name in EXPORTS if not kernel32.GetProcAddress(handle, name.encode("ascii"))
        ]
        if unresolved:
            failures.append(f"unresolved exports: {', '.join(unresolved)}")
        else:
            print(f"resolved {len(EXPORTS)} exports")

        # 3 - a call through the proxy gives the same answer as the system DLL.
        ours = ctypes.create_string_buffer(128)
        theirs = ctypes.create_string_buffer(128)
        system = load(SYSTEM_VERSION, LOAD_LIBRARY_SEARCH_SYSTEM32)
        for lang in (0x0409, 0x0407, 0x0411):
            mine = language_name(handle, lang, ours)
            real = language_name(system, lang, theirs)
            if mine != real:
                failures.append(f"VerLanguageNameA({lang:#06x}): {mine!r} here, {real!r} in System32")
            else:
                print(f"answered {lang:#06x} -> {mine}")

        kernel32.FreeLibrary(handle)

        # 4 - the carrier argument, with a picture in the directory this time.
        carrier = workspace / "sable.png"
        carrier.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
        (workspace / "launcher.txt").unlink(missing_ok=True)
        handle = load(proxy, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_WITH_ALTERED_SEARCH_PATH)
        recorded = wait_for_record(workspace / "launcher.txt", timeout=10.0)
        if recorded is None:
            failures.append("the launcher did not start on the carrier pass")
        else:
            lines = recorded.splitlines()
            joined = " ".join(lines)
            if "--carrier" not in joined:
                failures.append(f"no --carrier in the command line: {joined!r}")
            elif str(carrier) not in joined:
                failures.append(f"the carrier path is wrong: {joined!r}")
            else:
                print(f"carrier  {joined}")
        kernel32.FreeLibrary(handle)

        if failures:
            print("\nFAIL")
            for failure in failures:
                print(f"  {failure}")
            return 1
        print("\nPASS  attach ran, 17 exports resolved, one call matches System32, carrier passed")
        return 0
    finally:
        # The recorder sleeps for six seconds; nothing here waits for it, and a leftover process
        # would hold the workspace open on the next run.
        subprocess.run(
            ["taskkill", "/F", "/IM", "sable-launcher.exe"],
            capture_output=True,
            text=True,
        )
        if options.keep:
            print(f"workspace kept at {workspace}")
        else:
            time.sleep(1.0)
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
