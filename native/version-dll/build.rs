//! Linker arguments for the proxy DLL.
//!
//! **The export list is Rust's, not this file's.** On `windows-gnu`, `rustc` builds the export
//! table from the crate's `#[no_mangle]` items; that is where the seventeen exports come from.
//! `version.def` beside this file documents the list in the shape a true-forwarder proxy would
//! use, and is not consumed by GNU `ld`: `ld` splits a forwarder line on `:` and an absolute
//! target (`C:\Windows\System32\version.dll.Name`) becomes fragments
//! (`ld: cannot export C:: symbol not found`). The portable forwarding lives in `src/lib.rs`,
//! one thunk per name.
//!
//! **Two arguments, and both are about the entry point.**
//!
//! `--entry=DllMain` names the entry point explicitly. Without it, `ld` picks `_DllMainCRTStartup`
//! out of `dllcrt2.o`, and that function reaches `DllMain` through a *weak* reference — build the
//! DLL with `DllMain` deleted and it still links, with the attach callback silently never
//! running. That failure mode is invisible until a host loads the DLL and nothing happens, so
//! the entry point is named here and `DllMain` is defined in `global_asm!` rather than as a
//! `#[no_mangle]` item: a Rust item would land in the export table as an eighteenth export, and
//! the real `version.dll` has seventeen. `--exclude-symbols` does not help — it suppresses only
//! symbols the linker *auto*-exports, and this one is listed explicitly.
//!
//! Skipping `_DllMainCRTStartup` also skips what it exists to do: TLS callbacks, `atexit` lists,
//! and CRT initialisers. This crate is `no_std`, has no statics with destructors and no
//! constructors, so there is nothing for it to initialise, and the loader's `(hinstDLL, reason,
//! reserved)` arguments reach `DllMain` exactly as `_DllMainCRTStartup` would have forwarded
//! them.

fn main() {
    println!("cargo:rustc-link-arg=-Wl,--entry,DllMain");
    println!("cargo:rerun-if-changed=build.rs");
}
