# sable-version

A `version.dll` that is a real proxy and also starts a launcher.

Windows resolves an import by looking in the directory of the importing executable before it looks
in `System32`, so a `version.dll` dropped beside a host that imports `version.dll` is the one the
host loads. This is that file: seventeen exports that answer with Microsoft's own code, and an
attach callback that starts `sable-launcher.exe` from its own directory.

```text
src/lib.rs          the DLL: 17 thunks, DllMain, the launcher start
version.def         the export list in true-forwarder shape (see "Not forwarders")
build.rs            --entry=DllMain, and why that is not the default
guest/recorder.rs   a launcher that writes down its own argv, for the acceptance check
```

Built artifact: **16 896 bytes**, against 30 000 for the system `version.dll`. Size is a signature;
a 250 KB proxy next to a host is the whole tell.

## Build

```text
cargo build --release        # from native/version-dll
```

Host toolchain is `stable-x86_64-pc-windows-gnu`. No MSVC, no mingw on `PATH`, no dependencies in
`Cargo.toml`. The profile is `opt-level="z"`, `lto`, `codegen-units=1`, `panic="abort"`, `strip`.

## What is proven statically, and how

```text
python tools/probes/dll_exports.py native/version-dll/target/release/version.dll \
    --expect C:\Windows\System32\version.dll
```

Reads the PE export directory without loading the file and compares the name set against the
system DLL. It also reads the entry point: our image starts with `jmp rel32` into the Rust
function, which is how the reader can tell a trampoline from the CRT startup that would reach
`DllMain` through a weak symbol.

Current result: `17 named exports`, `entry point rva 0x1360: jmp 0x184F`, `PASS every name matches
version.dll`, and two notes — `VerLanguageNameA` and `VerLanguageNameW` are forwarded to
`KERNEL32` by the system DLL and are thunks here.

## Not forwarders

A true forwarder has no code: the export entry is the string `MODULE.Function`, the loader resolves
it, and a caller reaches the system function at the system function's address. That needs an
absolute target, because a bare `version.dll.Name` resolves back to the proxy and recurses until
the stack runs out. GNU `ld` splits a `.def` line and a `.drectve` directive on `:`, so
`C:\Windows\System32\version.dll.Name` becomes fragments and the link fails with
`ld: cannot export C:: symbol not found`. `link.exe` accepts it.

So the proxy forwards in code instead: one thunk per name, each resolving the real export through
`LoadLibraryExW("version.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)` + `GetProcAddress`, cached in a
`static`, called through `extern "system" fn(u64 × 8) -> u64`. On x64 that is byte-exact for
everything in this DLL: every one of the seventeen takes integers and pointers and returns an
integer, so the arguments arrive in the right registers and the return comes back in `RAX`. It is
also the reason there are no seventeen prototypes — `GetFileVersionInfoByHandle` is not in the
public SDK and its prototype would have been a guess.

`version.def` is kept in true-forwarder shape for a toolchain that accepts one. It is documented,
not consumed.

## Not proven statically

Everything about the attach callback, the launcher command line and the carrier flag needs the DLL
loaded into a live process. That is `tools/probes/version_dll_check.py`, and it runs on `VUURTH`
or inside `SABLE-CLEAN`, never on the build machine: it compiles `guest/recorder.rs`, loads the
DLL, and looks for the launcher the DLL started.

Until that run exists, the claim is "the entry point is a jump into the attach function and all
seventeen exports match", not "the sideload works".
