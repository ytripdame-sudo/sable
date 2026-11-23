# sable-aes

The two formats this project depends on, in Rust, byte-compatible with the Python tree.

```text
agent/util.py::seal_zip        <->  src/winzip.rs
core/seal.py + agent/loader.py <->  src/container.rs
```

That is the whole scope. Nothing here touches collection, delivery or the UI, and it is
not a library the agent imports yet — it is the first piece of the native port, proven
against real files before anything else is moved over.

## Why these two

Every other module is ordinary Python: readable, replaceable, and worth nothing to an
attacker who can already read the process memory. These two are the ones that have to
agree across a language boundary, and the ones where a single wrong byte order turns a
working artifact into a file nobody can open. If they agree, the port has a foundation.
If they do not, nothing built on top of them matters.

## Commands

```text
sable-aes seal <source.zip> <sealed.zip> <password>
sable-aes open <sealed.zip> <folder> <password>
sable-aes image <artifact.exe> <payload.zip>
sable-aes trailer <artifact.exe>
sable-aes seal-blob <payload.zip> <blob.bin> <seal key>
sable-aes version
```

Exit 0 on success, 2 on any refusal, 1 on bad usage. Every refusal prints why. There is
no interactive mode, because both callers are scripts.

## Formats

### WinZip AES-256, AE-2

```text
member = salt(16) || verifier(2) || AES-CTR(deflate(plaintext)) || HMAC-SHA1(...)[..10]
```

- Key material: `PBKDF2-HMAC-SHA1(password, salt, 1000, 66)` → 32-byte AES key, 32-byte
  authentication key, 2-byte verifier.
- Counter: 16 bytes, **little-endian**, starting at 1 and incrementing across the whole
  member. This is WinZip's counter, not NIST CTR, which is why `src/winzip.rs` carries
  its own instead of using a standard mode.
- Integrity: HMAC-SHA1 over the **ciphertext**, truncated to 10 bytes. The CRC field is
  zero because AE-2 uses the code instead.
- Extra field: `0x9901`, size 7, version 2, vendor `AE`, strength 3 (AES-256), inner
  method 8 (deflate).

The two mistakes this format invites, both of which were made and caught here:

1. Hashing the plaintext instead of the ciphertext. Verification then rejects every
   archive that is actually fine.
2. Big-endian counters. Everything opens as noise and nothing authenticates.

### SABL container

```text
[ launcher ][ ballast ][ sealed blob ][ trailer 868 ][ footer 12 ]
```

- Footer: `SBLT` + `u32` little-endian offset of the sealed blob.
- Trailer: `SBLK` + 64-byte key slot + 800-byte mutex slot, NUL-terminated and padded.
- Blob: `salt(16) || nonce(12) || ciphertext || tag(16)`, AES-256-GCM, keyed on
  `PBKDF2-HMAC-SHA256(seal key, salt, 200_000)`.
- Limits: a sealed blob above 512 MiB is a corrupt header, not a large build.

`write_image` exists so a test can assemble a container without Python. It is not a
replacement for `core/forge.py`, which also owns the ballast policy and the script
output mode.

## Build

```bash
cargo build --release     # sable-aes.exe, about 540 KB
cargo test --release      # 8 tests: 3 unit, 5 round trip
cargo clippy --all-targets --release
cargo fmt
```

The toolchain used is `stable-x86_64-pc-windows-gnu`, installed with rustup. The GNU
target links without Visual Studio Build Tools, which is the reason it was chosen: this
machine has no MSVC installation and the crate has no C dependencies, so nothing else is
needed. `flate2` runs on `miniz_oxide`, so the build is pure Rust apart from the linker.

## Known limits

- **No zip64.** The reader refuses an archive with zip64 markers rather than guessing.
  The writer never produces one; member counts are capped at 65535, sizes at 4 GiB.
- **One member in memory at a time.** Sealing reads a member, deflates it, encrypts it,
  writes it, then drops it. That is bounded by the largest file in the tree, not by the
  archive, but a tree with a 700 MB member will use 700 MB of RAM twice over.
- **AE-1 is not read.** Only AE-2 exists on this side and only AE-2 is produced.
- **No streaming write.** The sealed member is assembled in a `Vec` before it is written
  because the HMAC tag goes last and the sizes go in the header. A streaming writer would
  need a seek-back over the header; the current shape is simpler and the peak is one
  member.

## Proof

`tools/probes/rust_interop.py` builds a fixture tree, seals it with both implementations,
opens it with both, tests the result with 7-Zip under the right and wrong keys, and then
forges a real artifact with `core/forge.py` and reads it back through `sable-aes image`.

```text
21/21 passed
```

Measured on a 125.9 MB archive, 120 members, same machine:

```text
python seal    8.04 s
rust   seal    4.66 s    1.7x
rust   open    0.75 s
7z t           0.2 s    passes with the key, fails without
```

Members compared by SHA-256 after the round trip: identical.
