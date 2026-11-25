# LIMITS

What this build cannot do, what it does at a cost, and what the fix would be. Written before
the loader work rather than after it, because a limits page written afterwards is a defence of
decisions already made.

Every number here was measured on this bench. Where something is unverified it says so.

---

## 1. The artifact is 98.33% interpreter

| measurement | bytes |
|---|---|
| sealed payload | 173,207 |
| one-file artifact | 10,420,156 |
| one-directory tree | 22,846,028 (79 files) |
| C loader embedding CPython, measured | 20,754,960 |

The stub is 98.33% of the one-file artifact. That is not a bug to optimise, it is what
"Python payload behind a frozen launcher" costs.

**Cost.** A 10 MB unsigned installer is unremarkable; a 10 MB artifact that also writes to
`%TEMP%` at launch is the shape a scanner scores. Ballast is the lever used instead of
compression — a bigger file is more normal, a smaller one is the odd artifact.

**Fix.** Reflective PE mapping of `python312.dll` and every `.pyd`, so the interpreter comes
out of the resource section instead of `_MEIPASS`. That is 2.3a, and the measured alternative
is worse: the C loader that embeds CPython has to carry the tree the one-file build already
carries, and it measured 20,754,960 bytes against 10,420,156. Beating one-file is a different
project with a different budget.

---

## 2. One plaintext file exists on disk during the run

`agent.loader.prepare` decrypts the archive to `payload.zip` in a `mkdtemp` under `%TEMP%` and
`cleanup` removes the directory. `_load_entry` mounts it with `PathFinder.find_spec("agent",
[str(path)])`, and a path is a file.

**Verified:** the file is the plaintext archive, it sits under the platform temp root, it is
gone after cleanup, and nothing is ever written beside the artifact. Both are contracts
(`test_the_loader_puts_the_decrypted_payload_in_temp_and_takes_it_back`,
`test_the_loader_writes_nothing_beside_the_artifact`).

**Cost.** A tool watching `%TEMP%` for a zip appearing and disappearing sees this. It is
shorter-lived and less obvious than an exe drop, and it is the same category.

**Fix.** A loader that mounts the package from memory over an in-memory archive, replacing
zipimport. Same unit as §1, same deferral, same measurement.

---

## 3. Nothing is signed

**Cost.** SmartScreen on a first-run artifact with no reputation; Defender's cloud path scores
an unsigned binary higher; every "Unknown publisher" dialog is a place the run can stop. This is
the single largest conversion loss in the whole chain.

**Fix.** An EV or OV code-signing certificate with a hardware token. It costs money and cannot
be produced at the bench. Blocked, not deferred.

---

## 4. The double extension is a policy, not a property

`Invoice.pdf.exe` reads as `Invoice.pdf` only while `HideExtensionsForNetUser` is on. It is on
by default and the artifact cannot enforce it.

**Cost.** On a well-managed host the full name is visible and the artifact reads as exactly
what it is. The right-to-left override form is not produced at all: Explorer has normalised the
display of U+202E since Windows 10 1809, so it buys a mangled filename and no illusion.

---

## 5. ClickFix needs the clipboard and a secure context

`navigator.clipboard` requires a secure context, so a page opened from disk or served over plain
HTTP has no clipboard API. The handler falls back to `execCommand('copy')`, which works — but
the visible "Copied" state is now the only feedback, and a browser that refuses both leaves the
user pasting the wrong string.

**Cost.** Conversion depends on the user's hand, not the artifact. Nothing in the page can
verify that the right command was pasted.

---

## 6. A carrier image is transport, not a launcher

`png` and `jpg` output weld the same tail past the image's own terminator: the footer is
still the last eight bytes, the trailer the 864 before it, and the offset comes from the
head's length. Nothing about the arithmetic changes. What changes is that **an image cannot
be started** — so this is not a delivery shape, it is a transport. It only works when a
launcher is *already* on the machine, and that launcher is pointed at the file with
`--carrier`.

The reference set agrees, and it is the reason the mode exists: the loader is described as
"just a binary which is loading and executing shell code from an image file", with the note
that once the image is deleted after the shell code has come out of it, there is nothing left
to point at.

**Cost — the container is no longer the picture.** Any tool that compares a file's size to
its own terminator sees the tail immediately. `carrier_size` refuses to build on a file that
already has one for exactly this reason, so a build of a build cannot happen; but the output
is a picture whose byte length no longer matches its `IEND` chunk. That is only invisible to
a viewer, not to a scanner.

**Cost — carrier validation is structural, not decodability.** The walk proves the format
terminates where the file ends. It does not prove a decoder will render the head, and it
costs one full read of the file to walk (ceiling 64 MiB). A carrier that is a renamed
executable is refused because the signature is what is dispatched on, never the extension.

**Cost — the carrier's own size is not free steganography.** Ballast still applies and still
moves the offset, but every byte of ballast is a byte of file that grows visibly. A picture
that arrives at 20 MB and leaves at 20.2 MB is a size that changed.

**Cost — deletion is conditional.** `cleanup` removes the carrier only when
`util.pending_queue()` is empty. A parked archive brings the same image back on a task and
needs the container it was pointed at, so a failed delivery leaves the picture on disk.

---

## 7. The self-extractor is a `.cmd`, not a PE

`sfx_bundle` emits a batch self-extractor: base64 body behind `exit /b`, `certutil` to decode,
`tar` to expand. It needs no external tooling and it works.

**Cost.** The archive and the extracted payload both land in `%TEMP%`, and the stub is a script
with a `.cmd` extension — the least plausible shape of the nine. A PE stub with the archive
appended needs a compiled extractor and ships with the loader.

---

## 8. ABE is three rungs, and only two of them are shipped

App-bound encryption has three ways in, and each has a precondition, a cost and a trace. The
order below is the order a run tries them: cheapest first, measured in what the target has to
give up.

| rung | needs | leaves | shipped |
|---|---|---|---|
| `user` — DPAPI in process | nothing beyond the user's profile | nothing at all | yes |
| `hollow` — a browser process with its image replaced | the browser installed; code that calls the elevation service from inside it | a crash on the target if the hollow goes wrong, and a process image that no longer matches its file | **no** |
| `system` — a one-shot scheduled task | the right to register a task | a **task-creation event** in the log, every run | yes |

**`user` is first because it costs nothing.** On Brave there is no app-bound wrap at all, and on
Chrome before 127 the blob is a plain user DPAPI blob, so the cheapest rung produces the key and
the run never touches the task scheduler or a browser. A run that reports `app_bound: false` on
one of those is a bug; a run that reports `path: "system"` is a current Chrome.

**The hollow payload is deliberately not shipped.** It is the one artifact that has to be
rebuilt whenever the browser's signature check moves, it is the single binary the reference set
names as "highly detected", and a RunPE that has never been run once on this bench would ship as
a claim rather than a build. The rung is in the ordering with a defined contract and reports why
it was skipped, so a payload tested elsewhere drops into a slot that already has tests.

**Each Chromium fork wraps with its own key.** Brave, Edge and Thorium are separate targets
with separate binaries; a resolver that works on Chrome is a resolver for Chrome.

**Chrome version drift moves the ground under the hollow and the task path.** The ground truth is
the binary's own symbols and the version, not a constant in this repo.

**What is verified:** the `system` rung end to end on this bench, through a real artifact, with
the task registered, re-executed, the hex read back, the key reduced to 32 bytes and the task
deleted — `tools/probes/abe_check.py`. The `user` rung and the ordering are pinned by
`tests/test_abe.py` with every OS call stubbed.

**Not verified here:** which rung produces the key on a host with a current Chrome installed.
That needs a live browser and a real `app_bound_encrypted_key`, and it is the one acceptance
line in 2.3b that this bench cannot run.

---

## 9. Persistence is per-user and visible in one place

The installer writes `%LOCALAPPDATA%\Programs\<id>\`, one `Run` value, and one HKCU
Add/Remove Programs record with `EstimatedSize`. No admin, no UAC, no service.

**Cost.** A per-user install is visible in Settings > Apps, which is where a user looks when
something starts at login. The record is deliberate: a missing record is more suspicious than a
present one, and the uninstaller has to work.

---

## 10. What is claimed and not verified

- The three ABE rungs on a live Chrome install (2.3b) — the acceptance test is unrun.
- The carrier mode (2.3d) has never carried a real payload into a host. It is proven against
  `SABLE-CLEAN` on the build machine's clock and nowhere else.
- The sideload's attach path (2.3e) — the export set matches the system `version.dll` and the
  entry point is a jump into the attach function, both read statically. That the launcher actually
  starts is `version_dll_check.py`, and it is unwritten into the record until it runs on a guest.
- Delivery on a host that has never seen the image. Everything is proven against
  `SABLE-CLEAN`; a clean commercial machine with Defender in cloud mode is a different
  measurement.
- The three cookie endpoints. `cookies.validate` has never made a request — every call in the
  tests is stubbed. Whether `user_session` against `api.github.com/user` still answers 200 for a
  live session, and 401 for a dead one, is a fact about three vendors' behaviour in the field.
  `tools/probes/cookies_check.py` checks the premise from a guest (a garbage value must be
  refused); it is written and has not been run.

---

## 11. What is verified, and how

| claim | proof |
|---|---|
| the container survives a rebuild | `sable_launcher.py` **72/72**, both shapes |
| a picture opens a payload on a launcher that carries nothing | `sable_launcher.py` carrier boot, `--carrier` on the bare freeze |
| the carrier arithmetic is the exe arithmetic | `test_carrier.py`, same `expected_offset`, footer, trailer and decrypt |
| a thumbnail is not mistaken for the end of a JPEG | `test_carrier.py`, nested `APP1` fixture |
| the payload that comes out is the payload that went in | container contracts, byte identity |
| two builds from one freeze differ | nonce contract, plus the probe's re-stamp check |
| a dead cookie is told apart from an unreachable check | `session_status.json` contracts, three verdicts |
| a burst is spaced | pacing contracts, exact sequence with injected randomness |
| nothing lands beside the artifact | `test_the_loader_writes_nothing_beside_the_artifact` |
| the SYSTEM unwrap works end to end on a real artifact | `abe_check.py`, task registered, hex read back, key reduced, task deleted |
| the rungs are ordered by cost and each reports why it failed | `test_abe.py`, every OS call stubbed |
| the sideload exports exactly what the host imports, no more | `dll_exports.py --expect C:\Windows\System32\version.dll`, 17/17 |
| the sideload's entry point is the attach function | `dll_exports.py`, entry is `jmp rel32` into `.text`, not the CRT startup |
| a row that expired is dead without spending a request | `test_cookies.py`, the free half |
| only a 401 is a death | `test_cookies.py`, every other status parameterised |
| the same credential is asked once | `test_cookies.py`, two profiles, one request |
| the verdict record holds no cookie value | `test_cookies.py`, the status document read back as text |
| not asked is not the same as unknown | `test_cookies.py`, cap and deadline leave rows unmarked |

Gate at this commit: **658 passed**, ruff clean, compileall 0, `sable_forge` 60/60,
`sable_validate` 71/71, `sable_launcher` 72/72 on the one-file shape, `abe_check` clean,
`dll_exports` 17/17 against the system `version.dll`.

**The one-directory launcher probe was not run for this commit.** Every launcher probe boots a
frozen artifact and executes the payload; that is a live run, and live runs now belong to
`VUURTH` and `SABLE-CLEAN` rather than to the build machine. The one-file result above was
recorded before that boundary and is a measurement, not a claim about the one-directory shape.
Both shapes get re-proven on the laptop in the same pass as the next live run.

---

## 12. The sideload is a proxy, not a forwarder

`native/version-dll` builds to 16 896 bytes against 30 000 for the system `version.dll`, exports
the same seventeen names and nothing else, and answers each call out of `System32`.

**What is missing.** A true forwarder has no code at all: the export entry is the string
`MODULE.Function`, the loader resolves it, and a caller reaches Microsoft's function at
Microsoft's address. That form needs an absolute target — a bare `version.dll.Name` resolves back
to the proxy and recurses until the stack runs out — and GNU `ld` splits both a `.def` line and a
`.drectve` directive on `:`, so `C:\Windows\System32\version.dll.Name` becomes fragments and the
link dies with `ld: cannot export C:: symbol not found`. `link.exe` accepts it. This bench has
`ld`.

**What that costs.** The function a caller reaches is our thunk, not Microsoft's code. The answer
is identical because the thunk calls the real thing, but a checker that compares an export's RVA
against the system DLL's module range sees something the true-forwarder form would not show.

**What it does not cost.** The size, the name set, the import table and the entry point. A
250 KB proxy is a signature; 16 896 bytes with seventeen familiar names and a jump for an entry
point is not.
