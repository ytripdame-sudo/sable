# tools/probes

The standalone harnesses. Every proof in `DECISIONS.md` and `HANDOFF.md` that is not a
`pytest` contract lives here, and until v1 closed they lived one directory above the
repository, which meant a disk failure would have taken every measurement this project
ever made.

They are not shipping source and they are not in `MANIFEST.txt`. `tools/` is build
machinery for the same reason `native/` is: nothing here is imported by `agent/`, `core/`
or `app/`, and `tests/test_imports.py` only enforces the package boundaries on those three.

## What is here

| Kind | Names | What it proves |
|---|---|---|
| Forge and container | `sable_forge.py`, `sable_validate.py`, `sable_launcher.py` | payload, trailer, seal, refusals, and a frozen launcher booting real artifacts |
| Sources | `sable_gecko.py`, `sable_bundle.py`, `sable_sessions.py` | both gecko layouts, the profile folder bundle, the token stores |
| UI | `sable_ui.py`, `sable_window.py`, `widget_shot.py`, `gui_audit.py` | widgets, rail, worker thread, the whole window, a screenshot |
| Disguise | `disguise_check.py`, `pecheck.py`, `read_artifact.py` | resources written and read back, PE shape, artifact contents |
| Entry path | `abe_check.py`, `runtime_build.py`, `runner.py`, `invoke.py` | app-bound unwrap, the runtime image, elevated runs |
| Rust | `rust_interop.py` | the 21 cross-language checks against `native/aes` |
| Live desk | `live_*.py`, `verify_vuurth.py`, `roblox_*.py`, `session_probe.py` | runs against a real host, real profiles and the real guest |
| Guest and host | `laptop_*.ps1`, `guest_*.ps1`, `host_probe.py` | Hyper-V setup, snapshot, seed, capture, teardown |
| Fixtures | `sable_fixture.py`, `make_answer_iso.py`, `pack_src.py`, `mirror_build.py` | synthetic trees and images, so a probe never needs the real ones |

## Running one

From `sable/`:

```powershell
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'
$env:PYTHONDONTWRITEBYTECODE='1'
$env:QT_QPA_PLATFORM='offscreen'      # only for the UI probes
& C:\Users\Kuzenee\AppData\Local\Temp\opencode\py312\python.exe tools\probes\sable_forge.py
```

Most print `n/n passed` and exit 0. A few need the launcher to exist first
(`tools/dist/sable-launcher.exe`, built from `tools/sable-launcher.spec`); they skip or
refuse cleanly when it does not.

## Two rules that keep this folder honest

- **Output stays out.** Anything a probe writes goes to `out/` or `_out/` next to where the
  probe expects it, never committed. The repository ignores `build/`, `dist/`, `*.exe`,
  `*.pyz`, `*.part` and `*.log` already.
- **Lint is off here, syntax is not.** `pyproject.toml` excludes `tools/probes` from
  `ruff`: these were written against a live desk under time pressure, and rewriting them
  to a style guide would be editing evidence. `compileall` still covers the folder, so a
  probe that stops parsing is still caught at the gate.

## What did not move

`_harness/` still holds `out/`, `_out/`, `received/` and `_iso/` — 6.2 GB of artifacts,
captures and installer images. Those are build output. They stay where they are.
