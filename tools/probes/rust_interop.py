"""Prove the Rust crate and the Python tree agree on both formats.

Three claims, each one a real file crossing the boundary:

1. A zip sealed by Rust opens with the right key, fails with the wrong one, and passes
   `7z t` — the third-party reader that decides whether a real user can open it.
2. A zip sealed by Python (`agent.util.seal_zip`) opens in Rust, member for member.
3. A container sealed by Python (`core.seal`) opens in Rust, and a container sealed by
   Rust opens in Python (`agent.loader._open_sealed`).

Run from anywhere:

    python tools/probes/rust_interop.py
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555")
SABLE = ROOT / "sable"
BINARY = SABLE / "native" / "aes" / "target" / "release" / "sable-aes.exe"
SEVEN = shutil.which("7z")

sys.path.insert(0, str(SABLE))

from agent import loader, util  # noqa: E402
from core import seal  # noqa: E402

PASSWORD = "interop-key-4f2a"
RESULTS: list[tuple[bool, str, str]] = []


def check(passed: bool, label: str, detail: str = "") -> None:
    RESULTS.append((passed, label, detail))
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"   {detail}" if detail else ""))


def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(list(arguments), capture_output=True, timeout=600)


def tree(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            found[path.relative_to(root).as_posix()] = digest
    return found


def fixture(root: Path) -> Path:
    """A source tree with the shapes that break readers: nesting, a big member, an
    empty member, and a name that is not ASCII."""
    (root / "docs" / "inner").mkdir(parents=True)
    (root / "docs" / "readme.txt").write_text("sable interop fixture\n" * 40, encoding="utf-8")
    (root / "docs" / "inner" / "notes.txt").write_text("nested member\n", encoding="utf-8")
    (root / "empty.bin").write_bytes(b"")
    (root / "blob.bin").write_bytes(bytes(range(256)) * 8192)
    (root / "caf\u00e9.txt").write_text("non-ascii name\n", encoding="utf-8")

    source = root.parent / "fixture.zip"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(root).as_posix())
    return source


def main() -> int:
    if not BINARY.is_file():
        print(f"missing {BINARY}; build it first")
        return 1

    work = Path(tempfile.mkdtemp(prefix="sable-interop-"))
    try:
        root = work / "tree"
        source = fixture(root)
        check(source.stat().st_size > 0, "fixture written", f"{source.stat().st_size} bytes")

        # --- 1. Rust seals, Rust opens, 7z agrees ---------------------------
        sealed_rust = work / "rust-sealed.zip"
        done = run(str(BINARY), "seal", str(source), str(sealed_rust), PASSWORD)
        check(done.returncode == 0, "rust seal exits 0", done.stderr.decode()[:120].strip())
        check(sealed_rust.is_file() and sealed_rust.stat().st_size > 0, "rust seal wrote a file")

        opened = work / "rust-out"
        done = run(str(BINARY), "open", str(sealed_rust), str(opened), PASSWORD)
        check(done.returncode == 0, "rust opens its own seal", done.stderr.decode()[:160].strip())
        check(tree(opened) == tree(root), "rust seal round-trips every member")

        wrong = work / "rust-out-wrong"
        done = run(str(BINARY), "open", str(sealed_rust), str(wrong), PASSWORD + "x")
        check(done.returncode == 2, "rust refuses the wrong key")

        if SEVEN:
            with_password = run(SEVEN, "t", f"-p{PASSWORD}", str(sealed_rust))
            check(
                with_password.returncode == 0,
                "7z tests the rust seal",
                with_password.stdout.decode(errors="replace").strip().splitlines()[-1][:90],
            )
            without = run(SEVEN, "t", f"-p{PASSWORD}x", str(sealed_rust))
            check(without.returncode != 0, "7z refuses the rust seal with the wrong key")
        else:
            check(False, "7z is on PATH", "not found")

        # --- 2. Python seals, Rust opens ------------------------------------
        sealed_py = work / "python-sealed.zip"
        check(util.seal_zip(source, sealed_py, PASSWORD) is not None, "python seal wrote a file")

        opened_py = work / "python-out"
        done = run(str(BINARY), "open", str(sealed_py), str(opened_py), PASSWORD)
        check(
            done.returncode == 0,
            "rust opens the python seal",
            done.stderr.decode()[:160].strip(),
        )
        check(tree(opened_py) == tree(root), "python seal round-trips every member in rust")

        wrong_py = work / "python-out-wrong"
        done = run(str(BINARY), "open", str(sealed_py), str(wrong_py), PASSWORD + "x")
        check(done.returncode == 2, "rust refuses the wrong key on a python seal")

        # --- 3. Container, both directions ----------------------------------
        payload = source.read_bytes()
        key_text = "seal-key-7c1d"

        blob = seal.seal(payload, key_text)
        artifact = work / "python-artifact.exe"
        trailer = b"SBLK" + key_text.encode().ljust(64, b"\x00") + b"Global\\Interop".ljust(800, b"\x00")
        body = b"MZ" + bytes(4096)
        offset = len(body)
        artifact.write_bytes(
            body
            + blob
            + trailer
            + b"SBLT"
            + struct.pack("<Q", offset)
        )

        payload_out = work / "payload-out.zip"
        done = run(str(BINARY), "image", str(artifact), str(payload_out))
        check(done.returncode == 0, "rust reads a python container", done.stderr.decode()[:160].strip())
        check(
            payload_out.is_file() and payload_out.read_bytes() == payload,
            "rust container decrypt matches the payload",
        )

        done = run(str(BINARY), "trailer", str(artifact))
        text = done.stdout.decode()
        check(
            "seal-key-7c1d" in text and "Global\\Interop" in text,
            "rust reads the trailer slots",
        )

        rust_blob = work / "rust-blob.bin"
        done = run(str(BINARY), "seal-blob", str(source), str(rust_blob), key_text)
        check(done.returncode == 0, "rust seals a container blob")

        recovered = loader._open_sealed(rust_blob.read_bytes(), key_text)
        check(recovered == payload, "python opens a rust container blob")

        refused = False
        try:
            loader._open_sealed(rust_blob.read_bytes(), key_text + "x")
        except loader.ArchiveError:
            refused = True
        check(refused, "python refuses a rust blob under the wrong key")

        # --- 4. A real artifact, built by the product ------------------------
        from core import forge, schema

        config = schema.RunConfig(
            schema_version=1,
            mutex="Global\\InteropArtifact",
            seal_key=key_text,
            relay=schema.RelayConfig(
                kind="https", endpoint="https://example.invalid/relay"
            ),
            sources=schema.SourceConfig(),
        )

        staged = work / "staged.zip"
        staged.write_bytes(forge.payload(SABLE, config))
        artifact_sealed = seal.seal(staged.read_bytes(), key_text)

        stub = SABLE / "tools" / "dist" / "sable-launcher.exe"
        built = forge.build(
            config, artifact_sealed, work / "forged.exe", mode="exe", stub=stub
        )

        forged_out = work / "forged-payload.zip"
        done = run(str(BINARY), "image", str(built), str(forged_out))
        check(done.returncode == 0, "rust reads a forged artifact", done.stderr.decode()[:160].strip())
        check(
            forged_out.is_file() and forged_out.read_bytes() == staged.read_bytes(),
            "forged artifact decrypts to the payload the forge sealed",
        )

        done = run(str(BINARY), "trailer", str(built))
        text = done.stdout.decode()
        check(key_text in text, "the forged trailer carries the seal key")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for ok, _, _ in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
