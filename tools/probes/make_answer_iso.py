"""Build a one-file ISO carrying the answer file.

Windows Setup ignores ``autounattend.xml`` on a fixed disk but reads it from any
removable media it can enumerate. A second DVD drive is the reliable path in a
Hyper-V Gen 2 guest, which has no floppy controller and no USB passthrough worth
the trouble.

ISO9660 + Joliet, one file at the root, nothing else.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pycdlib

SOURCE = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\_iso\autounattend.xml")
TARGET = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\_iso\autounattend.iso")


def main() -> int:
    if not SOURCE.is_file():
        print(f"missing source: {SOURCE}")
        return 1

    iso = pycdlib.PyCdlib()
    iso.new(vol_ident="ANSWER", interchange_level=3, joliet=3)

    iso.add_file(
        str(SOURCE),
        iso_path="/AUTOUNATTEND.XML;1",
        joliet_path="/autounattend.xml",
    )

    if TARGET.exists():
        TARGET.unlink()
    iso.write(str(TARGET))
    iso.close()

    size = TARGET.stat().st_size
    print(f"wrote {TARGET.name}  {size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
