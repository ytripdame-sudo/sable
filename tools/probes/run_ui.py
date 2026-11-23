"""Start the SABLE window."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from app.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([]))
