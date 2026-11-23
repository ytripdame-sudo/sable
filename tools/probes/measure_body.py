"""Measure what the upload body costs in memory, old shape against new.

The archive is a real 174 MB file, the same one that came back from gofile. tracemalloc
counts Python allocations, which is exactly what the bytes objects are.
"""

from __future__ import annotations

import sys
import tracemalloc
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402

ARCHIVE = Path(r"C:\Users\Kuzenee\Downloads\payload.zip")
if not ARCHIVE.is_file():
    raise SystemExit(f"missing {ARCHIVE}")

size = ARCHIVE.stat().st_size
print(f"archive        {size / 1048576:.1f} MB")

tracemalloc.start()
before = tracemalloc.get_traced_memory()[0]

# The shape that shipped until now: the file as bytes, then the same bytes again
# inside the multipart buffer.
payload = ARCHIVE.read_bytes()
body, _ = relay._multipart(
    {"payload_json": "{}"}, "files[0]", ARCHIVE.name, payload, "application/zip"
)
old_peak = tracemalloc.get_traced_memory()[1]
del payload, body
tracemalloc.stop()
print(f"buffered path  peak {old_peak / 1048576:8.1f} MB")

tracemalloc.start()
body, _ = relay._multipart_stream(
    {"payload_json": "{}"}, "files[0]", ARCHIVE, "application/zip"
)
written = 0
for block in body:
    written += len(block)
new_peak = tracemalloc.get_traced_memory()[1]
tracemalloc.stop()
print(f"streamed path  peak {new_peak / 1048576:8.1f} MB   ({written / 1048576:.1f} MB sent)")
print(f"ratio          {old_peak / max(new_peak, 1):.1f}x")
