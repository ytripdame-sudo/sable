"""Receive a status report from the laptop and write it where the bench can read it.

The artifact self-removes on the success path and keeps nothing local, so after a run the
only evidence left on the machine is the absence of the image, the queue depth and the
retry task. Those are exactly the facts this sink collects.

    python tools/probes/report_sink.py [--port 8111] [--out tools/probes/out/received]

POST /report with a JSON body. Anything that is not JSON is stored as text, because a
broken report is still evidence and a 400 would throw it away.
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_BODY = 2 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "sable-sink/1"
    out_dir: Path = HERE / "out" / "received"

    def log_message(self, fmt: str, *args: object) -> None:
        # The peer address is the interesting part of every line, so it is kept and the
        # default timestamp noise is dropped.
        print(f"{self.client_address[0]} {fmt % args}")

    def _reply(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler names
        self._reply(200, b"sable sink up\n")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler names
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._reply(400, b"bad length\n")
            return
        if length <= 0 or length > MAX_BODY:
            self._reply(413, b"bad size\n")
            return

        raw = self.rfile.read(length)
        text = raw.decode("utf-8", "replace")

        stamp = time.strftime("%Y%m%d-%H%M%S")
        peer = self.client_address[0].replace(".", "-")
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Parsed and pretty-printed when it is JSON, stored verbatim when it is not, and
        # both are kept beside a plain-text copy of exactly what arrived.
        try:
            document = json.loads(text)
        except ValueError:
            document = None

        name = f"{stamp}-{peer}"
        (self.out_dir / f"{name}.raw.txt").write_text(text, encoding="utf-8")
        if document is not None:
            (self.out_dir / f"{name}.json").write_text(
                json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True),
                encoding="utf-8",
            )

        print()
        print(f"--- report from {self.client_address[0]} at {stamp} ---")
        if document is None:
            print(text)
        else:
            print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True))
        print("--- end ---")
        print()

        self._reply(200, b"received\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8111)
    parser.add_argument("--out", default=str(HERE / "out" / "received"))
    args = parser.parse_args()

    Handler.out_dir = Path(args.out)
    Handler.out_dir.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"sink listening on 0.0.0.0:{args.port}")
    print(f"writing to {Handler.out_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
