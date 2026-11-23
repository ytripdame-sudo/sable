"""Local relay: accepts one multipart upload and writes the file part to disk.

Nothing leaves the machine. This exists so the transmit path can be exercised for
real instead of mocked: a real socket, a real multipart body, a real status code.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "received")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
# 0.0.0.0 so a second machine on the same network can reach it. 127.0.0.1 keeps the
# receiver private to the box that started it, which is the default for a local test.
HOST = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"

OUT.mkdir(parents=True, exist_ok=True)

# ``refuse`` makes this box answer every upload with 500 without storing it. That is how
# an ordered failover gets proven: the primary is reachable and rejects, so a run that
# lands on the mirror did it after a real refusal rather than after a dead socket.
REFUSE = len(sys.argv) > 4 and sys.argv[4] == "refuse"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"  [relay] {format % args}", flush=True)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        content_type = self.headers.get("Content-Type") or ""
        body = self.rfile.read(length)

        print(f"  [relay] POST {self.path}  {length} bytes  {content_type[:60]}", flush=True)

        if REFUSE:
            print(f"  [relay] refused {length} bytes on purpose", flush=True)
            self._answer(500, b"refused by the audit")
            return

        if content_type.startswith("application/json"):
            # Status webhooks post JSON to the same box. Keep it visible rather than
            # rejecting it as a malformed multipart body.
            (OUT / f"status-{self.path.strip('/').replace('/', '-') or 'root'}.json").write_bytes(
                body
            )
            print(f"  [relay] json {body.decode('utf-8', 'replace')}", flush=True)
            self._answer(204, b"")
            return

        if "boundary=" not in content_type:
            self._answer(400, b"no boundary")
            return

        boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
        delimiter = b"--" + boundary

        written: list[str] = []
        for part in body.split(delimiter):
            if b"\r\n\r\n" not in part:
                continue
            head, payload = part.split(b"\r\n\r\n", 1)
            name_field = head.split(b'name="', 1)[1].split(b'"', 1)[0].decode(
                "utf-8", "replace"
            ) if b'name="' in head else "?"
            if b"filename=" not in head:
                value = payload.rstrip(b"\r\n").decode("utf-8", "replace")
                print(f"  [relay] field {name_field}: {value}", flush=True)
                continue
            payload = payload[:-2] if payload.endswith(b"\r\n") else payload
            name = head.split(b"filename=", 1)[1].split(b"\r\n")[0].strip(b'"').decode(
                "utf-8", "replace"
            )
            target = OUT / Path(name).name
            target.write_bytes(payload)
            written.append(f"{target.name} ({len(payload)} bytes)")
            print(f"  [relay] saved {target.name}  {len(payload)} bytes", flush=True)

        if not written:
            self._answer(400, b"no file part")
            return

        self._answer(200, ("stored: " + ", ".join(written)).encode())

    def _answer(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"relay listening on http://{HOST}:{PORT}/upload -> {OUT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
