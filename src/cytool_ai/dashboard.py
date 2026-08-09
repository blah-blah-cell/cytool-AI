"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import read
from .modules import registry
from .workspaces import open_workspace


def serve(workspace_name: str, host: str, port: int) -> None:
    workspace = open_workspace(workspace_name)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                payload = {"status": "ok", "service": "cytool-ai"}
            elif self.path == "/api/modules":
                payload = {"modules": [module.__dict__ for module in registry().values()]}
            elif self.path == "/api/audit":
                payload = {"events": read(workspace)}
            else:
                self.send_error(404, "not found")
                return
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    print(f"cytool-AI dashboard API: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
