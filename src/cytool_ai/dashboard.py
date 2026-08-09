"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .ai import chat, configured
from .audit import read
from .modules import registry
from .workspaces import open_workspace


def serve(workspace_name: str, host: str, port: int) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise PermissionError("dashboard may only bind to localhost")
    workspace = open_workspace(workspace_name)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                payload = {"status": "ok", "service": "cytool-ai"}
            elif self.path == "/v1/models":
                try:
                    model = configured().model
                except RuntimeError:
                    self.send_error(503, "configure an AI provider first")
                    return
                payload = {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "cytool-ai"}]}
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

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/chat/completions":
                self.send_error(404, "not found")
                return
            server_key = os.environ.get("CYTOOL_SERVER_KEY")
            if not server_key or self.headers.get("Authorization") != f"Bearer {server_key}":
                self.send_error(401, "set CYTOOL_SERVER_KEY and provide a bearer token")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload.get("messages"), list):
                    raise ValueError("messages must be a list")
                response = chat(payload["messages"], context={"workspace": workspace.name})
                encoded = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (ValueError, RuntimeError, PermissionError) as exc:
                self.send_error(400, str(exc))

        def log_message(self, _format: str, *_args: object) -> None:
            return

    print(f"cytool-AI dashboard API: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
