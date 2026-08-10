"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .ai import chat, configured
from .artifacts import MAX_UPLOAD_BYTES, inspect_upload
from .audit import read, record
from .findings import list_all
from .iocs import list_all as list_iocs
from .modules import install, installed, registry
from .workspaces import open_workspace


PAGE = (Path(__file__).with_name("web") / "dashboard.html").read_bytes()


def serve(workspace_name: str, host: str, port: int) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise PermissionError("dashboard may only bind to localhost")
    workspace = open_workspace(workspace_name)

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, payload: object, status: int = 200) -> None:
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                payload = {"status": "ok", "service": "cytool-ai"}
            elif self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(PAGE)))
                self.end_headers()
                self.wfile.write(PAGE)
                return
            elif self.path == "/v1/models":
                try:
                    model = configured().model
                except RuntimeError:
                    self.send_error(503, "configure an AI provider first")
                    return
                payload = {"object": "list", "data": [{"id": model, "object": "model", "owned_by": "cytool-ai"}]}
            elif self.path == "/api/modules":
                active = installed(workspace)
                payload = {"modules": [{**module.__dict__, "installed": module.id in active} for module in registry().values()]}
            elif self.path == "/api/audit":
                payload = {"events": read(workspace)}
            elif self.path == "/api/findings":
                payload = {"findings": list_all(workspace)}
            elif self.path == "/api/summary":
                payload = {"workspace": workspace.name, "audit_events": len(read(workspace)), "findings": len(list_all(workspace)), "iocs": len(list_iocs(workspace)), "modules": len(registry())}
            elif self.path == "/api/iocs":
                payload = {"iocs": list_iocs(workspace)}
            else:
                self.send_error(404, "not found")
                return
            self.send_json(payload)

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/artifacts/inspect":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_UPLOAD_BYTES:
                        raise ValueError("provide an artifact no larger than 100 MiB")
                    filename = self.headers.get("X-Cytool-Filename", "uploaded-artifact.bin")
                    result = inspect_upload(workspace, filename, self.rfile.read(length))
                    self.send_json(result, 201)
                except (ValueError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            prefix = "/api/modules/"
            suffix = "/install"
            if self.path.startswith(prefix) and self.path.endswith(suffix):
                module_id = unquote(self.path[len(prefix):-len(suffix)])
                try:
                    module = install(workspace, module_id)
                    record(workspace, "module.installed_from_dashboard", module_id=module.id, version=module.version)
                    self.send_json({"installed": module.id}, 201)
                except KeyError:
                    self.send_json({"error": "unknown module"}, 404)
                return
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
