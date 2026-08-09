"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .ai import chat, configured
from .audit import read
from .findings import list_all
from .iocs import list_all as list_iocs
from .modules import registry
from .workspaces import open_workspace


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>cytool-AI</title><style>body{background:#0a1019;color:#dbe7f3;font:15px system-ui;margin:0}main{max-width:1050px;margin:48px auto;padding:0 24px}h1{color:#58d5ff}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric,section{background:#121d2b;border:1px solid #284155;border-radius:10px;padding:18px;margin:16px 0}.metric strong{display:block;font-size:28px;color:#7ee787}pre{white-space:pre-wrap;word-break:break-word;color:#bbd5e8}.tag{color:#7ee787}</style></head><body><main><h1>cytool-AI <span class="tag">local workspace</span></h1><p>Local-only dashboard. Evidence remains on this machine unless you explicitly use an AI provider.</p><div class="grid"><div class="metric">Modules<strong id="module-count">…</strong></div><div class="metric">Findings<strong id="finding-count">…</strong></div><div class="metric">Audit events<strong id="audit-count">…</strong></div></div><section><h2>Case findings</h2><pre id="findings">Loading…</pre></section><section><h2>Installed capability registry</h2><pre id="modules">Loading…</pre></section><section><h2>Recent audit events</h2><pre id="audit">Loading…</pre></section></main><script>for(const [id,url] of Object.entries({modules:'/api/modules',audit:'/api/audit',findings:'/api/findings'})){fetch(url).then(r=>r.json()).then(x=>document.getElementById(id).textContent=JSON.stringify(x,null,2)).catch(e=>document.getElementById(id).textContent=e.message)}fetch('/api/summary').then(r=>r.json()).then(x=>{document.getElementById('module-count').textContent=x.modules;document.getElementById('finding-count').textContent=x.findings;document.getElementById('audit-count').textContent=x.audit_events})</script></body></html>""".encode("utf-8")


def serve(workspace_name: str, host: str, port: int) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise PermissionError("dashboard may only bind to localhost")
    workspace = open_workspace(workspace_name)

    class Handler(BaseHTTPRequestHandler):
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
                payload = {"modules": [module.__dict__ for module in registry().values()]}
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
