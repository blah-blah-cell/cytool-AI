"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .ai import chat, configured
from .artifacts import MAX_UPLOAD_BYTES, inspect_upload, store_upload
from .audit import read, record
from .findings import list_all
from .iocs import list_all as list_iocs
from .modules import install, installed, registry
from .policy import Scope, save, validate_target
from .investigations import web_evidence, web_input_surface
from .reports import write_report
from .findings import add
from .logs import correlate
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
            elif self.path == "/api/artifacts":
                payload = {"artifacts": [{"name": path.name, "size_bytes": path.stat().st_size} for path in sorted((workspace / "artifacts").iterdir()) if path.is_file()]}
            else:
                self.send_error(404, "not found")
                return
            self.send_json(payload)

        def do_POST(self) -> None:  # noqa: N802
            def request_json() -> dict[str, object]:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 64 * 1024:
                    raise ValueError("invalid request size")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("request body must be an object")
                return payload

            if self.path == "/api/scope":
                try:
                    payload = request_json()
                    domains = tuple(str(domain).strip().lower().rstrip(".") for domain in payload.get("domains", []) if str(domain).strip())
                    scope = Scope(str(payload.get("engagement", "")), str(payload.get("authorized_by", "")), domains)
                    save(workspace, scope)
                    record(workspace, "scope.declared_from_dashboard", engagement=scope.engagement, domains=domains)
                    self.send_json({"engagement": scope.engagement, "domains": domains}, 201)
                except (ValueError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/web/review":
                try:
                    payload = request_json()
                    if "web-scope-check" not in installed(workspace):
                        raise PermissionError("install the web-scope-check module before running a web review")
                    if payload.get("authorized") is not True:
                        raise PermissionError("confirm authorization before requesting a target")
                    mode = str(payload.get("mode", "headers"))
                    if mode not in {"headers", "forms"}:
                        raise ValueError("mode must be headers or forms")
                    url = str(payload.get("url", ""))
                    validate_target(workspace, url)
                    evidence = web_evidence(url) if mode == "headers" else web_input_surface(url)
                    title = "Web response-header review" if mode == "headers" else "Web input-surface inventory"
                    report = write_report(workspace, title, evidence)
                    add(workspace, title, report, "low" if mode == "headers" and evidence.get("missing_recommended_headers") else "info")
                    record(workspace, "web.reviewed_from_dashboard", mode=mode, url=url, status=evidence["status"])
                    self.send_json({"evidence": evidence, "report": str(report)}, 201)
                except (ValueError, PermissionError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/logs/correlate":
                try:
                    payload = request_json()
                    if "log-correlation" not in installed(workspace):
                        raise PermissionError("install the log-correlation module before correlating logs")
                    names = payload.get("artifacts", [])
                    if not isinstance(names, list) or not 1 <= len(names) <= 20:
                        raise ValueError("select between 1 and 20 uploaded log files")
                    paths = []
                    artifact_root = (workspace / "artifacts").resolve()
                    for name in names:
                        candidate = (artifact_root / Path(str(name)).name).resolve()
                        if artifact_root not in candidate.parents or not candidate.is_file():
                            raise ValueError("selected log artifact was not found")
                        paths.append(candidate)
                    evidence = correlate(paths)
                    report = write_report(workspace, "Log correlation", evidence)
                    add(workspace, "Log correlation", report)
                    record(workspace, "logs.correlated_from_dashboard", sources=evidence["sources"], event_count=evidence["event_count"])
                    self.send_json({"evidence": evidence, "report": str(report)}, 201)
                except (ValueError, PermissionError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/artifacts/inspect":
                try:
                    if "artifact-inspector" not in installed(workspace):
                        raise PermissionError("install the artifact-inspector module before inspecting uploads")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_UPLOAD_BYTES:
                        raise ValueError("provide an artifact no larger than 100 MiB")
                    filename = self.headers.get("X-Cytool-Filename", "uploaded-artifact.bin")
                    result = inspect_upload(workspace, filename, self.rfile.read(length))
                    self.send_json(result, 201)
                except (ValueError, PermissionError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/artifacts/upload":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_UPLOAD_BYTES:
                        raise ValueError("provide an artifact no larger than 100 MiB")
                    filename = self.headers.get("X-Cytool-Filename", "uploaded-evidence.bin")
                    destination = store_upload(workspace, filename, self.rfile.read(length))
                    record(workspace, "artifact.uploaded", filename=destination.name, size_bytes=destination.stat().st_size)
                    self.send_json({"artifact": destination.name, "size_bytes": destination.stat().st_size}, 201)
                except (ValueError, PermissionError, OSError) as exc:
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
