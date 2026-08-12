"""Small local-only JSON dashboard server (no third-party runtime required)."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .ai import build_context, chat, configure, configured, response_text
from .artifacts import MAX_UPLOAD_BYTES, inspect_upload, store_upload
from .audit import read, record
from .findings import add, list_all
from .iocs import list_all as list_iocs
from .modules import install, installed, registry
from .policy import Scope, save, validate_target
from .investigations import binary_metadata, cloud_export_review, memory_artifact_scan, web_evidence, web_input_surface
from .reports import write_report
from .iocs import extract as extract_iocs
from .integrations import discover
from .retools import inspect as external_re_inspect
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
            elif self.path == "/api/integrations":
                payload = {"integrations": discover()}
            elif self.path == "/api/config/provider":
                try:
                    settings = configured()
                    payload = {"configured": True, "base_url": settings.base_url, "model": settings.model, "api_key_env": settings.api_key_env, "key_present": bool(os.environ.get(settings.api_key_env))}
                except RuntimeError:
                    payload = {"configured": False}
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
            if self.path == "/api/config/provider":
                try:
                    payload = request_json()
                    settings = configure(str(payload.get("base_url", "")), str(payload.get("model", "")), str(payload.get("api_key_env", "OPENAI_API_KEY")))
                    record(workspace, "provider.configured_from_dashboard", base_url=settings.base_url, model=settings.model, api_key_env=settings.api_key_env)
                    self.send_json({"configured": True, "base_url": settings.base_url, "model": settings.model, "api_key_env": settings.api_key_env, "key_present": bool(os.environ.get(settings.api_key_env))}, 201)
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
            if self.path == "/api/ai":
                try:
                    payload = request_json()
                    workflow = str(payload.get("workflow", "ask"))
                    if workflow not in {"ask", "teach", "fix"}:
                        raise ValueError("workflow must be ask, teach, or fix")
                    prompt = str(payload.get("prompt", "")).strip()
                    if not 1 <= len(prompt) <= 20_000:
                        raise ValueError("prompt must be between 1 and 20,000 characters")
                    include_terminal = payload.get("terminal_context") is True
                    prefixes = {
                        "ask": "Answer this with practical, authorization-first guidance:\n",
                        "teach": "Teach this clearly, using the supplied context and emphasizing safe, authorized practice:\n",
                        "fix": "Analyze this and propose a reviewable remediation plan. Do not execute commands:\n",
                    }
                    response = chat([{"role": "user", "content": prefixes[workflow] + prompt}], context=build_context(workspace, include_terminal, Path.cwd()))
                    answer = response_text(response)
                    record(workspace, "ai.request_from_dashboard", workflow=workflow, terminal_context=include_terminal)
                    self.send_json({"workflow": workflow, "answer": answer}, 201)
                except (ValueError, PermissionError, RuntimeError, OSError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/offline/analyze":
                try:
                    payload = request_json()
                    workflow = str(payload.get("workflow", ""))
                    workflow_config = {
                        "binary": ("binary-fingerprint", "Binary metadata", False),
                        "memory": ("memory-artifact-triage", "Memory artifact triage", True),
                        "cloud": ("cloud-evidence-review", "Cloud export posture review", True),
                        "ioc": ("artifact-inspector", "IOC extraction", False),
                    }
                    if workflow not in workflow_config:
                        raise ValueError("workflow must be binary, memory, cloud, or ioc")
                    module_id, title, requires_authorization = workflow_config[workflow]
                    if module_id not in installed(workspace):
                        raise PermissionError(f"install the {module_id} module before running this workflow")
                    if requires_authorization and payload.get("authorized") is not True:
                        raise PermissionError("confirm authorization before running this workflow")
                    name = Path(str(payload.get("artifact", ""))).name
                    path = (workspace / "artifacts" / name).resolve()
                    if path.parent != (workspace / "artifacts").resolve() or not path.is_file():
                        raise ValueError("select an uploaded artifact")
                    if workflow == "binary":
                        evidence = binary_metadata(path)
                    elif workflow == "memory":
                        evidence = memory_artifact_scan(path)
                    elif workflow == "cloud":
                        evidence = cloud_export_review(path)
                    else:
                        indicators = extract_iocs(workspace, path)
                        evidence = {"path": str(path), "indicator_count": len(indicators), "indicators": indicators}
                    report = write_report(workspace, title, evidence)
                    severity = "medium" if workflow == "cloud" and evidence.get("finding_count") else "info"
                    add(workspace, title, report, severity)
                    record(workspace, "offline.workflow_from_dashboard", workflow=workflow, artifact=name)
                    self.send_json({"evidence": evidence, "report": str(report)}, 201)
                except (ValueError, PermissionError, OSError, json.JSONDecodeError) as exc:
                    self.send_json({"error": str(exc)}, 400)
                return
            if self.path == "/api/re/external":
                try:
                    payload = request_json()
                    if "binary-fingerprint" not in installed(workspace):
                        raise PermissionError("install the binary-fingerprint module before collecting RE evidence")
                    tool = str(payload.get("tool", ""))
                    name = Path(str(payload.get("artifact", ""))).name
                    path = (workspace / "artifacts" / name).resolve()
                    if path.parent != (workspace / "artifacts").resolve() or not path.is_file():
                        raise ValueError("select an uploaded artifact")
                    evidence = external_re_inspect(path, tool)
                    report = write_report(workspace, f"External RE evidence ({tool})", evidence)
                    add(workspace, f"External RE evidence ({tool})", report)
                    record(workspace, "re.external_from_dashboard", tool=tool, artifact=name, returncode=evidence["returncode"])
                    self.send_json({"evidence": evidence, "report": str(report)}, 201)
                except (ValueError, PermissionError, FileNotFoundError, OSError) as exc:
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
