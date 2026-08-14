from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cytool_ai.ai import build_context, configure, configured
from cytool_ai.approval import ApprovalMode
from cytool_ai.artifacts import inspect_upload, store_upload
from cytool_ai.cli import main
from cytool_ai.dashboard import create_server
from cytool_ai.exports import sarif_payload, stix_payload, write_sarif, write_stix
from cytool_ai.findings import add, list_all
from cytool_ai.findings import list_all as workspace_findings
from cytool_ai.integrations import discover
from cytool_ai.investigations import (
    binary_metadata,
    cloud_export_review,
    memory_artifact_scan,
)
from cytool_ai.iocs import extract
from cytool_ai.iocs import extract as extract_iocs
from cytool_ai.modules import registry
from cytool_ai.operations import backup, doctor
from cytool_ai.paths import workspace_path
from cytool_ai.policy import Scope, save, validate_target
from cytool_ai.reports import write_report
from cytool_ai.state import atomic_write_text
from cytool_ai.terminal import execute, parse_safe, redact
from cytool_ai.toolpacks import fetch, register


def test_workspace_module_and_audit_flow(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    assert main(["init", "lab"]) == 0
    assert main(["modules", "install", "artifact-inspector", "--workspace", "lab"]) == 0
    assert main(["audit", "--workspace", "lab"]) == 0
    output = capsys.readouterr().out
    assert "module.installed" in output
    assert json.loads((workspace_path("lab") / "modules.json").read_text())["artifact-inspector"]


def test_workspace_names_cannot_escape_or_inject_control_characters(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    for name in ("../escape", "bad/name", "line\nbreak", "."):
        assert main(["init", name]) == 2


def test_authorization_gate(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    main(["init", "lab"])
    capture = tmp_path / "capture.raw"
    capture.write_bytes(b"memory evidence")
    main(["modules", "install", "memory-artifact-triage", "--workspace", "lab"])
    assert main(["memory", "scan", str(capture), "--workspace", "lab"]) == 2
    assert "requires --authorized" in capsys.readouterr().out


def test_every_builtin_offline_module_runs_through_cli(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path / "state"))
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 58)
    memory = tmp_path / "capture.raw"
    memory.write_bytes(b"connection https://case.example/path from 192.0.2.42")
    cloud = tmp_path / "cloud.json"
    cloud.write_text('{"bucket":{"public":true,"encryption":false}}')
    first_log = tmp_path / "auth.log"
    second_log = tmp_path / "web.log"
    first_log.write_text("2026-08-14T10:00:00Z login accepted\n")
    second_log.write_text("2026-08-14T10:00:01Z GET /dashboard\n")

    assert main(["init", "all-modules"]) == 0
    for module_id in ("artifact-inspector", "binary-fingerprint", "memory-artifact-triage", "cloud-evidence-review", "log-correlation"):
        assert main(["modules", "install", module_id, "--workspace", "all-modules"]) == 0
    assert main(["inspect", str(binary), "--workspace", "all-modules"]) == 0
    assert main(["binary", "inspect", str(binary), "--workspace", "all-modules"]) == 0
    assert main(["memory", "scan", str(memory), "--workspace", "all-modules", "--authorized"]) == 0
    assert main(["cloud", "review", str(cloud), "--workspace", "all-modules", "--authorized"]) == 0
    assert main(["logs", "correlate", str(first_log), str(second_log), "--workspace", "all-modules"]) == 0
    assert len(workspace_findings(workspace_path("all-modules"))) == 5


def test_inspection_writes_report_and_ai_bundle(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x7fELFhello-cytool-AI")
    main(["init", "lab"])
    main(["modules", "install", "artifact-inspector", "--workspace", "lab"])
    assert main(["inspect", str(sample), "--workspace", "lab", "--ai-bundle"]) == 0
    output = capsys.readouterr().out
    assert "ELF executable" in output
    workspace = workspace_path("lab")
    assert list((workspace / "findings").glob("report-*.md"))
    assert list((workspace / "findings").glob("ai-bundle-*.json"))
    assert list_all(workspace)


def test_scope_prevents_out_of_scope_target(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    main(["init", "lab"])
    assert main(["scope", "set", "--workspace", "lab", "--engagement", "test", "--authorized-by", "owner", "--domain", "example.com"]) == 0
    assert main(["scope", "check", "api.example.com", "--workspace", "lab"]) == 0
    assert main(["scope", "check", "outside.example", "--workspace", "lab"]) == 2
    assert main(["scope", "check", "file://example.com/etc/passwd", "--workspace", "lab"]) == 2
    assert "outside the declared scope" in capsys.readouterr().out


def test_terminal_modes_redact_and_do_not_use_a_shell(tmp_path):
    preview = execute("pwd", ApprovalMode.PLAN, tmp_path)
    assert not preview.executed
    allowed = execute("pwd", ApprovalMode.APPROVED, tmp_path)
    assert allowed.executed and allowed.returncode == 0
    try:
        execute("pwd; id", ApprovalMode.APPROVED, tmp_path)
    except PermissionError as exc:
        assert "shell syntax" in str(exc)
    else:
        raise AssertionError("shell syntax must be rejected")
    try:
        parse_safe("pytest")
    except PermissionError:
        pass
    else:
        raise AssertionError("commands that load project code must not be in the read-only allowlist")
    assert "[REDACTED]" in redact("api_key=should-not-leak")


def test_verified_toolpack_is_saved_but_never_executed(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path / "state"))
    main(["init", "lab"])
    source = tmp_path / "sample-pack.bin"
    source.write_bytes(b"verified fixture")
    manifest = tmp_path / "pack.json"
    manifest.write_text(json.dumps({
        "id": "fixture-pack", "name": "Fixture", "summary": "test", "version": "1.0",
        "source": source.as_uri(), "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }))
    workspace = workspace_path("lab")
    register(workspace, manifest)
    downloaded = fetch(workspace, "fixture-pack")
    assert downloaded.read_bytes() == source.read_bytes()


def test_toolpack_manifest_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path / "state"))
    main(["init", "lab"])
    manifest = tmp_path / "bad-pack.json"
    manifest.write_text(json.dumps({
        "id": "fixture-pack", "name": "Fixture", "summary": "test", "version": "../../escape",
        "source": (tmp_path / "source.bin").as_uri(), "sha256": "0" * 64,
    }))
    try:
        register(workspace_path("lab"), manifest)
    except ValueError as exc:
        assert "safe identifiers" in str(exc)
    else:
        raise AssertionError("tool-pack path components must be validated")


def test_offline_investigation_workflows(tmp_path):
    elf = tmp_path / "sample"
    elf.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\0")
    assert binary_metadata(elf)["details"]["machine"] == "x86-64"
    capture = tmp_path / "capture.raw"
    capture.write_bytes(b"connect https://example.test/path from 192.0.2.25")
    memory = memory_artifact_scan(capture)
    assert memory["urls"] == ["https://example.test/path"]
    assert memory["ipv4_addresses"] == ["192.0.2.25"]
    cloud = tmp_path / "cloud.json"
    cloud.write_text('{"bucket":{"public":true,"encryption":false}}')
    assert cloud_export_review(cloud)["finding_count"] == 2


def test_memory_domains_and_elf_sections(tmp_path):
    elf = tmp_path / "minimal.elf"
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (62).to_bytes(2, "little")
    elf.write_bytes(header)
    assert binary_metadata(elf)["format"] == "ELF"
    capture = tmp_path / "capture.raw"
    capture.write_bytes(b"dns api.example.test https://api.example.test/health")
    assert "api.example.test" in memory_artifact_scan(capture)["domains"]


def test_sarif_export(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    report = workspace / "finding.md"
    report.write_text("# Finding")
    add(workspace, "Demo finding", report, "medium")
    output = write_sarif(workspace, tmp_path / "out.sarif")
    sarif = json.loads(output.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_ioc_extraction_and_stix_export(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = tmp_path / "evidence.txt"
    source.write_text("visit https://evil.example/path from 198.51.100.5")
    values = extract(workspace, source)
    assert any(value["kind"] == "url" for value in values)
    output = write_stix(workspace, tmp_path / "iocs.stix.json")
    assert json.loads(output.read_text())["type"] == "bundle"


def test_uploaded_artifact_is_stored_and_inspected(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "artifacts").mkdir(parents=True)
    (workspace / "findings").mkdir()
    result = inspect_upload(workspace, "sample.bin", b"MZlocal-test")
    assert Path(result["artifact"]).is_file()
    assert result["evidence"]["sha256"]


def test_scope_saved_for_dashboard_web_workflow(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    save(workspace, Scope("review", "owner", ("example.com",)))
    assert validate_target(workspace, "https://api.example.com/login") == "api.example.com"


def test_stored_upload_is_available_for_follow_up_workflows(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "artifacts").mkdir(parents=True)
    stored = store_upload(workspace, "auth.log", b"2026-08-10T12:00:00Z login")
    assert stored.name == "auth.log"
    assert stored.read_bytes().endswith(b"login")


def test_ai_context_requires_explicit_terminal_opt_in(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = build_context(workspace, False, tmp_path)
    assert context["workspace"] == "workspace"
    assert "terminal_snapshot" not in context


def test_uploaded_artifact_can_feed_ioc_analysis(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "artifacts").mkdir(parents=True)
    stored = store_upload(workspace, "network.txt", b"https://indicator.example/path 203.0.113.15")
    values = extract_iocs(workspace, stored)
    assert {item["kind"] for item in values} >= {"url", "ipv4-addr"}


def test_re_integration_registry_is_machine_readable():
    values = discover()
    assert {item["command"] for item in values} >= {"readelf", "objdump", "rabin2"}


def test_workspace_backup_and_doctor(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "workspace.json").write_text("{}")
    (workspace / "evidence.txt").write_text("case evidence")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("must not follow this link")
    (workspace / "outside-link").symlink_to(outside)
    output = backup(workspace, tmp_path / "backup.zip")
    assert output.is_file()
    import zipfile
    with zipfile.ZipFile(output) as archive:
        assert "outside-link" not in archive.namelist()
    assert doctor(workspace)["workspace"]["path"] == str(workspace)


def test_provider_configuration_stores_no_api_key(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    settings = configure("https://provider.example/v1", "model-a", "TEST_PROVIDER_KEY")
    saved = (tmp_path / "provider.json").read_text()
    assert settings.model == "model-a"
    assert "TEST_PROVIDER_KEY" in saved
    assert "secret" not in saved.lower()


def test_provider_configuration_requires_tls_for_remote_hosts(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    try:
        configure("http://provider.example/v1", "model-a", "PROVIDER_KEY")
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("remote provider traffic must use TLS")


def test_tampered_provider_configuration_is_revalidated(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    (tmp_path / "provider.json").write_text(json.dumps({"base_url": "http://provider.example/v1", "model": "model-a", "api_key_env": "PROVIDER_KEY"}))
    try:
        configured()
    except RuntimeError as exc:
        assert "configuration is invalid" in str(exc)
    else:
        raise AssertionError("stored provider configuration must not bypass transport validation")


def test_findings_keep_report_references(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    report = workspace / "report.md"
    report.write_text("# Case report")
    add(workspace, "Report", report)
    assert workspace_findings(workspace)[0]["report"] == str(report)


def test_export_payloads_support_dashboard_downloads(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert sarif_payload(workspace)["version"] == "2.1.0"
    assert stix_payload(workspace)["type"] == "bundle"


def test_module_registry_lists_only_implemented_workflows():
    assert "memory-capture-review" not in registry()
    assert "memory-artifact-triage" in registry()


def test_atomic_state_write_replaces_file_contents(tmp_path):
    destination = tmp_path / "state.json"
    atomic_write_text(destination, '{"version": 1}\n')
    atomic_write_text(destination, '{"version": 2}\n')
    assert json.loads(destination.read_text())["version"] == 2


def test_reports_do_not_collide_within_one_second(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "findings").mkdir(parents=True)
    first = write_report(workspace, "first", {"value": 1})
    second = write_report(workspace, "second", {"value": 2})
    assert first != second
    assert first.is_file() and second.is_file()


def test_dashboard_http_workflows(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path / "state"))
    assert main(["init", "dashboard-lab"]) == 0
    server = create_server("dashboard-lab")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    def request(path: str, *, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None):
        response = urlopen(Request(base_url + path, method=method, data=data, headers=headers or {}), timeout=5)
        return response.status, response.headers, response.read()

    try:
        status, _, body = request("/health")
        assert status == 200 and json.loads(body)["status"] == "ok"
        status, headers, body = request("/")
        assert status == 200 and "text/html" in headers["Content-Type"]
        assert b"cytool-AI" in body
        assert headers["X-Frame-Options"] == "DENY"

        status, _, body = request("/api/modules/artifact-inspector/install", method="POST", data=b"")
        assert status == 201 and json.loads(body)["installed"] == "artifact-inspector"
        status, _, body = request(
            "/api/artifacts/inspect",
            method="POST",
            data=b"MZdashboard-evidence https://indicator.example/path",
            headers={"X-Cytool-Filename": "sample.bin", "Content-Type": "application/octet-stream"},
        )
        result = json.loads(body)
        assert status == 201 and result["evidence"]["sha256"]

        assert main(["modules", "install", "web-scope-check", "--workspace", "dashboard-lab"]) == 0
        assert main(["scope", "set", "--workspace", "dashboard-lab", "--engagement", "local integration", "--authorized-by", "test owner", "--domain", "127.0.0.1"]) == 0
        assert main(["web", "headers", base_url + "/", "--workspace", "dashboard-lab", "--authorized"]) == 0
        assert main(["web", "forms", base_url + "/", "--workspace", "dashboard-lab", "--authorized"]) == 0

        status, _, body = request("/api/offline/analyze", method="POST", data=json.dumps({"workflow": "ioc", "artifact": "sample.bin"}).encode(), headers={"Content-Type": "application/json"})
        assert status == 201 and json.loads(body)["evidence"]["indicator_count"] >= 1
        status, _, body = request("/api/summary")
        assert status == 200 and json.loads(body)["findings"] >= 2
        status, headers, body = request("/api/export/sarif")
        assert status == 200 and "application/sarif+json" in headers["Content-Type"]
        assert json.loads(body)["version"] == "2.1.0"

        try:
            request("/v1/chat/completions", method="POST", data=b'{"messages": []}')
        except HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("the compatibility endpoint must require a bearer token")

        for hostile_headers in ({"Host": "attacker.example"}, {"Origin": "https://attacker.example"}):
            try:
                request("/api/modules/artifact-inspector/install", method="POST", data=b"", headers=hostile_headers)
            except HTTPError as exc:
                assert exc.code == 403
            else:
                raise AssertionError("untrusted dashboard requests must be rejected")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_dashboard_refuses_non_local_bind(monkeypatch, tmp_path):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    main(["init", "lab"])
    try:
        create_server("lab", "0.0.0.0")
    except PermissionError as exc:
        assert "localhost" in str(exc)
    else:
        raise AssertionError("dashboard must remain localhost-only")


def test_openai_compatible_endpoint_proxies_provider(monkeypatch, tmp_path):
    class ProviderHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            payload = json.loads(self.rfile.read(length))
            assert self.path == "/v1/chat/completions"
            assert self.headers["Authorization"] == "Bearer upstream-secret"
            assert payload["messages"][0]["role"] == "system"
            encoded = json.dumps({"id": "chatcmpl-test", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "provider-ok"}, "finish_reason": "stop"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format, *_args):
            return

    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("UPSTREAM_KEY", "upstream-secret")
    monkeypatch.setenv("CYTOOL_SERVER_KEY", "dashboard-secret")
    assert main(["init", "ai-lab"]) == 0
    provider = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    configure(f"http://127.0.0.1:{provider.server_address[1]}/v1", "test-model", "UPSTREAM_KEY")
    dashboard = create_server("ai-lab")
    dashboard_thread = threading.Thread(target=dashboard.serve_forever, daemon=True)
    dashboard_thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{dashboard.server_address[1]}/v1/chat/completions",
            method="POST",
            data=json.dumps({"messages": [{"role": "user", "content": "Teach me this"}]}).encode(),
            headers={"Authorization": "Bearer dashboard-secret", "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
        assert response.status == 200
        assert payload["choices"][0]["message"]["content"] == "provider-ok"
    finally:
        dashboard.shutdown()
        dashboard.server_close()
        provider.shutdown()
        provider.server_close()
        dashboard_thread.join(timeout=5)
        provider_thread.join(timeout=5)
