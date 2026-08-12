from __future__ import annotations

import json
import hashlib
from pathlib import Path

from cytool_ai.cli import main
from cytool_ai.paths import workspace_path
from cytool_ai.approval import ApprovalMode
from cytool_ai.terminal import execute, redact
from cytool_ai.toolpacks import fetch, register
from cytool_ai.investigations import binary_metadata, cloud_export_review, memory_artifact_scan, web_input_surface
from cytool_ai.exports import write_sarif, write_stix
from cytool_ai.findings import add
from cytool_ai.iocs import extract
from cytool_ai.artifacts import inspect_upload, store_upload
from cytool_ai.policy import Scope, save, validate_target
from cytool_ai.ai import build_context
from cytool_ai.iocs import extract as extract_iocs
from cytool_ai.integrations import discover


def test_workspace_module_and_audit_flow(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    assert main(["init", "lab"]) == 0
    assert main(["modules", "install", "artifact-inspector", "--workspace", "lab"]) == 0
    assert main(["run", "artifact-inspector", "--workspace", "lab"]) == 0
    assert main(["audit", "--workspace", "lab"]) == 0
    output = capsys.readouterr().out
    assert "module.execution_requested" in output
    assert json.loads((workspace_path("lab") / "modules.json").read_text())["artifact-inspector"]


def test_authorization_gate(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    main(["init", "lab"])
    main(["modules", "install", "web-scope-check", "--workspace", "lab"])
    assert main(["run", "web-scope-check", "--workspace", "lab"]) == 2
    assert "requires --authorized" in capsys.readouterr().out


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


def test_scope_prevents_out_of_scope_target(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CYTOOL_HOME", str(tmp_path))
    main(["init", "lab"])
    assert main(["scope", "set", "--workspace", "lab", "--engagement", "test", "--authorized-by", "owner", "--domain", "example.com"]) == 0
    assert main(["scope", "check", "api.example.com", "--workspace", "lab"]) == 0
    assert main(["scope", "check", "outside.example", "--workspace", "lab"]) == 2
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
