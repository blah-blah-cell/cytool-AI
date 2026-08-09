from __future__ import annotations

import json

from cytool_ai.cli import main
from cytool_ai.paths import workspace_path


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
