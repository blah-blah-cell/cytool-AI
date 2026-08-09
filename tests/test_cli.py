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
