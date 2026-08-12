"""Workspace finding index for evidence reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .state import atomic_write_text, workspace_lock


def _path(workspace: Path) -> Path:
    return workspace / "finding-index.json"


def add(workspace: Path, title: str, report: Path, severity: str = "info") -> dict[str, str]:
    item = {"id": datetime.now(UTC).strftime("f-%Y%m%dT%H%M%S%fZ"), "title": title, "severity": severity, "report": str(report), "created_at": datetime.now(UTC).isoformat()}
    with workspace_lock(workspace):
        entries = list_all(workspace)
        entries.append(item)
        atomic_write_text(_path(workspace), json.dumps(entries, indent=2) + "\n")
    return item


def list_all(workspace: Path) -> list[dict[str, str]]:
    path = _path(workspace)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
