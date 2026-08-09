"""Workspace creation and validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .audit import record
from .paths import workspace_path


def create(name: str) -> Path:
    path = workspace_path(name)
    if path.exists():
        raise FileExistsError(f"workspace already exists: {name}")
    path.mkdir(parents=True)
    (path / "artifacts").mkdir()
    (path / "findings").mkdir()
    (path / "workspace.json").write_text(
        json.dumps({"name": name, "created_at": datetime.now(UTC).isoformat(), "schema_version": 1}, indent=2) + "\n",
        encoding="utf-8",
    )
    record(path, "workspace.created", name=name)
    return path


def open_workspace(name: str) -> Path:
    path = workspace_path(name)
    if not (path / "workspace.json").is_file():
        raise FileNotFoundError(f"workspace not found: {name}")
    return path
