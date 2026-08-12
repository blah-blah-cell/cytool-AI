"""Portable Markdown reports and AI-ready evidence bundles."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .state import atomic_write_text, workspace_lock


def write_report(workspace: Path, title: str, evidence: dict[str, Any]) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = workspace / "findings" / f"report-{stamp}.md"
    rendered = json.dumps(evidence, indent=2, sort_keys=True)
    with workspace_lock(workspace):
        atomic_write_text(destination, f"# {title}\n\nGenerated: {stamp}\n\n## Evidence\n\n```json\n{rendered}\n```\n")
    return destination


def write_ai_bundle(workspace: Path, purpose: str, evidence: dict[str, Any]) -> Path:
    """Write a provider-neutral bundle; users choose if and where to send it."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = workspace / "findings" / f"ai-bundle-{stamp}.json"
    with workspace_lock(workspace):
        atomic_write_text(destination, json.dumps({"purpose": purpose, "evidence": evidence}, indent=2, sort_keys=True) + "\n")
    return destination
