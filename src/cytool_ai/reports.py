"""Portable Markdown reports and AI-ready evidence bundles."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def write_report(workspace: Path, title: str, evidence: dict[str, Any]) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = workspace / "findings" / f"report-{stamp}.md"
    rendered = json.dumps(evidence, indent=2, sort_keys=True)
    destination.write_text(f"# {title}\n\nGenerated: {stamp}\n\n## Evidence\n\n```json\n{rendered}\n```\n", encoding="utf-8")
    return destination


def write_ai_bundle(workspace: Path, purpose: str, evidence: dict[str, Any]) -> Path:
    """Write a provider-neutral bundle; users choose if and where to send it."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = workspace / "findings" / f"ai-bundle-{stamp}.json"
    destination.write_text(json.dumps({"purpose": purpose, "evidence": evidence}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
