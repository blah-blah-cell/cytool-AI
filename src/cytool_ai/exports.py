"""Interchange formats for workspace findings."""

from __future__ import annotations

import json
from pathlib import Path

from .findings import list_all


LEVELS = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def write_sarif(workspace: Path, destination: Path) -> Path:
    findings = list_all(workspace)
    rules = []
    results = []
    seen: set[str] = set()
    for finding in findings:
        rule_id = f"cytool-ai/{finding['title'].lower().replace(' ', '-') }"
        if rule_id not in seen:
            rules.append({"id": rule_id, "shortDescription": {"text": finding["title"]}})
            seen.add(rule_id)
        results.append({
            "ruleId": rule_id,
            "level": LEVELS.get(finding["severity"], "note"),
            "message": {"text": finding["title"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding["report"]}}}],
            "properties": {"cytoolFindingId": finding["id"], "createdAt": finding["created_at"]},
        })
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "cytool-AI", "rules": rules}}, "results": results}]}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination
