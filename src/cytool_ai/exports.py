"""Interchange formats for workspace findings."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .findings import list_all
from .iocs import list_all as list_iocs

LEVELS = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def sarif_payload(workspace: Path) -> dict[str, object]:
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
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "cytool-AI", "rules": rules}}, "results": results}]}


def write_sarif(workspace: Path, destination: Path) -> Path:
    payload = sarif_payload(workspace)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination


def stix_payload(workspace: Path) -> dict[str, object]:
    objects = []
    for ioc in list_iocs(workspace):
        escaped_value = ioc["value"].replace("'", "\\'")
        objects.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}", "created": ioc["first_seen"], "modified": ioc["first_seen"], "name": f"cytool-AI {ioc['kind']}", "pattern_type": "stix", "valid_from": ioc["first_seen"], "pattern": f"[{ioc['kind']} = '{escaped_value}']", "external_references": [{"source_name": "cytool-ai", "description": ioc["source"]}]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects, "created": datetime.now(UTC).isoformat()}


def write_stix(workspace: Path, destination: Path) -> Path:
    payload = stix_payload(workspace)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination
