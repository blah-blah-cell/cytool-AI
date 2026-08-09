"""Append-only audit event storage."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def record(workspace: Path, event: str, **details: Any) -> dict[str, Any]:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        "details": details,
    }
    audit_file = workspace / "audit.jsonl"
    with audit_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return payload


def read(workspace: Path) -> list[dict[str, Any]]:
    audit_file = workspace / "audit.jsonl"
    if not audit_file.exists():
        return []
    return [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines() if line]
