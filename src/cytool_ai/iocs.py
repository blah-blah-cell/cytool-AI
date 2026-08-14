"""Local indicator extraction, deduplication, and STIX-ready storage."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from .state import atomic_write_text, workspace_lock

URL = re.compile(r"https?://[^\s\"'<>]{6,512}", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
MAX_TEXT_SCAN_BYTES = 64 * 1024 * 1024


def _path(workspace: Path) -> Path:
    return workspace / "iocs.json"


def list_all(workspace: Path) -> list[dict[str, str]]:
    path = _path(workspace)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def _values(text: str) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for kind, pattern in (("url", URL), ("ipv4-addr", IPV4), ("domain-name", DOMAIN), ("file:hashes.SHA-256", SHA256)):
        for value in pattern.findall(text):
            normalized = value.lower().rstrip(".,;:)")
            values.append((kind, normalized))
    return values


def extract(workspace: Path, source: Path) -> list[dict[str, str]]:
    if not source.is_file():
        raise FileNotFoundError(f"source not found: {source}")
    digest = hashlib.sha256()
    sample = bytearray()
    with source.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            if len(sample) < MAX_TEXT_SCAN_BYTES:
                sample.extend(chunk[:MAX_TEXT_SCAN_BYTES - len(sample)])
    text = bytes(sample).decode("utf-8", errors="replace")
    now = datetime.now(UTC).isoformat()
    with workspace_lock(workspace):
        existing = {(ioc["kind"], ioc["value"]): ioc for ioc in list_all(workspace)}
        for kind, value in _values(text):
            existing.setdefault((kind, value), {"kind": kind, "value": value, "source": str(source.resolve()), "first_seen": now})
        sha = digest.hexdigest()
        existing.setdefault(("file:hashes.SHA-256", sha), {"kind": "file:hashes.SHA-256", "value": sha, "source": str(source.resolve()), "first_seen": now})
        values = sorted(existing.values(), key=lambda entry: (entry["kind"], entry["value"]))
        atomic_write_text(_path(workspace), json.dumps(values, indent=2) + "\n")
    return values
