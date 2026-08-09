"""Authorization and target-scope controls."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Scope:
    engagement: str
    authorized_by: str
    domains: tuple[str, ...]


def _path(workspace: Path) -> Path:
    return workspace / "scope.json"


def save(workspace: Path, scope: Scope) -> None:
    if not scope.engagement.strip() or not scope.authorized_by.strip():
        raise ValueError("engagement and authorized-by are required")
    if not scope.domains:
        raise ValueError("at least one approved domain is required")
    _path(workspace).write_text(json.dumps(asdict(scope), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load(workspace: Path) -> Scope:
    path = _path(workspace)
    if not path.exists():
        raise PermissionError("no declared scope; use `cytool scope set` first")
    data = json.loads(path.read_text(encoding="utf-8"))
    return Scope(data["engagement"], data["authorized_by"], tuple(data["domains"]))


def validate_target(workspace: Path, target: str) -> str:
    scope = load(workspace)
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("target must include a hostname")
    if not any(hostname == domain or hostname.endswith(f".{domain}") for domain in scope.domains):
        raise PermissionError(f"target is outside the declared scope: {hostname}")
    return hostname
