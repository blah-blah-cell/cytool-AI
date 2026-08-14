"""Authorization and target-scope controls."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

from .state import atomic_write_text, workspace_lock

DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


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
    for domain in scope.domains:
        if not _valid_domain(domain):
            raise ValueError(f"invalid approved domain: {domain}")
    with workspace_lock(workspace):
        atomic_write_text(_path(workspace), json.dumps(asdict(scope), indent=2, sort_keys=True) + "\n")


def load(workspace: Path) -> Scope:
    path = _path(workspace)
    if not path.exists():
        raise PermissionError("no declared scope; use `cytool scope set` first")
    data = json.loads(path.read_text(encoding="utf-8"))
    return Scope(data["engagement"], data["authorized_by"], tuple(data["domains"]))


def validate_target(workspace: Path, target: str) -> str:
    scope = load(workspace)
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target URL must use HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("target URL must not contain credentials")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("target must include a hostname")
    if not any(hostname == domain or hostname.endswith(f".{domain}") for domain in scope.domains):
        raise PermissionError(f"target is outside the declared scope: {hostname}")
    return hostname


def _valid_domain(domain: str) -> bool:
    if not domain or domain != domain.lower().strip().rstrip(".") or len(domain) > 253:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass
    if domain == "localhost":
        return True
    labels = domain.split(".")
    return len(labels) >= 2 and all(DOMAIN_LABEL.fullmatch(label) for label in labels)
