"""Module registry and installation metadata.

This layer intentionally installs metadata, not unreviewed executable payloads.
Future remote module sources must be integrity checked before code is accepted.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    summary: str
    category: str
    requires_authorization: bool
    version: str = "0.1.0"


BUILTIN_MODULES = (
    Module(
        id="artifact-inspector",
        name="Artifact Inspector",
        summary="Offline metadata triage for user-provided files.",
        category="forensics",
        requires_authorization=False,
    ),
    Module(
        id="memory-capture-review",
        name="Memory Capture Review",
        summary="Reserved workflow for offline analysis of supplied memory captures.",
        category="memory-forensics",
        requires_authorization=True,
    ),
    Module(
        id="web-scope-check",
        name="Web Scope Check",
        summary="Reserved workflow for validating a declared, authorized web assessment scope.",
        category="web-security",
        requires_authorization=True,
    ),
    Module(
        id="binary-fingerprint",
        name="Binary Fingerprint",
        summary="Offline hashes, strings, and format hints for a user-provided binary.",
        category="reverse-engineering",
        requires_authorization=False,
    ),
    Module(
        id="memory-artifact-triage",
        name="Memory Artifact Triage",
        summary="Offline strings and indicators review for a supplied memory capture.",
        category="memory-forensics",
        requires_authorization=True,
    ),
    Module(
        id="cloud-evidence-review",
        name="Cloud Evidence Review",
        summary="Offline review workflow for exported cloud configuration evidence.",
        category="cloud-security",
        requires_authorization=True,
    ),
    Module(
        id="log-correlation",
        name="Log Correlation",
        summary="Offline normalization and timestamp correlation for supplied logs.",
        category="incident-response",
        requires_authorization=False,
    ),
)


def registry() -> dict[str, Module]:
    return {module.id: module for module in BUILTIN_MODULES}


def installed_path(workspace: Path) -> Path:
    return workspace / "modules.json"


def installed(workspace: Path) -> dict[str, dict[str, object]]:
    path = installed_path(workspace)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def install(workspace: Path, module_id: str) -> Module:
    module = registry().get(module_id)
    if module is None:
        raise KeyError(f"unknown module: {module_id}")
    active = installed(workspace)
    active[module_id] = asdict(module)
    installed_path(workspace).write_text(json.dumps(active, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return module
