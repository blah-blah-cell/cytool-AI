"""Registry for built-in, implemented workflow modules.

Installation enables a bundled workflow; external archives use the separate,
integrity-verified tool-pack mechanism and are never silently executed.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .state import atomic_write_text, workspace_lock


@dataclass(frozen=True)
class Module:
    id: str
    name: str
    summary: str
    category: str
    requires_authorization: bool
    version: str = "2.0.0"


BUILTIN_MODULES = (
    Module(
        id="artifact-inspector",
        name="Artifact Inspector",
        summary="Streaming hashes, bounded strings, and format triage for user-provided files.",
        category="forensics",
        requires_authorization=False,
    ),
    Module(
        id="web-scope-check",
        name="Web Scope Check",
        summary="Scope validation, passive HTTP review, and TLS evidence for an authorized web target.",
        category="web-security",
        requires_authorization=True,
    ),
    Module(
        id="binary-fingerprint",
        name="Binary Fingerprint",
        summary="Explainable entropy, capability, hash, and ELF/PE profiling for a supplied binary.",
        category="reverse-engineering",
        requires_authorization=False,
    ),
    Module(
        id="memory-artifact-triage",
        name="Memory Artifact Triage",
        summary="Chunk-streamed network, email, and file-path indicators from supplied memory.",
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
    with workspace_lock(workspace):
        active = installed(workspace)
        active[module_id] = asdict(module)
        atomic_write_text(installed_path(workspace), json.dumps(active, indent=2, sort_keys=True) + "\n")
    return module
