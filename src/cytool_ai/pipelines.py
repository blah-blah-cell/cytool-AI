"""Declarative, evidence-only investigation pipelines.

Pipeline steps dispatch only to bundled defensive workflows. They never invoke
a shell, execute samples, or load code from a manifest.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analysis import inspect_file
from .audit import record
from .findings import add
from .investigations import (
    binary_security_profile,
    cloud_export_review,
    memory_artifact_scan,
)
from .iocs import extract as extract_iocs
from .logs import correlate
from .modules import installed
from .reports import write_report
from .state import atomic_write_text

MAX_STEPS = 25
WORKFLOWS = {
    "inspect": {"module": "artifact-inspector", "authorized": False},
    "binary": {"module": "binary-fingerprint", "authorized": False},
    "memory": {"module": "memory-artifact-triage", "authorized": True},
    "cloud": {"module": "cloud-evidence-review", "authorized": True},
    "ioc": {"module": "artifact-inspector", "authorized": False},
    "logs": {"module": "log-correlation", "authorized": False},
}


def _run_path(workspace: Path, run_id: str) -> Path:
    return workspace / "pipeline-runs" / f"{run_id}.json"


def list_runs(workspace: Path, *, limit: int = 50) -> list[dict[str, Any]]:
    root = workspace / "pipeline-runs"
    if not root.exists():
        return []
    runs: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json"), reverse=True)[:limit]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                runs.append(payload)
        except (OSError, json.JSONDecodeError):
            continue
    return runs


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"pipeline manifest not found: {path}")
    if path.stat().st_size > 256 * 1024:
        raise ValueError("pipeline manifest exceeds 256 KiB")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return validate_manifest(payload)


def validate_manifest(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("pipeline manifest must be a JSON object")  # noqa: TRY004 - invalid JSON value
    allowed = {"name", "steps", "fail_fast"}
    if set(payload) - allowed:
        raise ValueError(f"unknown pipeline fields: {', '.join(sorted(set(payload) - allowed))}")
    name = payload.get("name")
    steps = payload.get("steps")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError("pipeline name must be between 1 and 100 characters")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise ValueError(f"pipeline must contain between 1 and {MAX_STEPS} steps")
    normalized: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, raw in enumerate(steps, start=1):
        if not isinstance(raw, dict) or set(raw) - {"id", "workflow", "path", "paths"}:
            raise ValueError(f"pipeline step {index} has invalid fields")
        workflow = raw.get("workflow")
        step_id = raw.get("id", f"step-{index}")
        if workflow not in WORKFLOWS:
            raise ValueError(f"pipeline step {index} has unsupported workflow: {workflow}")
        if not isinstance(step_id, str) or not step_id.replace("-", "").replace("_", "").isalnum() or len(step_id) > 64 or step_id in ids:
            raise ValueError(f"pipeline step {index} has an invalid or duplicate id")
        ids.add(step_id)
        if workflow == "logs":
            values = raw.get("paths")
            if not isinstance(values, list) or not 1 <= len(values) <= 20 or not all(isinstance(value, str) and value for value in values):
                raise ValueError(f"pipeline step {step_id} requires paths")
            normalized.append({"id": step_id, "workflow": workflow, "paths": values})
        else:
            value = raw.get("path")
            if not isinstance(value, str) or not value:
                raise ValueError(f"pipeline step {step_id} requires path")
            normalized.append({"id": step_id, "workflow": workflow, "path": value})
    return {"name": name.strip(), "fail_fast": payload.get("fail_fast", True) is not False, "steps": normalized}


def _resolve(value: str, base: Path, artifact_root: Path | None) -> Path:
    if artifact_root is not None:
        if Path(value).name != value:
            raise ValueError("dashboard pipeline inputs must be uploaded artifact names")
        candidate = (artifact_root / value).resolve()
        if candidate.parent != artifact_root.resolve() or not candidate.is_file():
            raise ValueError(f"uploaded artifact not found: {value}")
        return candidate
    candidate = Path(value)
    return (base / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()


def _execute_step(workspace: Path, step: dict[str, Any], base: Path, artifact_root: Path | None) -> tuple[dict[str, Any], Path, str]:
    workflow = step["workflow"]
    if workflow == "logs":
        paths = [_resolve(value, base, artifact_root) for value in step["paths"]]
        evidence, title = correlate(paths), "Pipeline log correlation"
    else:
        path = _resolve(step["path"], base, artifact_root)
        if workflow == "inspect":
            evidence, title = inspect_file(path), "Pipeline artifact inspection"
        elif workflow == "binary":
            evidence, title = binary_security_profile(path), "Pipeline binary security profile"
        elif workflow == "memory":
            evidence, title = memory_artifact_scan(path), "Pipeline memory artifact triage"
        elif workflow == "cloud":
            evidence, title = cloud_export_review(path), "Pipeline cloud posture review"
        else:
            indicators = extract_iocs(workspace, path)
            evidence = {"path": str(path), "indicator_count": len(indicators), "indicators": indicators}
            title = "Pipeline IOC extraction"
    report = write_report(workspace, title, evidence)
    severity = "medium" if workflow == "cloud" and evidence.get("finding_count") else "info"
    add(workspace, title, report, severity)
    return evidence, report, title


def run_pipeline(
    workspace: Path,
    manifest: dict[str, Any],
    *,
    base: Path | None = None,
    artifact_root: Path | None = None,
    authorized: bool = False,
) -> dict[str, Any]:
    manifest = validate_manifest(manifest)
    active = installed(workspace)
    run_id = datetime.now(UTC).strftime("run-%Y%m%dT%H%M%S%fZ")
    started = datetime.now(UTC).isoformat()
    result: dict[str, Any] = {"id": run_id, "name": manifest["name"], "status": "running", "started_at": started, "completed_at": None, "steps": []}
    record(workspace, "pipeline.started", run_id=run_id, name=manifest["name"], step_count=len(manifest["steps"]))
    for step in manifest["steps"]:
        definition = WORKFLOWS[step["workflow"]]
        step_result: dict[str, Any] = {"id": step["id"], "workflow": step["workflow"], "status": "running"}
        result["steps"].append(step_result)
        try:
            if definition["module"] not in active:
                raise PermissionError(f"install the {definition['module']} module before running {step['workflow']}")
            if definition["authorized"] and not authorized:
                raise PermissionError(f"pipeline workflow {step['workflow']} requires authorization confirmation")
            evidence, report, _title = _execute_step(workspace, step, base or Path.cwd(), artifact_root)
            step_result.update({"status": "completed", "report": str(report), "summary": _summarize(step["workflow"], evidence)})
            record(workspace, "pipeline.step_completed", run_id=run_id, step_id=step["id"], workflow=step["workflow"], report=str(report))
        except (FileNotFoundError, PermissionError, RuntimeError, ValueError, OSError, json.JSONDecodeError) as exc:
            step_result.update({"status": "failed", "error": str(exc)})
            result["status"] = "failed"
            record(workspace, "pipeline.step_failed", run_id=run_id, step_id=step["id"], workflow=step["workflow"], error=str(exc))
            if manifest["fail_fast"]:
                break
    if result["status"] == "running":
        result["status"] = "completed" if all(step["status"] == "completed" for step in result["steps"]) else "failed"
    result["completed_at"] = datetime.now(UTC).isoformat()
    atomic_write_text(_run_path(workspace, run_id), json.dumps(result, indent=2, sort_keys=True) + "\n")
    record(workspace, "pipeline.completed", run_id=run_id, status=result["status"], completed_steps=sum(step["status"] == "completed" for step in result["steps"]))
    return result


def _summarize(workflow: str, evidence: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "inspect": ("size_bytes", "sha256", "format_hints"),
        "binary": ("format", "risk_score", "entropy", "suspicious_capabilities"),
        "memory": ("bytes_examined", "sha256", "urls", "ipv4_addresses", "domains", "email_addresses"),
        "cloud": ("finding_count", "truncated"),
        "ioc": ("indicator_count",),
        "logs": ("event_count", "truncated"),
    }[workflow]
    return {key: evidence[key] for key in keys if key in evidence}
