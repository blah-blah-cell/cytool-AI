"""Safe handling of evidence uploaded into a workspace."""

from __future__ import annotations

from pathlib import Path

from .analysis import inspect_file
from .audit import record
from .findings import add
from .reports import write_report
from .state import workspace_lock


MAX_UPLOAD_BYTES = 100 * 1024 * 1024


def store_upload(workspace: Path, filename: str, data: bytes) -> Path:
    """Store user-provided evidence without executing it."""
    safe_name = Path(filename).name.strip() or "uploaded-artifact.bin"
    if safe_name in {".", ".."}:
        raise ValueError("invalid artifact filename")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("artifact exceeds the 100 MiB upload limit")
    with workspace_lock(workspace):
        destination = workspace / "artifacts" / safe_name
        if destination.exists():
            stem, suffix = destination.stem, destination.suffix
            index = 2
            while destination.exists():
                destination = workspace / "artifacts" / f"{stem}-{index}{suffix}"
                index += 1
        destination.write_bytes(data)
    return destination


def inspect_upload(workspace: Path, filename: str, data: bytes) -> dict[str, object]:
    """Store and inspect an uploaded artifact without executing it."""
    destination = store_upload(workspace, filename, data)
    evidence = inspect_file(destination)
    report = write_report(workspace, "Uploaded artifact inspection", evidence)
    add(workspace, "Uploaded artifact inspection", report)
    record(workspace, "artifact.uploaded_and_inspected", filename=destination.name, sha256=evidence["sha256"], size_bytes=len(data))
    return {"artifact": str(destination), "evidence": evidence, "report": str(report)}
