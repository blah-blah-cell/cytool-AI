"""Operational diagnostics and portable workspace backups."""

from __future__ import annotations

import json
import platform
import sys
import zipfile
from pathlib import Path
from typing import Any

from .ai import configured
from .integrations import discover
from .modules import installed


def doctor(workspace: Path | None = None) -> dict[str, Any]:
    try:
        provider: dict[str, object] = {"configured": True, "base_url": configured().base_url, "model": configured().model}
    except RuntimeError:
        provider = {"configured": False}
    result: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "provider": provider,
        "integrations": discover(),
    }
    if workspace is not None:
        result["workspace"] = {"path": str(workspace), "installed_modules": sorted(installed(workspace))}
    return result


def backup(workspace: Path, output: Path) -> Path:
    """Create a portable ZIP backup of one workspace, excluding no evidence."""
    output = output.resolve()
    workspace = workspace.resolve()
    if output == workspace or workspace in output.parents:
        raise ValueError("backup output must be outside the workspace")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(workspace.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(workspace))
    return output
