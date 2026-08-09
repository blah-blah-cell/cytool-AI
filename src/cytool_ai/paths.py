"""Filesystem locations for local cytool-AI state."""

from __future__ import annotations

import os
from pathlib import Path


def app_home() -> Path:
    """Return the configurable local data directory."""
    configured = os.environ.get("CYTOOL_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".local/share/cytool-ai"


def workspace_path(name: str) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("workspace names must be simple directory names")
    return app_home() / "workspaces" / name
