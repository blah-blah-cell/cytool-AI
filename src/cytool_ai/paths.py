"""Filesystem locations for local cytool-AI state."""

from __future__ import annotations

import os
import re
from pathlib import Path

WORKSPACE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def app_home() -> Path:
    """Return the configurable local data directory."""
    configured = os.environ.get("CYTOOL_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".local/share/cytool-ai"


def workspace_path(name: str) -> Path:
    if not WORKSPACE_NAME.fullmatch(name) or name in {".", ".."}:
        raise ValueError("workspace names must be 1–64 safe filename characters")
    return app_home() / "workspaces" / name
