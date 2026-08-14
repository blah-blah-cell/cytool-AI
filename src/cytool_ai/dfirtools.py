"""Bounded, offline adapters for operator-installed DFIR tools."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

VOLATILITY_PLUGINS = {"windows.info", "windows.pslist", "windows.netscan", "linux.pslist", "linux.netstat"}


def yara_scan(rules: Path, target: Path) -> dict[str, Any]:
    executable = shutil.which("yara")
    if not executable:
        raise FileNotFoundError("yara is not installed; run `cytool integrations list`")
    if not rules.is_file() or not target.is_file():
        raise FileNotFoundError("rules and target must both be regular files")
    completed = subprocess.run([executable, "--no-warnings", str(rules.resolve()), str(target.resolve())], text=True, capture_output=True, timeout=60, check=False)
    return {"tool": "yara", "returncode": completed.returncode, "matches": completed.stdout[:200_000], "stderr": completed.stderr[:20_000]}


def volatility(image: Path, plugin: str) -> dict[str, Any]:
    executable = shutil.which("vol")
    if not executable:
        raise FileNotFoundError("Volatility (`vol`) is not installed; run `cytool integrations list`")
    if plugin not in VOLATILITY_PLUGINS:
        raise ValueError(f"plugin must be one of: {', '.join(sorted(VOLATILITY_PLUGINS))}")
    if not image.is_file():
        raise FileNotFoundError(f"memory image not found: {image}")
    completed = subprocess.run([executable, "-f", str(image.resolve()), plugin, "--output", "json"], text=True, capture_output=True, timeout=180, check=False)
    return {"tool": "volatility", "plugin": plugin, "returncode": completed.returncode, "stdout": completed.stdout[:500_000], "stderr": completed.stderr[:20_000], "truncated": len(completed.stdout) > 500_000}
