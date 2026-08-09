"""Bounded adapters for optional operator-installed RE utilities."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


COMMANDS = {
    "readelf": ["-h", "-S", "--wide"],
    "objdump": ["-x"],
    "rabin2": ["-I", "-S"],
}


def inspect(path: Path, tool: str) -> dict[str, Any]:
    if tool not in COMMANDS:
        raise ValueError(f"unsupported external RE tool: {tool}")
    executable = shutil.which(tool)
    if not executable:
        raise FileNotFoundError(f"{tool} is not installed; run `cytool integrations list`")
    if not path.is_file():
        raise FileNotFoundError(f"sample not found: {path}")
    command = [executable, *COMMANDS[tool], str(path.resolve())]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    return {"tool": tool, "command": command, "returncode": completed.returncode, "stdout": completed.stdout[:200_000], "stderr": completed.stderr[:20_000], "truncated": len(completed.stdout) > 200_000 or len(completed.stderr) > 20_000}
