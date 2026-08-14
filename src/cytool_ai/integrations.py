"""Discovery of optional, operator-installed defensive analysis tools."""

from __future__ import annotations

import shutil
from typing import Any

TOOLS = {
    "readelf": "ELF metadata parser",
    "objdump": "binary inspection utility",
    "rabin2": "radare2 binary metadata utility",
    "r2": "radare2 interactive reverse-engineering utility",
    "vol": "Volatility memory-forensics launcher",
    "yara": "pattern matching utility",
}


def discover() -> list[dict[str, Any]]:
    return [{"command": command, "purpose": purpose, "available": shutil.which(command) is not None} for command, purpose in TOOLS.items()]
