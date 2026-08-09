"""Local, offline evidence analysis primitives.

These routines only read a path supplied by the operator; they never execute a
sample, connect to a target, or modify source evidence.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def inspect_file(path: Path, *, string_limit: int = 40) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"evidence file not found: {path}")
    data = path.read_bytes()
    hints: list[str] = []
    if data.startswith(b"\x7fELF"):
        hints.append("ELF executable or shared object")
    elif data.startswith(b"MZ"):
        hints.append("PE executable or DLL")
    elif data.startswith(b"\xca\xfe\xba\xbe"):
        hints.append("Mach-O universal binary")
    elif data.startswith(b"PK\x03\x04"):
        hints.append("ZIP-compatible archive")
    else:
        hints.append("unrecognized or generic data")
    strings = [match.decode("utf-8", errors="replace") for match in PRINTABLE.findall(data)[:string_limit]]
    return {
        "path": str(path.resolve()),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "format_hints": hints,
        "strings": strings,
        "truncated_strings": len(PRINTABLE.findall(data)) > string_limit,
    }
