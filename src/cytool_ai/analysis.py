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
MAX_STRING_SAMPLE_BYTES = 16 * 1024 * 1024


def inspect_file(path: Path, *, string_limit: int = 40) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"evidence file not found: {path}")
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    sample = bytearray()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            if len(sample) < MAX_STRING_SAMPLE_BYTES:
                sample.extend(chunk[:MAX_STRING_SAMPLE_BYTES - len(sample)])
    data = bytes(sample)
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
    matches = PRINTABLE.findall(data)
    strings = [match.decode("utf-8", errors="replace") for match in matches[:string_limit]]
    return {
        "path": str(path.resolve()),
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "format_hints": hints,
        "strings": strings,
        "string_sample_bytes": len(data),
        "truncated_strings": size > len(data) or len(matches) > string_limit,
    }
