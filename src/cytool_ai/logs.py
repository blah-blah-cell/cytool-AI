"""Small, offline log correlation for user-provided text files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


TIMESTAMP = re.compile(r"\b(20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)")


def correlate(paths: list[Path], *, limit: int = 1000) -> dict[str, Any]:
    events: list[dict[str, str]] = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"log file not found: {path}")
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = TIMESTAMP.search(line)
            events.append({
                "timestamp": match.group(1) if match else "unknown",
                "source": str(path.resolve()),
                "line": str(line_number),
                "message": line[:2000],
            })
    events.sort(key=lambda event: (event["timestamp"] == "unknown", event["timestamp"], event["source"], event["line"]))
    return {"sources": [str(path.resolve()) for path in paths], "event_count": len(events), "events": events[:limit], "truncated": len(events) > limit}
