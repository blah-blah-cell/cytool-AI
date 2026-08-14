"""Small, offline log correlation for user-provided text files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

TIMESTAMP = re.compile(r"\b(20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)")
MAX_TOTAL_LOG_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 100_000


def correlate(paths: list[Path], *, limit: int = 1000) -> dict[str, Any]:
    if not paths:
        raise ValueError("at least one log file is required")
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"log file not found: {path}")
    if sum(path.stat().st_size for path in paths) > MAX_TOTAL_LOG_BYTES:
        raise ValueError("combined log input exceeds the 128 MiB analysis limit")
    events: list[dict[str, str]] = []
    event_cap_reached = False
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            for line_number, line in enumerate(source, start=1):
                if len(events) >= MAX_EVENTS:
                    event_cap_reached = True
                    break
                match = TIMESTAMP.search(line)
                events.append({
                    "timestamp": match.group(1) if match else "unknown",
                    "source": str(path.resolve()),
                    "line": str(line_number),
                    "message": line.rstrip("\r\n")[:2000],
                })
        if event_cap_reached:
            break
    events.sort(key=lambda event: (event["timestamp"] == "unknown", event["timestamp"], event["source"], event["line"]))
    return {"sources": [str(path.resolve()) for path in paths], "event_count": len(events), "events": events[:limit], "truncated": event_cap_reached or len(events) > limit}
