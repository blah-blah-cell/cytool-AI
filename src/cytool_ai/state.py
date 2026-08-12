"""Small atomic persistence helpers for local workspace state."""

from __future__ import annotations

import os
import tempfile
import threading
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_locks: defaultdict[str, threading.RLock] = defaultdict(threading.RLock)


@contextmanager
def workspace_lock(workspace: Path) -> Iterator[None]:
    """Serialize in-process mutations for a workspace."""
    lock = _locks[str(workspace.resolve())]
    with lock:
        yield


def atomic_write_text(path: Path, content: str) -> None:
    """Replace a state file atomically after fully writing its next version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise
