"""Verified, opt-in acquisition of non-executable tool-pack archives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from .state import atomic_write_text, workspace_lock

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SHA256 = re.compile(r"[A-Fa-f0-9]{64}")


@dataclass(frozen=True)
class ToolPack:
    id: str
    name: str
    summary: str
    version: str
    source: str
    sha256: str


def _registry_path(workspace: Path) -> Path:
    return workspace / "toolpacks.json"


def registered(workspace: Path) -> dict[str, ToolPack]:
    path = _registry_path(workspace)
    if not path.exists():
        return {}
    return {pack_id: ToolPack(**data) for pack_id, data in json.loads(path.read_text(encoding="utf-8")).items()}


def register(workspace: Path, manifest_path: Path) -> ToolPack:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    required = {"id", "name", "summary", "version", "source", "sha256"}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError(f"manifest fields must be exactly: {', '.join(sorted(required))}")
    if not all(isinstance(data[field], str) for field in required):
        raise ValueError("all tool-pack manifest fields must be strings")
    pack = ToolPack(**data)
    if not IDENTIFIER.fullmatch(pack.id) or not IDENTIFIER.fullmatch(pack.version):
        raise ValueError("tool-pack id and version must be safe identifiers")
    if not SHA256.fullmatch(pack.sha256):
        raise ValueError("tool-pack SHA-256 is invalid")
    if not all(value.strip() for value in (pack.name, pack.summary)):
        raise ValueError("tool-pack name and summary are required")
    parsed = urllib.parse.urlparse(pack.source)
    if parsed.scheme not in {"https", "file"} or (parsed.scheme == "https" and not parsed.hostname):
        raise ValueError("tool-pack source must use https:// or file://")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("tool-pack source must not contain credentials or a fragment")
    with workspace_lock(workspace):
        active = registered(workspace)
        active[pack.id] = pack
        atomic_write_text(_registry_path(workspace), json.dumps({key: asdict(value) for key, value in active.items()}, indent=2, sort_keys=True) + "\n")
    return pack


def fetch(workspace: Path, pack_id: str) -> Path:
    pack = registered(workspace).get(pack_id)
    if pack is None:
        raise KeyError(f"tool pack is not registered: {pack_id}")
    destination_dir = workspace / "toolpacks" / pack.id / pack.version
    destination_dir.mkdir(parents=True, exist_ok=True)
    if workspace.resolve() not in destination_dir.resolve().parents:
        raise PermissionError("tool-pack destination escapes the workspace")
    destination = destination_dir / "archive.bin"
    digest = hashlib.sha256()
    written = 0
    descriptor, temporary_name = tempfile.mkstemp(prefix=".archive.", dir=destination_dir)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target, urllib.request.urlopen(pack.source, timeout=30) as source:
            final_scheme = urllib.parse.urlparse(source.geturl()).scheme
            if final_scheme not in {"https", "file"}:
                raise ValueError("tool-pack download redirected to an unsafe protocol")
            while chunk := source.read(64 * 1024):
                written += len(chunk)
                if written > MAX_ARCHIVE_BYTES:
                    raise ValueError("tool pack exceeds the 100 MiB download limit")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if digest.hexdigest().lower() != pack.sha256.lower():
            raise ValueError("SHA-256 verification failed; archive was discarded")
        with workspace_lock(workspace):
            os.replace(temporary, destination)
            atomic_write_text(destination_dir / "manifest.json", json.dumps(asdict(pack), indent=2, sort_keys=True) + "\n")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return destination
