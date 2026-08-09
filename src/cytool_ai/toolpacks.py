"""Verified, opt-in acquisition of non-executable tool-pack archives."""

from __future__ import annotations

import hashlib
import json
import shutil
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_ARCHIVE_BYTES = 100 * 1024 * 1024


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
    if set(data) != required:
        raise ValueError(f"manifest fields must be exactly: {', '.join(sorted(required))}")
    pack = ToolPack(**data)
    if not pack.id.replace("-", "").isalnum() or len(pack.sha256) != 64:
        raise ValueError("tool-pack id or SHA-256 is invalid")
    parsed = urllib.parse.urlparse(pack.source)
    if parsed.scheme not in {"https", "file"}:
        raise ValueError("tool-pack source must use https:// or file://")
    active = registered(workspace)
    active[pack.id] = pack
    _registry_path(workspace).write_text(json.dumps({key: asdict(value) for key, value in active.items()}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pack


def fetch(workspace: Path, pack_id: str) -> Path:
    pack = registered(workspace).get(pack_id)
    if pack is None:
        raise KeyError(f"tool pack is not registered: {pack_id}")
    destination_dir = workspace / "toolpacks" / pack.id / pack.version
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / "archive.bin"
    digest = hashlib.sha256()
    written = 0
    try:
        with urllib.request.urlopen(pack.source, timeout=30) as source, destination.open("wb") as target:  # noqa: S310 - source is explicitly registered
            while chunk := source.read(64 * 1024):
                written += len(chunk)
                if written > MAX_ARCHIVE_BYTES:
                    raise ValueError("tool pack exceeds the 100 MiB download limit")
                digest.update(chunk)
                target.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if digest.hexdigest().lower() != pack.sha256.lower():
        destination.unlink(missing_ok=True)
        raise ValueError("SHA-256 verification failed; archive was discarded")
    (destination_dir / "manifest.json").write_text(json.dumps(asdict(pack), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def remove_cached(workspace: Path, pack_id: str) -> None:
    target = workspace / "toolpacks" / pack_id
    if target.exists():
        shutil.rmtree(target)
