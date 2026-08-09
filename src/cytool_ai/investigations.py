"""Defensive, evidence-first investigation workflows.

All functions either read a user-provided local file or make one explicit HTTP
request to a target that the caller has already scope-validated. No samples are
executed and no active vulnerability payloads are sent.
"""

from __future__ import annotations

import ipaddress
import json
import re
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0xAA64: "AArch64"}
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]{6,512}")
IP_PATTERN = re.compile(rb"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)")


def binary_metadata(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {"path": str(path.resolve()), "format": "unknown", "details": {}}
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        prefix = "<" if endian == "little" else ">"
        machine = struct.unpack(f"{prefix}H", data[18:20])[0] if endian != "unknown" else None
        result.update({"format": "ELF", "details": {"class": {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown"), "endianness": endian, "machine": ELF_MACHINES.get(machine, f"unknown ({machine})")}})
    elif data.startswith(b"MZ") and len(data) >= 0x40:
        offset = int.from_bytes(data[0x3C:0x40], "little")
        if len(data) >= offset + 6 and data[offset:offset + 4] == b"PE\0\0":
            machine = int.from_bytes(data[offset + 4:offset + 6], "little")
            result.update({"format": "PE", "details": {"machine": PE_MACHINES.get(machine, f"unknown ({machine:#x})"), "pe_header_offset": offset}})
    return result


def memory_artifact_scan(path: Path, *, max_bytes: int = 64 * 1024 * 1024, limit: int = 100) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"memory capture not found: {path}")
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    urls = [match.decode("utf-8", errors="replace") for match in URL_PATTERN.findall(data)[:limit]]
    ips: list[str] = []
    for match in IP_PATTERN.findall(data):
        value = match.decode("ascii")
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not parsed.is_unspecified and value not in ips:
            ips.append(value)
    return {"path": str(path.resolve()), "bytes_examined": len(data), "input_truncated": truncated, "urls": urls, "ipv4_addresses": ips[:limit], "result_limit": limit}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def web_evidence(url: str) -> dict[str, Any]:
    """Fetch response headers only; redirects remain unvisited for scope safety."""
    request = urllib.request.Request(url, headers={"User-Agent": "cytool-AI/0.1 (authorized evidence review)"}, method="HEAD")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:  # noqa: S310 - caller validates target scope
            headers = dict(response.headers.items())
            status = response.status
    except urllib.error.HTTPError as exc:
        headers, status = dict(exc.headers.items()), exc.code
    lower = {key.lower(): value for key, value in headers.items()}
    recommended = {
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "strict-transport-security": "Strict-Transport-Security",
    }
    return {"url": url, "status": status, "headers": headers, "missing_recommended_headers": [label for key, label in recommended.items() if key not in lower]}


def cloud_export_review(path: Path, *, limit: int = 100) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[dict[str, object]] = []
    risky_pairs = {"public": True, "publicly_accessible": True, "encryption": False, "mfa_enabled": False, "logging": False}

    def walk(value: object, location: str) -> None:
        if len(findings) >= limit:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = key.lower().replace("-", "_")
                if normalized in risky_pairs and child == risky_pairs[normalized]:
                    findings.append({"path": f"{location}.{key}".lstrip("."), "value": child, "reason": f"{key} is set to {child}"})
                walk(child, f"{location}.{key}".lstrip("."))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}[{index}]")

    walk(data, "")
    return {"path": str(path.resolve()), "finding_count": len(findings), "findings": findings, "truncated": len(findings) >= limit}
