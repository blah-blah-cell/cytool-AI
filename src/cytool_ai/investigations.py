"""Defensive, evidence-first investigation workflows.

All functions either read a user-provided local file or make one explicit HTTP
request to a target that the caller has already scope-validated. No samples are
executed and no active vulnerability payloads are sent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import socket
import ssl
import struct
import urllib.error
import urllib.request
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .analysis import inspect_file

ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0xAA64: "AArch64"}
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>]{6,512}")
IP_PATTERN = re.compile(rb"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)")
DOMAIN_PATTERN = re.compile(rb"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
EMAIL_PATTERN = re.compile(rb"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}\b")
WINDOWS_PATH_PATTERN = re.compile(rb"\b[A-Za-z]:\\(?:[^\x00\r\n\\/:*?\"<>|]+\\){0,12}[^\x00\r\n\\/:*?\"<>|]{1,128}")
UNIX_PATH_PATTERN = re.compile(rb"(?<![A-Za-z0-9])/(?:etc|home|opt|root|tmp|usr|var)/(?:[^\x00\s]{1,128})")
MAX_BINARY_METADATA_BYTES = 64 * 1024 * 1024
MAX_CLOUD_EXPORT_BYTES = 32 * 1024 * 1024
MAX_BINARY_PROFILE_BYTES = 16 * 1024 * 1024
CAPABILITY_PATTERNS = {
    "command-shell": (b"powershell", b"cmd.exe", b"/bin/sh", b"/bin/bash"),
    "network-client": (b"curl ", b"wget ", b"winhttp", b"internetopen", b"socket"),
    "process-memory-access": (b"virtualalloc", b"writeprocessmemory", b"createremotethread", b"ptrace"),
    "persistence-indicator": (b"currentversion\\run", b"systemd/system", b"cron.d"),
    "credential-material": (b"authorization: bearer", b"private key-----", b"password="),
}


def binary_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"binary not found: {path}")
    with path.open("rb") as source:
        data = source.read(MAX_BINARY_METADATA_BYTES + 1)
    truncated = len(data) > MAX_BINARY_METADATA_BYTES
    data = data[:MAX_BINARY_METADATA_BYTES]
    result: dict[str, Any] = {"path": str(path.resolve()), "format": "unknown", "details": {}, "bytes_examined": len(data), "input_truncated": truncated}
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        prefix = "<" if endian == "little" else ">"
        machine = struct.unpack(f"{prefix}H", data[18:20])[0] if endian != "unknown" else None
        elf_class = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")
        sections: list[dict[str, object]] = []
        if elf_class == "64-bit" and endian != "unknown" and len(data) >= 64:
            section_offset = struct.unpack(f"{prefix}Q", data[40:48])[0]
            section_size = struct.unpack(f"{prefix}H", data[58:60])[0]
            section_count = struct.unpack(f"{prefix}H", data[60:62])[0]
            for index in range(min(section_count, 512)):
                start = section_offset + index * section_size
                if section_size < 64 or start + section_size > len(data):
                    break
                section_type = struct.unpack(f"{prefix}I", data[start + 4:start + 8])[0]
                address = struct.unpack(f"{prefix}Q", data[start + 16:start + 24])[0]
                size = struct.unpack(f"{prefix}Q", data[start + 32:start + 40])[0]
                sections.append({"index": index, "type": section_type, "address": hex(address), "size": size})
        result.update({"format": "ELF", "details": {"class": elf_class, "endianness": endian, "machine": ELF_MACHINES.get(machine, f"unknown ({machine})"), "sections": sections}})
    elif data.startswith(b"MZ") and len(data) >= 0x40:
        offset = int.from_bytes(data[0x3C:0x40], "little")
        if len(data) >= offset + 6 and data[offset:offset + 4] == b"PE\0\0":
            machine = int.from_bytes(data[offset + 4:offset + 6], "little")
            section_count = int.from_bytes(data[offset + 6:offset + 8], "little")
            optional_size = int.from_bytes(data[offset + 20:offset + 22], "little")
            section_offset = offset + 24 + optional_size
            sections = []
            for index in range(min(section_count, 512)):
                start = section_offset + index * 40
                if start + 40 > len(data):
                    break
                name = data[start:start + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
                sections.append({"index": index, "name": name, "virtual_size": int.from_bytes(data[start + 8:start + 12], "little"), "raw_size": int.from_bytes(data[start + 16:start + 20], "little")})
            result.update({"format": "PE", "details": {"machine": PE_MACHINES.get(machine, f"unknown ({machine:#x})"), "pe_header_offset": offset, "sections": sections}})
    return result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts if count), 4)


def binary_security_profile(path: Path) -> dict[str, Any]:
    """Build an explainable static profile without executing the binary."""
    metadata = binary_metadata(path)
    hashes = inspect_file(path, string_limit=100)
    with path.open("rb") as source:
        data = source.read(MAX_BINARY_PROFILE_BYTES + 1)
    truncated = len(data) > MAX_BINARY_PROFILE_BYTES
    data = data[:MAX_BINARY_PROFILE_BYTES]
    lowered = data.lower()
    capabilities = []
    for capability, patterns in CAPABILITY_PATTERNS.items():
        matches = [pattern.decode("ascii", errors="replace") for pattern in patterns if pattern in lowered]
        if matches:
            capabilities.append({"capability": capability, "matches": matches})
    window_size = 64 * 1024
    high_entropy = []
    for offset in range(0, len(data), window_size):
        value = _entropy(data[offset:offset + window_size])
        if value >= 7.2:
            high_entropy.append({"offset": offset, "size": min(window_size, len(data) - offset), "entropy": value})
    score = min(100, len(capabilities) * 12 + min(len(high_entropy), 5) * 5)
    return {
        **metadata,
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "entropy": _entropy(data),
        "profile_bytes": len(data),
        "profile_truncated": truncated,
        "suspicious_capabilities": capabilities,
        "high_entropy_windows": high_entropy[:20],
        "risk_score": score,
        "risk_note": "Explainable static indicators only; this score is not a malware verdict.",
    }


def memory_artifact_scan(path: Path, *, max_bytes: int = 64 * 1024 * 1024, limit: int = 100) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"memory capture not found: {path}")
    if not 1 <= max_bytes <= 512 * 1024 * 1024:
        raise ValueError("max_bytes must be between 1 byte and 512 MiB")
    collected: dict[str, list[str]] = {"urls": [], "ipv4_addresses": [], "domains": [], "email_addresses": [], "file_paths": []}
    seen = {key: set() for key in collected}
    digest = hashlib.sha256()
    examined = 0
    overlap = b""

    def add(key: str, value: str) -> None:
        if len(collected[key]) < limit and value not in seen[key]:
            seen[key].add(value)
            collected[key].append(value)

    with path.open("rb") as source:
        while examined < max_bytes:
            chunk = source.read(min(1024 * 1024, max_bytes - examined))
            if not chunk:
                break
            examined += len(chunk)
            digest.update(chunk)
            scan = overlap + chunk
            for match in URL_PATTERN.findall(scan):
                add("urls", match.decode("utf-8", errors="replace"))
            for match in IP_PATTERN.findall(scan):
                value = match.decode("ascii")
                try:
                    parsed = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not parsed.is_unspecified:
                    add("ipv4_addresses", value)
            for match in DOMAIN_PATTERN.findall(scan):
                add("domains", match.decode("ascii", errors="ignore").lower())
            for match in EMAIL_PATTERN.findall(scan):
                add("email_addresses", match.decode("utf-8", errors="replace").lower())
            for pattern in (WINDOWS_PATH_PATTERN, UNIX_PATH_PATTERN):
                for match in pattern.findall(scan):
                    add("file_paths", match.decode("utf-8", errors="replace"))
            overlap = scan[-1024:]
    return {
        "path": str(path.resolve()),
        "bytes_examined": examined,
        "sha256": digest.hexdigest(),
        "input_truncated": path.stat().st_size > examined,
        **collected,
        "result_limit": limit,
    }


def tls_evidence(url: str) -> dict[str, Any]:
    """Collect one scoped TLS handshake and peer-certificate summary."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("TLS evidence requires an HTTPS URL")
    port = parsed.port or 443
    context = ssl.create_default_context()
    with socket.create_connection((parsed.hostname, port), timeout=15) as raw, context.wrap_socket(raw, server_hostname=parsed.hostname) as secured:
        certificate = secured.getpeercert()
        certificate_binary = secured.getpeercert(binary_form=True)
        cipher = secured.cipher()
        protocol = secured.version()
    expires_at = None
    days_remaining = None
    if certificate.get("notAfter"):
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), UTC)
        expires_at = expiry.isoformat()
        days_remaining = (expiry - datetime.now(UTC)).days

    def flatten(name: object) -> dict[str, str]:
        result: dict[str, str] = {}
        if isinstance(name, tuple):
            for group in name:
                if isinstance(group, tuple):
                    for item in group:
                        if isinstance(item, tuple) and len(item) == 2:
                            result[str(item[0])] = str(item[1])
        return result

    return {
        "url": url,
        "host": parsed.hostname,
        "port": port,
        "protocol": protocol,
        "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
        "subject": flatten(certificate.get("subject")),
        "issuer": flatten(certificate.get("issuer")),
        "serial_number": certificate.get("serialNumber"),
        "subject_alt_names": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"][:100],
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "certificate_sha256": hashlib.sha256(certificate_binary or b"").hexdigest(),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def web_evidence(url: str) -> dict[str, Any]:
    """Fetch response headers only; redirects remain unvisited for scope safety."""
    request = urllib.request.Request(url, headers={"User-Agent": "cytool-AI/2.0 (authorized evidence review)"}, method="HEAD")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
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


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._active_form: dict[str, object] | None = None
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self._active_form = {"method": (values.get("method") or "get").lower(), "action": values.get("action") or "", "inputs": []}
            self.forms.append(self._active_form)
        elif tag in {"input", "textarea", "select", "button"} and self._active_form is not None:
            inputs = self._active_form["inputs"]
            assert isinstance(inputs, list)
            inputs.append({"name": values.get("name") or "", "type": values.get("type") or tag, "required": "required" in values})
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._active_form = None


def web_input_surface(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    """Retrieve one in-scope page and inventory its declared HTML inputs only."""
    request = urllib.request.Request(url, headers={"User-Agent": "cytool-AI/2.0 (authorized input inventory)"}, method="GET")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(max_bytes + 1)
            status, content_type = response.status, response.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "forms": [], "scripts": [], "error": "HTTP error response; body was not inventoried"}
    if len(body) > max_bytes:
        body = body[:max_bytes]
        truncated = True
    else:
        truncated = False
    parser = _SurfaceParser()
    if content_type in {"text/html", "application/xhtml+xml"}:
        parser.feed(body.decode("utf-8", errors="replace"))
    return {"url": url, "status": status, "content_type": content_type, "forms": parser.forms, "scripts": parser.scripts[:100], "body_truncated": truncated}


def cloud_export_review(path: Path, *, limit: int = 100) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"cloud export not found: {path}")
    if path.stat().st_size > MAX_CLOUD_EXPORT_BYTES:
        raise ValueError("cloud export exceeds the 32 MiB analysis limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError("cloud export is nested too deeply") from exc
    findings: list[dict[str, object]] = []
    risky_pairs = {"public": True, "publicly_accessible": True, "encryption": False, "mfa_enabled": False, "logging": False}

    pending: list[tuple[object, str]] = [(data, "")]
    while pending and len(findings) < limit:
        value, location = pending.pop()
        if isinstance(value, dict):
            for key, child in reversed(list(value.items())):
                normalized = key.lower().replace("-", "_")
                if normalized in risky_pairs and child == risky_pairs[normalized]:
                    findings.append({"path": f"{location}.{key}".lstrip("."), "value": child, "reason": f"{key} is set to {child}"})
                    if len(findings) >= limit:
                        break
                pending.append((child, f"{location}.{key}".lstrip(".")))
        elif isinstance(value, list):
            for index in range(len(value) - 1, -1, -1):
                pending.append((value[index], f"{location}[{index}]"))

    return {"path": str(path.resolve()), "finding_count": len(findings), "findings": findings, "truncated": bool(pending)}
