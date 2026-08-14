# Changelog

## 1.0.0 — 2026-08-14

- Declared the implemented local-first defensive scope stable.
- Removed the no-op generic execution command and unimplemented runner profiles;
  every advertised module now maps to a concrete CLI and dashboard workflow.
- Added live HTTP integration coverage for the dashboard, module installation,
  artifact inspection, IOC analysis, exports, and compatibility-endpoint auth.
- Hardened dashboard Host/Origin validation, browser response headers, provider
  configuration, compatibility request limits, and upstream response parsing.
- Added streaming artifact hashing, bounded evidence parsing, safe upload names,
  and atomic path-safe tool-pack downloads.
- Added package metadata and explicit Python 3.11–3.13 support classifiers.

## 0.2.0 — 2026-08-12

- Local operations dashboard with module installation, artifact inspection,
  offline analysis, log correlation, scope-bound web evidence, local RE tools,
  and optional AI assistance.
- Workspace reports, audit trail, findings, IOC/STIX/SARIF exports, diagnostics,
  and portable backups.
- Integrity-verified tool-pack acquisition and optional local RE/DFIR adapters.
- Added automated test coverage, package-data checks, and CI.

## 0.1.0

- Initial local-first CLI, workspace, module registry, and audit foundation.
