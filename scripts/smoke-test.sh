#!/usr/bin/env bash
set -euo pipefail

smoke_home="$(mktemp -d)"
trap 'rm -rf "$smoke_home"' EXIT
export CYTOOL_HOME="$smoke_home/state"

cytool init smoke
printf '\177ELFsmoke-evidence' > "$smoke_home/sample.bin"
cytool modules install artifact-inspector --workspace smoke
cytool modules install binary-fingerprint --workspace smoke
cytool inspect "$smoke_home/sample.bin" --workspace smoke
printf '{"name":"Smoke pipeline","steps":[{"workflow":"inspect","path":"sample.bin"},{"workflow":"binary","path":"sample.bin"}]}' > "$smoke_home/pipeline.json"
cytool pipeline run "$smoke_home/pipeline.json" --workspace smoke
cytool pipeline history --workspace smoke
cytool findings --workspace smoke
