#!/usr/bin/env bash
set -euo pipefail

smoke_home="$(mktemp -d)"
trap 'rm -rf "$smoke_home"' EXIT
export CYTOOL_HOME="$smoke_home/state"

cytool init smoke
printf '\177ELFsmoke-evidence' > "$smoke_home/sample.bin"
cytool modules install artifact-inspector --workspace smoke
cytool inspect "$smoke_home/sample.bin" --workspace smoke
cytool findings --workspace smoke
