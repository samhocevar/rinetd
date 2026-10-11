#!/usr/bin/env bash
# Compatibility entrypoint: installation is unified.
set -euo pipefail
exec "$(cd "$(dirname "$0")/.." && pwd)/install.sh" "$@"
