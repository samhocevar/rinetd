#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
: "${RINETD_RELOAD_CYCLES:=100}"
export RINETD_RELOAD_CYCLES RINETD_RUN_RELOAD_TESTS=1
[[ -x upstream/rinetd ]] || { echo 'Build upstream/rinetd first' >&2; exit 1; }
python3 -m pytest -q -rs tests/test_reload_regression.py
