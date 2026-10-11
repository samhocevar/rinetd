#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -x upstream/rinetd ]] || { echo 'Missing upstream/rinetd. Run ./install.sh --build-only first.' >&2; exit 2; }
python3 -m pytest -q tests -rs
RINETD_RUN_RELOAD_TESTS=1 RINETD_RELOAD_CYCLES="${RINETD_RELOAD_CYCLES:-100}" python3 -m pytest -q tests/test_reload_regression.py tests/test_reload_semantics.py -rs
