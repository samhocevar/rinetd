#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$ROOT/upstream/src/rinetd.c" ]] || { echo 'Run tools/import-upstream.sh first' >&2; exit 1; }
python3 "$ROOT/tools/patch-engine.py"
python3 "$ROOT/tools/patch-select-wakeup.py"
cd "$ROOT/upstream"
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc
make -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
[[ -x "$ROOT/upstream/rinetd" ]] || { echo 'ERROR: expected upstream/rinetd' >&2; exit 1; }
echo 'Build OK: upstream/rinetd'
