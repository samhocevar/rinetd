#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -x upstream/rinetd ]] || { echo 'FAIL: upstream/rinetd missing'; exit 1; }
python3 -m pytest -q -rs tests
if [[ "${RINETD_FINAL_ACCEPTANCE:-0}" != "1" ]]; then
 echo 'Foundation tests passed. Full release acceptance pending. See docs/RC1-STATUS.md'
 exit 0
fi
echo 'Full acceptance has NOT been automated: cannot promote release.' >&2
exit 1
