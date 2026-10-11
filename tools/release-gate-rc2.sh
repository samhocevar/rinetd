#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
./tools/acceptance-linux.sh
if [[ "${RINETD_RUN_RESILIENCE:-0}" == 1 ]]; then
 python3 tools/resilience_tcp.py --binary ./upstream/rinetd --connections "${RINETD_RESILIENCE_CONNECTIONS:-100}" --duration "${RINETD_RESILIENCE_DURATION:-60}" --output resilience-results.json
else
 echo 'BLOCKER: resilience test not explicitly run (RINETD_RUN_RESILIENCE=1)' >&2
 exit 4
fi
# Release gate must fail closed: the core reload implementation is not transactional.
echo 'BLOCKER: atomic reload/rollback implementation and verification are outstanding.' >&2
exit 5
