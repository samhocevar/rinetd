#!/usr/bin/env bash
set -euo pipefail
UPSTREAM=https://github.com/samhocevar/rinetd.git
COMMIT=d4e0a60119a575b851d6b5e6268491f432d91089
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -e "$ROOT/upstream" ]]; then echo 'ERROR: upstream/ exists; refusing to overwrite' >&2; exit 1; fi
command -v git >/dev/null || { echo 'ERROR: git required' >&2; exit 1; }
git clone "$UPSTREAM" "$ROOT/upstream"
git -C "$ROOT/upstream" checkout --detach "$COMMIT"
ACTUAL="$(git -C "$ROOT/upstream" rev-parse HEAD)"
[[ "$ACTUAL" == "$COMMIT" ]] || { echo 'ERROR: commit mismatch' >&2; exit 1; }
echo "Pinned upstream at $COMMIT"
