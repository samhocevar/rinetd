#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$ROOT/upstream/src/rinetd.c" ]] || { echo 'Missing upstream; run ./install.sh --build-only first' >&2; exit 2; }
# A separate copy avoids corrupting the normal binary and working tree.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/upstream" "$TMP/upstream"
cd "$TMP/upstream"
make distclean >/dev/null 2>&1 || true
./bootstrap
CFLAGS='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' ./configure --prefix=/usr
make -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
[[ -x rinetd ]] || { echo 'Sanitized build did not create binary' >&2; exit 1; }
mkdir -p "$ROOT/build"
cp rinetd "$ROOT/build/rinetd-sanitized"
echo 'Sanitized binary: build/rinetd-sanitized'
echo 'Run ASAN_OPTIONS=detect_leaks=1 with local integration tests before any release.'
