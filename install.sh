#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -r /etc/os-release ]] || { echo 'Unsupported system: /etc/os-release missing' >&2; exit 2; }
. /etc/os-release
FAMILY=''
case "${ID:-}" in
  rocky) FAMILY=rpm ;;
  ubuntu) FAMILY=deb ;;
  *) echo "Unsupported distribution: ${ID:-unknown}. Supported: Rocky Linux 8/9/10, Ubuntu 22.04/24.04/26.04." >&2; exit 2 ;;
esac
case "${ID}:${VERSION_ID}" in
  rocky:8*|rocky:9*|rocky:10*|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "Unsupported OS version: ${PRETTY_NAME:-$ID $VERSION_ID}" >&2; exit 2 ;;
esac
MODE=install
for arg in "$@"; do
 case "$arg" in
  --install) MODE=install ;;
  --build-only) MODE=build ;;
  --test-only) MODE=test ;;
  --test-stress) MODE=stress ;;
  --test-resilience) MODE=resilience ;;
  --check-release) MODE=gate ;;
  --help|-h) echo 'Usage: ./install.sh [--install|--build-only|--test-only|--test-stress|--test-resilience|--check-release]'; exit 0 ;;
  *) echo "Unknown argument: $arg" >&2; exit 2 ;;
 esac
done
if [[ "$MODE" == install && "$EUID" -ne 0 ]]; then
 echo 'Installation requires root. Run: sudo ./install.sh' >&2; exit 2
fi
if [[ "$MODE" != test && "$MODE" != stress && "$MODE" != resilience && "$MODE" != gate ]]; then
  if [[ "$FAMILY" == rpm ]]; then
    if [[ $EUID -eq 0 ]]; then dnf install -y git gcc make autoconf automake python3 python3-pytest; else
      for cmd in git gcc make autoconf automake python3; do command -v "$cmd" >/dev/null || { echo "Missing $cmd (install build dependencies with dnf)" >&2; exit 2; }; done
    fi
  else
    if [[ $EUID -eq 0 ]]; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends git build-essential autoconf automake python3 python3-pytest ca-certificates
    else
      for cmd in git gcc make autoconf automake python3; do command -v "$cmd" >/dev/null || { echo "Missing $cmd (install build dependencies with apt)" >&2; exit 2; }; done
    fi
  fi
  if [[ ! -f "$ROOT/upstream/src/rinetd.c" ]]; then
    "$ROOT/tools/import-upstream.sh"
  fi
  "$ROOT/tools/build.sh"
fi
if [[ "$MODE" == build ]]; then echo 'Build complete. Run ./tools/acceptance-linux.sh'; exit 0; fi
if [[ "$MODE" == test ]]; then exec "$ROOT/tools/acceptance-linux.sh"; fi
if [[ "$MODE" == stress ]]; then exec python3 "$ROOT/tools/stress_tcp.py" --binary "$ROOT/upstream/rinetd"; fi
if [[ "$MODE" == resilience ]]; then exec python3 "$ROOT/tools/resilience_tcp.py" --binary "$ROOT/upstream/rinetd"; fi
if [[ "$MODE" == gate ]]; then exec "$ROOT/tools/release-gate-rc2.sh"; fi
if command -v pytest >/dev/null 2>&1 || python3 -m pytest --version >/dev/null 2>&1; then
 echo 'Running tests, including the live reload tests...'
 "$ROOT/tools/acceptance-linux.sh"
else
 echo 'WARNING: pytest is absent. Install python3-pytest (or a venv with pytest) and run ./install.sh --test-only.' >&2
 echo 'Refusing installation without acceptance tests.' >&2
 exit 3
fi
if getent passwd rinetd >/dev/null; then :; else
 if [[ "$FAMILY" == rpm ]]; then useradd --system --no-create-home --shell /sbin/nologin rinetd; else adduser --system --group --no-create-home --disabled-login rinetd; fi
fi
if ! getent group rinetd >/dev/null; then groupadd -r rinetd; fi
install -Dm0755 "$ROOT/upstream/rinetd" /usr/sbin/rinetd
install -Dm0755 "$ROOT/bin/rinetd-ng-config-check" /usr/libexec/rinetd-ng-config-check
install -Dm0644 "$ROOT/packaging/rinetd-ng.service" /etc/systemd/system/rinetd-ng.service
if [[ ! -e /etc/rinetd.conf ]]; then
 install -Dm0640 -o root -g rinetd "$ROOT/config/rinetd.conf.example" /etc/rinetd.conf
 echo 'Created /etc/rinetd.conf example. Review before starting.'
else
 echo 'Existing /etc/rinetd.conf retained, unchanged.'
fi
systemctl daemon-reload
echo 'Installed, NOT started or restarted. Review config; start with systemctl enable --now rinetd-ng'
