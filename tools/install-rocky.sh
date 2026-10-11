#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -x "$ROOT/upstream/rinetd" ]] || { echo 'Build first with tools/build.sh' >&2; exit 1; }
getent passwd rinetd >/dev/null || useradd --system --no-create-home --shell /sbin/nologin rinetd
install -D -m 0755 "$ROOT/upstream/rinetd" /usr/sbin/rinetd
install -D -m 0755 "$ROOT/bin/rinetd-ng-config-check" /usr/libexec/rinetd-ng-config-check
install -D -m 0644 "$ROOT/packaging/rinetd-ng.service" /etc/systemd/system/rinetd-ng.service
if [[ ! -e /etc/rinetd.conf ]]; then
  install -m 0640 -o root -g rinetd "$ROOT/config/rinetd.conf.example" /etc/rinetd.conf
fi
systemctl daemon-reload
echo 'Installed but NOT started. Review configuration, ports, SELinux, and systemd sandbox.'
echo 'Start explicitly: systemctl enable --now rinetd-ng'
