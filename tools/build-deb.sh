#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v dpkg-deb >/dev/null || { echo 'dpkg-deb not installed' >&2; exit 2; }
[[ -x "$ROOT/upstream/rinetd" ]] || { echo 'Build binary first' >&2; exit 2; }
ARCH="$(dpkg --print-architecture)"; VER=1.0~rc2; OUT="$ROOT/dist"; STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/sbin" "$STAGE/usr/libexec" "$STAGE/lib/systemd/system" "$STAGE/etc" "$STAGE/usr/share/doc/rinetd-ng"
install -m0755 "$ROOT/upstream/rinetd" "$STAGE/usr/sbin/rinetd"
install -m0755 "$ROOT/bin/rinetd-ng-config-check" "$STAGE/usr/libexec/rinetd-ng-config-check"
install -m0644 "$ROOT/packaging/rinetd-ng.service" "$STAGE/lib/systemd/system/rinetd-ng.service"
install -m0644 "$ROOT/config/rinetd.conf.example" "$STAGE/etc/rinetd.conf"
install -m0644 "$ROOT/README.md" "$STAGE/usr/share/doc/rinetd-ng/README.md"
install -m0644 "$ROOT/upstream/COPYING" "$STAGE/usr/share/doc/rinetd-ng/copyright"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: rinetd-ng
Version: $VER
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: rinetd-ng contributors <noreply@example.invalid>
Depends: libc6
Description: TCP and UDP port redirection daemon, experimental RC2
 Derived from rinetd by Thomas Boutell and Sam Hocevar.
EOF
printf '/etc/rinetd.conf\n' > "$STAGE/DEBIAN/conffiles"
mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/rinetd-ng_${VER}_${ARCH}.deb"
echo 'Package built; NOT certified on Ubuntu yet.'
