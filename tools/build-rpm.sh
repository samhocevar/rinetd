#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for cmd in rpmbuild tar; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
[[ -f "$ROOT/upstream/COPYING" ]] || { echo 'Import upstream first' >&2; exit 1; }
TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$TOP/package/rinetd-ng-1.0"
tar --exclude=.git --exclude=.pytest_cache --exclude=.venv --exclude='*.pyc' -C "$ROOT" -cf - . | tar -C "$TOP/package/rinetd-ng-1.0" -xf -
tar -czf "$TOP/SOURCES/rinetd-ng-1.0.tar.gz" -C "$TOP/package" rinetd-ng-1.0
cp "$ROOT/packaging/rpm/rinetd-ng.spec" "$TOP/SPECS/"
rpmbuild --define "_topdir $TOP" -ba "$TOP/SPECS/rinetd-ng.spec"
mkdir -p "$ROOT/dist"
find "$TOP/RPMS" "$TOP/SRPMS" -type f -name '*.rpm' -exec cp -v {} "$ROOT/dist/" \;
