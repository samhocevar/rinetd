# rinetd-ng 1.0 RC2 — Engineering candidate

This is **not** a final release. The RC2 package extends the Rocky/Ubuntu unified installer with:

- `./install.sh --test-resilience` — sustained TCP echoes using local sockets; no production service change.
- `./install.sh --check-release` — fail-closed release gate, including explicitly tracked blockers.
- `./tools/build-sanitized.sh` — separate ASan/UBSan build (not run automatically).
- `./tools/build-deb.sh` — experimental Debian package generator (not platform certified).
- Existing RPM spec is a draft, not a validated package.

Known blockers: actual transactional reload with rollback, preservation of long-lived TCP flows on reload, ASan/UBSan tests, Rocky 8/9 and Ubuntu 22.04/24.04/26.04 certification. The version label is a development designation, not a claim of release readiness.

> The package does not bundle the original upstream source. First build requires Git network access to the pinned commit. Preserve attribution and GNU GPL-2.0-or-later notices.
