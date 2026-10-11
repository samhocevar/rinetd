# RC1 implementation status — 2026-10-08

This package is **not a completed release candidate**. It contains deployable foundation and development changes, but must not be promoted to 1.0 final.

Implemented in development overlay:
- Original rinetd 2021 upstream pinned by importer; no source bundled because fetching upstream from this environment failed.
- Signal handler safety patch: SIGHUP handler sets `sig_atomic_t` only, and the main loop executes reload outside signal context.
- RPM spec and local build wrapper (not tested on Rocky).
- systemd unit no longer falsely exposes validation-only `ExecReload`.
- Existing TCP/UDP forwarding tests plus basic packaging regression tests.

**Not implemented**:
- Transactional/atomic reload with validation and rollback. Upstream's destructive reload still occurs.
- Preservation guarantee for existing UDP sessions or active listeners.
- Fix for repeated UDP reload bug.
- 100-reload stress suite, ASan/UBSan validation, clean Rocky 8/9/10 RPM test matrix.

Do not enable reload via `systemctl reload`; use controlled restarts in the lab. The `patch-engine.py` script is deliberately conservative and refuses unknown upstream structures; keep a backup of the baseline before trying it. Treat C patch as uncompiled and unverified until built and tested against imported upstream.

Additional regression coverage:
- `tools/reload-lab-test.sh` runs an opt-in **100 consecutive UDP SIGHUP reload** live socket test against the compiled engine, deliberately outside routine acceptance until the reload defect is resolved.
- A test failure is evidence of an issue to investigate; a pass alone is not proof of transactional reload, session preservation, or production readiness.
