# rinetd-ng 1.0 RC1 acceptance contract

An RC candidate may be promoted to 1.0 final **without rebuilding** only after all gates pass on the same Git commit and binary artifacts. Promotion is a release/tag change, not a code modification. RC1 is not complete yet.

## Required gates
- [ ] Original author notices and GPL-2.0-or-later retained; upstream Git history preserved.
- [ ] Functional atomic config reload on SIGHUP; invalid config leaves previous listeners unchanged.
- [ ] No regression for TCP and UDP forwarding, ACL, IPv4/IPv6 and repeated UDP reload.
- [ ] 100 sequential reloads with active TCP and UDP traffic; no socket leaks or stalls.
- [ ] Active TCP sessions preserved where documented; removed listeners stop accepting new sessions.
- [ ] AddressSanitizer and UBSan tests pass; resource limits and error handling checked.
- [ ] Systemd ExecReload really applies config; install does not unexpectedly start service.
- [ ] Build signed or reproducibly verifiable RPM artifacts for Rocky 8/9/10; clean VM install/upgrade/rollback tests pass.
- [ ] Documentation, license, AUTHORS, CHANGES, and source archives match released commit.
- [ ] Release candidate deployed in lab only; acceptance recorded for all three Rocky versions.

`tools/release-check.sh` checks only the *existing foundation tests*, and intentionally cannot certify the 1.0 final gates above.
