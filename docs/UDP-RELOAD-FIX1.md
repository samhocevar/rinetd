# UDP reload stabilization candidate — not transactional

The previous reload closed UDP listener sockets but left live virtual UDP
sessions referencing the old listening file descriptor. Linux may recycle
that descriptor when a replacement listener is created.

This patch invalidates virtual UDP sessions before closing old listeners:
it closes only each session's private outbound socket, clears references
to the shared inbound UDP listener, and lets incoming datagrams construct
fresh sessions after reload. Existing TCP flows are not explicitly closed.

**Limitations:** the active UDP sessions are discarded on reload; the
reload is still destructive, not atomic, and invalid configuration can
terminate the service. No rollback or preservation of UDP session state
is claimed. UDP timeouts and concurrent reloads still require testing.

On Rocky, rebuild and run:

    ./tools/build.sh
    RINETD_RELOAD_CYCLES=20 ./tools/reload-lab-test.sh
    RINETD_RELOAD_CYCLES=100 ./tools/reload-lab-test.sh
    python3 -m pytest -q tests

Do not restart the production service before these tests pass. The tests
exercise only local forwarding, not the production ruleset.
