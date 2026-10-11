# rinetd-ng — select wakeup diagnostic patch

This patch addresses a specific issue in the current experimental engine: SIGHUP only sets a pending flag, while the main loop may wait indefinitely in select() until network activity. It bounds each select wait to 100 ms, and ignores descriptor sets when select() returns <=0 (including EINTR). This is a diagnostic/stabilization change, not transactional reload.

**Known limitations:** repeated wakeups (10/s), UDP sessions intentionally discarded on reload; invalid configurations may still stop the service. Do not deploy to production.

On Rocky:

    cd /software/rinetd-ng
    cp -a upstream/rinetd upstream/rinetd.before-wakeup
    ./tools/build.sh
    python3 rinetd-udp-reload-diagnose.py --binary ./upstream/rinetd --cycles 3 --wait 0.5
    RINETD_RELOAD_CYCLES=20 ./tools/reload-lab-test.sh

If the first test now succeeds, rerun 100 cycles and the full pytest suite. For the final RC replace periodic polling with a self-pipe/eventfd wakeup and transactional reload.
