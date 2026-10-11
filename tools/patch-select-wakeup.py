#!/usr/bin/env python3
"""Diagnostic fix: bound select waiting and check interrupted/error return."""
from pathlib import Path
import sys
p=Path(__file__).resolve().parents[1]/'upstream/src/rinetd.c'
s=p.read_text()
needle='select(maxfd + 1, readfds, writefds, 0, timeout.tv_sec ? &timeout : NULL);'
replacement="""/* Temporary bounded wait: check SIGHUP requests at least every 100ms.
     * A future version will use a self-pipe wakeup instead. */
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    int ready = select(maxfd + 1, readfds, writefds, 0, &timeout);
    if (ready <= 0) {
        /* EINTR and errors invalidate the descriptor sets. */
        return;
    }"""
if 'Temporary bounded wait: check SIGHUP requests' in s:
    print('select wakeup diagnostic patch already applied')
    sys.exit(0)
if s.count(needle)!=1:
    sys.exit('Cannot locate select() call; refusing to change code')
if 'rinetd_ng_reload_pending' not in s:
    sys.exit('Missing signal-safe SIGHUP patch: run patch-engine.py first')
p.write_text(s.replace(needle,replacement))
print('select() bounded to 100ms, interrupted select results ignored')
