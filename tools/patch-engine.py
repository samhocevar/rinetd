#!/usr/bin/env python3
"""Apply reviewed minimal signal-safety fix to pinned upstream C engine.

Not a transactional reload; explicitly does not claim to solve UDP reload bug.
"""
from pathlib import Path
import sys
p=Path(__file__).resolve().parents[1]/'upstream/src/rinetd.c'
if not p.is_file():
    sys.exit('Missing upstream/src/rinetd.c: run tools/import-upstream.sh')
s=p.read_text()
if 'rinetd_ng_udp_retire_sessions' in s:
    print('UDP reload session fix already applied')
    sys.exit(0)
already_signal_patched = 'rinetd_ng_reload_pending' in s
# When old UDP listening sockets are closed during reload, all virtual UDP
# sessions referencing those sockets must be invalidated first. Otherwise the
# same descriptor may be recycled for the new listener.
udp_anchor='static void clearConfiguration(void) {'
udp_replacement='''static void rinetd_ng_udp_retire_sessions(void)
{
    for (int i = 0; i < coTotal; ++i) {
        ConnectionInfo *cnx = &coInfo[i];
        if (cnx->remote.protocol != IPPROTO_UDP)
            continue;
        /* Remote UDP fd is shared with ServerInfo; do NOT close it here. */
        if (cnx->local.fd != INVALID_SOCKET) {
            closesocket(cnx->local.fd);
            cnx->local.fd = INVALID_SOCKET;
        }
        cnx->remote.fd = INVALID_SOCKET;
        cnx->local.recvPos = cnx->local.sentPos = 0;
        cnx->remote.recvPos = cnx->remote.sentPos = 0;
        cnx->server = NULL;
    }
}

static void clearConfiguration(void) {
    rinetd_ng_udp_retire_sessions();'''
if s.count(udp_anchor) != 1:
    sys.exit('Cannot find clearConfiguration; refusing UDP fix')
s = s.replace(udp_anchor, udp_replacement)

if already_signal_patched:
    p.write_text(s)
    print('Applied UDP session retirement fix to existing signal-safe engine.')
    sys.exit(0)

anchor='static int forked = 0;'
if s.count(anchor)!=1:
    sys.exit('Unexpected upstream layout; refusing patch')
s=s.replace(anchor, anchor+'''\n\n#ifndef _WIN32
/* Signal handlers must not allocate, log, or reconfigure sockets. */
static volatile sig_atomic_t rinetd_ng_reload_pending = 0;
#endif''')
old='''\twhile (1) {
\t\tselectPass();
\t}'''
new='''\twhile (1) {
#ifndef _WIN32
\t\tif (rinetd_ng_reload_pending) {
\t\t\trinetd_ng_reload_pending = 0;
\t\t\tlogInfo("received SIGHUP, reloading configuration...\\n");
\t\t\tclearConfiguration();
\t\t\treadConfiguration(options.conf_file);
\t\t}
#endif
\t\tselectPass();
\t}'''
if s.count(old)!=1:
    sys.exit('Cannot locate event loop; refusing patch')
s=s.replace(old,new)
start=s.index('#if !_WIN32\nRETSIGTYPE hup(int s)')+len('#if !_WIN32\n')
end=s.index('\n#endif /* _WIN32 */',start)
oldfunc=s[start:end]
newfunc='''RETSIGTYPE hup(int s)
{
\t(void)s;
\trinetd_ng_reload_pending = 1;
#if !HAVE_SIGACTION
\tsignal(SIGHUP, hup);
#endif
}'''
s=s[:start]+newfunc+s[end:]
p.write_text(s)
print('Patched SIGHUP handling: flag in signal handler; reload in main loop.')
print('WARNING: reload remains non-transactional; rollback is not implemented.')
