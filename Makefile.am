
AUTOMAKE_OPTIONS = foreign dist-bzip2

EXTRA_DIST = bootstrap CHANGES.md README.md index.html \
	getopt.c getopt.h $(man_MANS) $(sysconf_DATA)

man_MANS = rinetd.8
sysconf_DATA = rinetd.conf

sbin_PROGRAMS = rinetd
rinetd_SOURCES = rinetd.c rinetd.h parse.h match.c match.h

BUILT_SOURCES = parse.h

# If peg/leg is available, regenerate parse.h
parse.h: parse.peg
	if which leg >/dev/null 2>&1; then leg -o $@ $^; else touch $@; fi

# _POSIX_C_SOURCE is for SA_RESTART and others
# _XOPEN_SOURCE is for struct sigaction
# _GNU_SOURCE is for h_errno and gethostbyname-related macros
rinetd_CFLAGS = -std=c99 -D_XOPEN_SOURCE -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wwrite-strings -I.

# This is for Travis CI; we don’t have a testsuite yet.
test:

