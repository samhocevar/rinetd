
AUTOMAKE_OPTIONS = foreign dist-bzip2

EXTRA_DIST = bootstrap CHANGES index.html \
	getopt.c getopt.h $(man_MANS) $(sysconf_DATA)

man_MANS = rinetd.8
sysconf_DATA = rinetd.conf

sbin_PROGRAMS = rinetd
rinetd_SOURCES = rinetd.c match.c match.h

# _POSIX_C_SOURCE is for SA_RESTART and others
# _XOPEN_SOURCE is for struct sigaction
# _DEFAULT_SOURCE is for h_errno and gethostbyname-related macros
rinetd_CFLAGS = -std=c99 -D_XOPEN_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wwrite-strings -I.

