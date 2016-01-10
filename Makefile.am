
AUTOMAKE_OPTIONS = foreign dist-bzip2

EXTRA_DIST = bootstrap CHANGES index.html \
	getopt.c getopt.h $(man_MANS) $(sysconf_DATA)

man_MANS = rinetd.8
sysconf_DATA = rinetd.conf

sbin_PROGRAMS = rinetd
rinetd_SOURCES = rinetd.c match.c match.h
rinetd_CFLAGS = -Wall -Wwrite-strings -I.

