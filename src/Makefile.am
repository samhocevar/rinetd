
EXTRA_DIST = parse.peg getopt.c getopt.h

sbin_PROGRAMS = ../rinetd
___rinetd_SOURCES = rinetd.c rinetd.h \
                    parse.c parse.h \
                    match.c match.h \
                    net.c net.h \
                    types.h

BUILT_SOURCES = parse.c

# If peg/leg is available, regenerate parse.h
parse.c: parse.peg
	if which leg >/dev/null 2>&1; then leg -o $@ $^; else touch $@; fi

# _POSIX_C_SOURCE is for SA_RESTART and others
# _DARWIN_C_SOURCE is for NI_MAXHOST on OS X
# _XOPEN_SOURCE is for struct sigaction
# _GNU_SOURCE is for h_errno and gethostbyname-related macros
___rinetd_CFLAGS = -std=c99 -D_POSIX_C_SOURCE=200809L \
                   -D_XOPEN_SOURCE -D_GNU_SOURCE -D_DARWIN_C_SOURCE \
                   -Wall -Wextra -Wwrite-strings

