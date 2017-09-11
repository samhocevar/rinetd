
AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src

EXTRA_DIST = bootstrap CHANGES.md README.md index.html \
	$(man_MANS) $(sysconf_DATA)

man_MANS = rinetd.8
sysconf_DATA = rinetd.conf
noinst_DATA = index.html

# This is for Travis CI; we don’t have a testsuite yet.
test:

