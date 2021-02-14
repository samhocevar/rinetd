
AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src

EXTRA_DIST = bootstrap COPYING CHANGES.md README.md index.html rinetd.vcxproj \
	$(man_MANS) $(sysconf_DATA)

man_MANS = rinetd.8
sysconf_DATA = rinetd.conf
noinst_DATA = index.html

# If roffit is available, regenerate index.html
index.html: rinetd.8
	if which roffit >/dev/null 2>&1; then roffit < $^ > $@; else touch $@; fi

# This is for Travis CI; we don’t have a testsuite yet.
test:

