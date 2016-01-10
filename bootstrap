#! /bin/sh

# bootstrap — generic bootstrap/autogen.sh script for autotools projects
#
# Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
#
# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What the Fuck You Want
# to Public License, Version 2, as published by the WTFPL Task Force.
# See http://www.wtfpl.net/ for more details.
#
# The latest version of this script can be found at the following place:
#    http://caca.zoy.org/wiki/build

# Die if an error occurs
set -e

# Guess whether we are using configure.ac or configure.in
if test -f configure.ac; then
  conffile="configure.ac"
elif test -f configure.in; then
  conffile="configure.in"
else
  echo "$0: could not find configure.ac or configure.in"
  exit 1
fi

# Check for needed features
auxdir="`sed -ne 's/^[ \t]*A._CONFIG_AUX_DIR *([[ ]*\([^] )]*\).*/\1/p' $conffile`"
pkgconfig="`grep '^[ \t]*PKG_PROG_PKG_CONFIG' $conffile >/dev/null 2>&1 && echo yes || echo no`"
libtool="`grep '^[ \t]*A._PROG_LIBTOOL' $conffile >/dev/null 2>&1 && echo yes || echo no`"
header="`grep '^[ \t]*A._CONFIG_HEADER' $conffile >/dev/null 2>&1 && echo yes || echo no`"
automake="`grep '^[ \t]*AM_INIT_AUTOMAKE' $conffile >/dev/null 2>&1 && echo yes || echo no`"
aclocalflags="`sed -ne 's/^[ \t]*ACLOCAL_AMFLAGS[ \t]*=//p' Makefile.am 2>/dev/null || :`"

# Check for automake
amvers="no"
for v in "" "-1.15" "-1.14" "-1.13" "-1.12" "-1.11"; do
  if automake${v} --version > /dev/null 2>&1; then
    amvers=${v}
    break
  fi
done

if test "$amvers" = "no"; then
  echo "$0: automake not found"
  exit 1
fi

# Check for autoconf
acvers="no"
for v in "" "259" "253"; do
  if autoconf${v} --version >/dev/null 2>&1; then
    acvers="${v}"
    break
  fi
done

if test "$acvers" = "no"; then
  echo "$0: autoconf not found"
  exit 1
fi

# Check for libtool
if test "$libtool" = "yes"; then
  libtoolize="no"
  if glibtoolize --version >/dev/null 2>&1; then
    libtoolize="glibtoolize"
  else
    for v in "16" "15" "" "14"; do
      if libtoolize${v} --version >/dev/null 2>&1; then
        libtoolize="libtoolize${v}"
        break
      fi
    done
  fi

  if test "$libtoolize" = "no"; then
    echo "$0: libtool not found"
    exit 1
  fi
fi

# Check for pkg-config
if test "$pkgconfig" = "yes"; then
  if ! pkg-config --version >/dev/null 2>&1; then
    echo "$0: pkg-config not found"
    exit 1
  fi
fi

# Remove old cruft
for x in aclocal.m4 configure config.guess config.log config.sub config.cache config.h.in config.h compile libtool.m4 ltoptions.m4 ltsugar.m4 ltversion.m4 ltmain.sh libtool ltconfig missing mkinstalldirs depcomp install-sh; do rm -f $x autotools/$x; if test -n "$auxdir"; then rm -f "$auxdir/$x"; fi; done
rm -Rf autom4te.cache
if test -n "$auxdir"; then
  if test ! -d "$auxdir"; then
    mkdir "$auxdir"
  fi
  aclocalflags="-I $auxdir -I . ${aclocalflags}"
fi

# Honour M4PATH because sometimes M4 doesn't
save_IFS=$IFS
IFS=:
tmp="$M4PATH"
for x in $tmp; do
  if test -n "$x"; then
    aclocalflags="-I $x ${aclocalflags}"
  fi
done
IFS=$save_IFS

# Explain what we are doing from now
set -x

# Bootstrap package
if test "$libtool" = "yes"; then
  ${libtoolize} --copy --force
  if test -n "$auxdir" -a ! "$auxdir" = "." -a -f "ltmain.sh"; then
    echo "$0: working around a minor libtool issue"
    mv ltmain.sh "$auxdir/"
  fi
fi

aclocal${amvers} ${aclocalflags}
autoconf${acvers}
if test "$header" = "yes"; then
  autoheader${acvers}
fi
if test "$automake" = "yes"; then
  #add --include-deps if you want to bootstrap with any other compiler than gcc
  #automake${amvers} --add-missing --copy --include-deps
  automake${amvers} --foreign --add-missing --copy
fi

# Remove cruft that we no longer want
rm -Rf autom4te.cache

