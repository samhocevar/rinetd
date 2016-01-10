# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.52)
AC_INIT(rinetd, 0.62, sam@hocevar.net)
AC_CONFIG_AUX_DIR(.auto)
AC_CONFIG_SRCDIR([getopt.h])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([no-define tar-ustar silent-rules])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([gethostbyname memset select socket strstr daemon sigaction])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
