/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2017 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#if _WIN32
	/* Define this to a reasonably large value */
#	define FD_SETSIZE 4096
#	include <winsock2.h>
#	include <windows.h>
#else
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <netdb.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif

#if defined HAVE_ERRNO_H
#	include <errno.h>
#endif

#if defined HAVE_UNISTD_H
#	include <unistd.h>
#endif

/* We've got to get FIONBIO from somewhere. Try the Solaris location
	if it isn't defined yet by the above includes. */
#ifndef FIONBIO
#	include <sys/filio.h>
#endif /* FIONBIO */

#if HAVE_SOCKLEN_T
#	define SOCKLEN_T socklen_t
#else
#	define SOCKLEN_T int
#endif

#if _WIN32
#	define FIONBIO_ARG_T u_long
#else
#	define FIONBIO_ARG_T int
#endif

#if _WIN32
	/* _WIN32 doesn't really have WSAEAGAIN */
#	ifndef WSAEAGAIN
#		define WSAEAGAIN WSAEWOULDBLOCK
#	endif
#else
	/* Windows sockets compatibility defines */
#	define INVALID_SOCKET (-1)
#	define SOCKET_ERROR (-1)
static inline int closesocket(int s) {
	return close(s);
}
#	define WSAEWOULDBLOCK EWOULDBLOCK
#	define WSAEAGAIN EAGAIN
#	define WSAEINPROGRESS EINPROGRESS
#	define WSAEINTR EINTR
#	define SOCKET int
static inline int GetLastError(void) {
	return errno;
}
#endif /* _WIN32 */

void setSocketDefaults(SOCKET fd);

