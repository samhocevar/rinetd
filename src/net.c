/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#	include <config.h>
#endif

#include "net.h"

void setSocketDefaults(SOCKET fd) {
	/* Make socket non-blocking (FIXME: this uses legacy API) */
	FIONBIO_ARG_T ioctltmp = 1;
#if _WIN32
	ioctlsocket(fd, FIONBIO, &ioctltmp);
#else
	ioctl(fd, FIONBIO, &ioctltmp);
#endif

#if defined __linux__
	int tmp = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
#endif

#if !defined __linux__ && !defined _WIN32
	int tmp = 1024;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(tmp));
#endif
}

uint16_t getPort(struct addrinfo* ai) {
	switch (ai->ai_family) {
		case AF_INET:
			return ntohs(((struct sockaddr_in*)ai->ai_addr)->sin_port);
		case AF_INET6:
			return ntohs(((struct sockaddr_in6*)ai->ai_addr)->sin6_port);
		default:
			return 0;
	}
}
