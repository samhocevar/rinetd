/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2017 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

#include <time.h>

enum ruleType {
	allowRule,
	denyRule,
};

enum protocolType {
	protoTcp = 1,
	protoUdp = 2,
};

typedef struct _rule Rule;
struct _rule
{
	char *pattern;
	int type;
};

typedef struct _server_info ServerInfo;
struct _server_info {
	SOCKET fd;

	/* In network order, for network purposes */
	struct in_addr localAddr;
	unsigned short localPort;
	struct in_addr sourceAddr;

	/* In ASCII and local byte order, for logging purposes */
	char *fromHost, *toHost;
	int fromPort, fromProto, toPort, toProto;

	/* Offset and count into list of allow and deny rules. Any rules
		prior to globalAllowRules and globalDenyRules are global rules. */
	int rulesStart, rulesCount;
	/* Timeout for UDP traffic before we consider the connection
		was dropped by the remote host. */
	int serverTimeout;
};

typedef struct _socket Socket;
struct _socket
{
	SOCKET fd;
	int proto;
	/* recv: received on this socket
		sent: sent to this socket from the other buffer */
	int recvPos, sentPos;
	int recvBytes, sentBytes;
	char *buffer;
};

typedef struct _connection_info ConnectionInfo;
struct _connection_info
{
	Socket remote, local;
	struct sockaddr_in remoteAddress;
	time_t remoteTimeout;
	int coClosing;
	int coLog;
	ServerInfo const *server; // only useful for logEvent
};

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
	char const *conf_file;
	int foreground;
};

