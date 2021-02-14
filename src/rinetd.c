/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2021 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#if HAVE_CONFIG_H
#	include <config.h>
#endif

#ifndef RETSIGTYPE
#	define RETSIGTYPE void
#endif

#ifdef _MSC_VER
#	include <malloc.h>
#endif

#if _WIN32
#	include "getopt.h"
#else
#	include <getopt.h>
#	if TIME_WITH_SYS_TIME
#		include <sys/time.h>
#		include <time.h>
#	elif HAVE_SYS_TIME_H
#		include <sys/time.h>
#	endif
#endif /* _WIN32 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#if _WIN32 || (!TIME_WITH_SYS_TIME && !HAVE_SYS_TIME_H)
#	include <time.h>
#endif
#include <ctype.h>

#ifdef DEBUG
#	define PERROR perror
#else
#	define PERROR(x)
#endif /* DEBUG */

#include "match.h"
#include "net.h"
#include "types.h"
#include "rinetd.h"
#include "parse.h"

Rule *allRules = NULL;
int allRulesCount = 0;
int globalRulesCount = 0;

ServerInfo *seInfo = NULL;
int seTotal = 0;

ConnectionInfo *coInfo = NULL;
int coTotal = 0;

/* On Windows, the maximum number of file descriptors in an fd_set
	is simply FD_SETSIZE and the first argument to select() is
	ignored, so maxfd will never change. */
#ifdef _WIN32
int const maxfd = 0;
#else
int maxfd = 0;
#endif

/* Global static buffer for UDP data. */
static char globalUdpBuffer[65536];

char *logFileName = NULL;
char *pidLogFileName = NULL;
int logFormatCommon = 0;
FILE *logFile = NULL;

char const *logMessages[] = {
	"unknown-error",
	"done-local-closed",
	"done-remote-closed",
	"accept-failed -",
	"local-socket-failed -",
	"local-bind-failed -",
	"local-connect-failed -",
	"opened",
	"not-allowed",
	"denied",
};

enum {
	logUnknownError = 0,
	logLocalClosedFirst,
	logRemoteClosedFirst,
	logAcceptFailed,
	logLocalSocketFailed,
	logLocalBindFailed,
	logLocalConnectFailed,
	logOpened,
	logAllowed,
	logNotAllowed,
	logDenied,
};

RinetdOptions options = {
	RINETD_CONFIG_FILE,
	0,
};

static void selectPass(void);
static void handleWrite(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static void handleRead(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static void handleUdpRead(ConnectionInfo *cnx, char const *buffer, int bytes);
static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static void handleAccept(ServerInfo const *srv);
static ConnectionInfo *findAvailableConnection(void);
static void setConnectionCount(int newCount);
static int getAddress(char const *host, struct in_addr *iaddr);
static int checkConnectionAllowed(ConnectionInfo const *cnx);

static int readArgs (int argc, char **argv, RinetdOptions *options);
static void clearConfiguration(void);
static void readConfiguration(char const *file);

static void registerPID(char const *pid_file_name);
static void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result);
static struct tm *get_gmtoff(int *tz);

/* Signal handlers */
#if !HAVE_SIGACTION && !_WIN32
static RETSIGTYPE plumber(int s);
#endif
#if !_WIN32
static RETSIGTYPE hup(int s);
#endif
static RETSIGTYPE quit(int s);


int main(int argc, char *argv[])
{
#ifdef _WIN32
	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(1, 1), &wsaData);
	if (result != 0) {
		fprintf(stderr, "Your computer was not connected "
			"to the Internet at the time that "
			"this program was launched, or you "
			"do not have a 32-bit "
			"connection to the Internet.");
		exit(1);
	}
#else
	openlog("rinetd", LOG_PID, LOG_DAEMON);
#endif

	readArgs(argc, argv, &options);

#if HAVE_DAEMON && !DEBUG
	if (!options.foreground && daemon(0, 0) != 0) {
		exit(0);
	}
#elif HAVE_FORK && !DEBUG
	if (!options.foreground && fork() != 0) {
		exit(0);
	}
#endif

#if HAVE_SIGACTION
	struct sigaction act;
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &act, NULL);
	act.sa_handler = &hup;
	sigaction(SIGHUP, &act, NULL);
#elif !_WIN32
	signal(SIGPIPE, plumber);
	signal(SIGHUP, hup);
#endif
	signal(SIGINT, quit);
	signal(SIGTERM, quit);

	readConfiguration(options.conf_file);
	if (pidLogFileName || !options.foreground) {
		registerPID(pidLogFileName ? pidLogFileName : RINETD_PID_FILE);
	}

	syslog(LOG_INFO, "Starting redirections...\n");
	while (1) {
		selectPass();
	}

	return 0;
}

static void clearConfiguration(void) {
	/* Remove references to server information */
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		cnx->server = NULL;
	}
	/* Close existing server sockets. */
	for (int i = 0; i < seTotal; ++i) {
		ServerInfo *srv = &seInfo[i];
		if (srv->fd != INVALID_SOCKET) {
			closesocket(srv->fd);
		}
		free(srv->fromHost);
		free(srv->toHost);
		freeaddrinfo(srv->fromAddrInfo);
		if (srv->sourceAddrInfo) {
			freeaddrinfo(srv->sourceAddrInfo);
		}
	}
	/* Free memory associated with previous set. */
	free(seInfo);
	seInfo = NULL;
	seTotal = 0;
	/* Forget existing rules. */
	for (int i = 0; i < allRulesCount; ++i) {
		free(allRules[i].pattern);
	}
	/* Free memory associated with previous set. */
	free(allRules);
	allRules = NULL;
	allRulesCount = globalRulesCount = 0;
	/* Free file names */
	free(logFileName);
	logFileName = NULL;
	free(pidLogFileName);
	pidLogFileName = NULL;
}

static void readConfiguration(char const *file) {

	/* Parse the configuration file. */
	parseConfiguration(file);

	/* Open the log file */
	if (logFile) {
		fclose(logFile);
		logFile = NULL;
	}
	if (logFileName) {
		logFile = fopen(logFileName, "a+");
		if (logFile) {
			setvbuf(logFile, NULL, _IONBF, 0);
		} else {
			syslog(LOG_ERR, "could not open %s to append (%m).\n",
				logFileName);
		}
	}
}

void addServer(char *bindAddress, char *bindPort, int bindProtocol,
               char *connectAddress, uint16_t connectPort, int connectProtocol,
               int serverTimeout, char *sourceAddress)
{
	ServerInfo si = {
		.fromHost = bindAddress,
		.toHost = connectAddress,
		.toPort = connectPort,
		.toProtocol = connectProtocol,
		.serverTimeout = serverTimeout,
	};

	/* Make a server socket */
	struct addrinfo hints =
	{
		.ai_family = AF_UNSPEC,
		.ai_protocol = bindProtocol,
		.ai_socktype = getSocketType(bindProtocol),
		.ai_flags = AI_PASSIVE,
	};
	struct addrinfo *servinfo;
	int ret = getaddrinfo(bindAddress, bindPort, &hints, &servinfo);
	if (ret != 0) {
		fprintf(stderr, "rinetd: getaddrinfo error: %s\n", gai_strerror(ret));
		exit(1);
	}

	for (struct addrinfo *it = servinfo; it; it = it->ai_next) {
		si.fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (si.fd == INVALID_SOCKET) {
			syslog(LOG_ERR, "couldn't create server socket! (%m)\n");
			freeaddrinfo(servinfo);
			exit(1);
		}

		int tmp = 1;
		setsockopt(si.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&tmp, sizeof(tmp));

		if (bind(si.fd, it->ai_addr, it->ai_addrlen) == SOCKET_ERROR) {
			syslog(LOG_ERR, "couldn't bind to address %s port %s (%m)\n",
				bindAddress, bindPort);
			closesocket(si.fd);
			freeaddrinfo(servinfo);
			exit(1);
		}

		if (bindProtocol == IPPROTO_TCP) {
			if (listen(si.fd, RINETD_LISTEN_BACKLOG) == SOCKET_ERROR) {
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "couldn't listen to address %s port %s (%m)\n",
					bindAddress, bindPort);
				/* XXX: check whether this is correct */
				closesocket(si.fd);
			}

			/* Make socket nonblocking in TCP mode only, otherwise
				we may miss some data. */
			setSocketDefaults(si.fd);
		}

		si.fromAddrInfo = it;
		break;
	}

	/* Resolve source address if applicable */
	if (sourceAddress) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC,
		hints.ai_protocol = connectProtocol,
		hints.ai_socktype = getSocketType(connectProtocol),

		ret = getaddrinfo(sourceAddress, NULL, &hints, &servinfo);
		if (ret != 0) {
			fprintf(stderr, "rinetd: getaddrinfo error: %s\n", gai_strerror(ret));
			exit(1);
		}
		si.sourceAddrInfo = servinfo;
	}

	if (getAddress(connectAddress, &si.localAddr) < 0) {
		/* Warn -- don't exit. */
		syslog(LOG_ERR, "host %s could not be resolved.\n",
			bindAddress);
		closesocket(si.fd);
		exit(1);
	}
	si.localPort = htons(connectPort);

#ifndef _WIN32
	if (si.fd > maxfd) {
		maxfd = si.fd;
	}
#endif

	/* Allocate server info */
	seInfo = (ServerInfo *)realloc(seInfo, sizeof(ServerInfo) * (seTotal + 1));
	if (!seInfo) {
		exit(1);
	}
	seInfo[seTotal] = si;
	++seTotal;
}

static void setConnectionCount(int newCount)
{
	if (newCount == coTotal) {
		return;
	}

	for (int i = newCount; i < coTotal; ++i) {
		if (coInfo[i].local.fd != INVALID_SOCKET) {
			closesocket(coInfo[i].local.fd);
		}
		if (coInfo[i].remote.fd != INVALID_SOCKET) {
			if (coInfo[i].remote.protocol == IPPROTO_TCP)
				closesocket(coInfo[i].remote.fd);
		}
		free(coInfo[i].local.buffer);
	}

	if (newCount == 0) {
		free(coInfo);
		coInfo = NULL;
		coTotal = 0;
		return;
	}

	ConnectionInfo * newCoInfo = (ConnectionInfo *)
		malloc(sizeof(ConnectionInfo) * newCount);
	if (!newCoInfo) {
		return;
	}

	memcpy(newCoInfo, coInfo, sizeof(ConnectionInfo) * coTotal);

	for (int i = coTotal; i < newCount; ++i) {
		ConnectionInfo *cnx = &newCoInfo[i];
		memset(cnx, 0, sizeof(*cnx));
		cnx->local.fd = INVALID_SOCKET;
		cnx->remote.fd = INVALID_SOCKET;
		cnx->local.buffer = (char *) malloc(sizeof(char) * 2 * RINETD_BUFFER_SIZE);
		if (!cnx->local.buffer) {
			while (i-- >= coTotal) {
				free(newCoInfo[i].local.buffer);
			}
			free(newCoInfo);
			return;
		}
		cnx->remote.buffer = cnx->local.buffer + RINETD_BUFFER_SIZE;
	}

	free(coInfo);
	coInfo = newCoInfo;
	coTotal = newCount;
}

static ConnectionInfo *findAvailableConnection(void)
{
	/* Find an existing closed connection to reuse */
	for (int j = 0; j < coTotal; ++j) {
		if (coInfo[j].local.fd == INVALID_SOCKET
			&& coInfo[j].remote.fd == INVALID_SOCKET) {
			return &coInfo[j];
		}
	}

	/* Allocate new connections and pick the first one */
	int oldTotal = coTotal;
	setConnectionCount(coTotal * 4 / 3 + 8);
	if (coTotal == oldTotal) {
		syslog(LOG_ERR, "not enough memory to add slots. "
			"Currently %d slots.\n", coTotal);
		/* Go back to the previous total number of slots */
		return NULL;
	}
	return &coInfo[oldTotal];
}

static void selectPass(void)
{
	int const fdSetCount = maxfd / FD_SETSIZE + 1;
#	define FD_ZERO_EXT(ar) for (int i = 0; i < fdSetCount; ++i) { FD_ZERO(&(ar)[i]); }
#ifdef _WIN32
	/* On Windows, only one fd_set is usable because of its structure. */
#	define FD_SET_EXT(fd, ar) FD_SET(fd, &(ar)[0])
#	define FD_ISSET_EXT(fd, ar) FD_ISSET(fd, &(ar)[0])
#else
#	define FD_SET_EXT(fd, ar) FD_SET((fd) % FD_SETSIZE, &(ar)[(fd) / FD_SETSIZE])
#	define FD_ISSET_EXT(fd, ar) FD_ISSET((fd) % FD_SETSIZE, &(ar)[(fd) / FD_SETSIZE])
#endif

	/* Timeout value -- infinite by default */
	struct timeval timeout;
	timeout.tv_sec = timeout.tv_usec = 0;
	time_t now = time(NULL);

#ifdef _MSC_VER
	fd_set* readfds = (fd_set*)alloca(sizeof(*readfds) * fdSetCount);
	fd_set* writefds = (fd_set*)alloca(sizeof(*writefds) * fdSetCount);
#else
	fd_set readfds[fdSetCount], writefds[fdSetCount];
#endif
	FD_ZERO_EXT(readfds);
	FD_ZERO_EXT(writefds);
	/* Server sockets */
	for (int i = 0; i < seTotal; ++i) {
		if (seInfo[i].fd != INVALID_SOCKET) {
			FD_SET_EXT(seInfo[i].fd, readfds);
		}
	}
	/* Connection sockets */
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		if (cnx->local.fd != INVALID_SOCKET) {
			/* Accept more output from the local
				server if there's room */
			if (cnx->local.recvPos < RINETD_BUFFER_SIZE) {
				FD_SET_EXT(cnx->local.fd, readfds);
			}
			/* Send more input to the local server
				if we have any, or if we’re closing */
			if (cnx->local.sentPos < cnx->remote.recvPos || cnx->coClosing) {
				FD_SET_EXT(cnx->local.fd, writefds);
			}
		}
		if (cnx->remote.fd != INVALID_SOCKET) {
			/* Get more input if we have room for it */
			if (cnx->remote.recvPos < RINETD_BUFFER_SIZE) {
				FD_SET_EXT(cnx->remote.fd, readfds);
				/* For UDP connections, we need to handle timeouts */
				if (cnx->remote.protocol == IPPROTO_UDP) {
					long delay = (long)(cnx->remoteTimeout - now);
					timeout.tv_sec = delay <= 1 ? 1
						: (delay < timeout.tv_sec || timeout.tv_sec == 0) ? delay
						: timeout.tv_sec;
				}
			}
			/* Send more output if we have any, or if we’re closing */
			if (cnx->remote.sentPos < cnx->local.recvPos || cnx->coClosing) {
				FD_SET_EXT(cnx->remote.fd, writefds);
			}
		}
	}

	select(maxfd + 1, readfds, writefds, 0, timeout.tv_sec ? &timeout : NULL);
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		if (cnx->remote.fd != INVALID_SOCKET) {
			/* Do not read on remote UDP sockets, the server does it,
				but handle timeouts instead. */
			if (cnx->remote.protocol == IPPROTO_TCP) {
				if (FD_ISSET_EXT(cnx->remote.fd, readfds)) {
					handleRead(cnx, &cnx->remote, &cnx->local);
				}
			} else {
				if (now > cnx->remoteTimeout) {
					handleClose(cnx, &cnx->remote, &cnx->local);
				}
			}
		}
		if (cnx->remote.fd != INVALID_SOCKET) {
			if (FD_ISSET_EXT(cnx->remote.fd, writefds)) {
				handleWrite(cnx, &cnx->remote, &cnx->local);
			}
		}
		if (cnx->local.fd != INVALID_SOCKET) {
			if (FD_ISSET_EXT(cnx->local.fd, readfds)) {
				handleRead(cnx, &cnx->local, &cnx->remote);
			}
		}
		if (cnx->local.fd != INVALID_SOCKET) {
			if (FD_ISSET_EXT(cnx->local.fd, writefds)) {
				handleWrite(cnx, &cnx->local, &cnx->remote);
			}
		}
	}
	/* Handle servers last because handleAccept() may modify coTotal */
	for (int i = 0; i < seTotal; ++i) {
		ServerInfo *srv = &seInfo[i];
		if (srv->fd != INVALID_SOCKET) {
			if (FD_ISSET_EXT(srv->fd, readfds)) {
				handleAccept(srv);
			}
		}
	}
}

static void handleRead(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
	if (RINETD_BUFFER_SIZE == socket->recvPos) {
		return;
	}
	int wanted = RINETD_BUFFER_SIZE - socket->recvPos;
	int got = recv(socket->fd, socket->buffer + socket->recvPos, wanted, 0);
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
	}
	if (got <= 0) {
		/* Prepare for closing */
		handleClose(cnx, socket, other_socket);
		return;
	}
	socket->totalBytesIn += got;
	socket->recvPos += got;
}

static void handleUdpRead(ConnectionInfo *cnx, char const *buffer, int bytes)
{
	Socket *socket = &cnx->remote;
	int got = bytes < RINETD_BUFFER_SIZE - socket->recvPos
		? bytes : RINETD_BUFFER_SIZE - socket->recvPos;
	if (got > 0) {
		memcpy(socket->buffer + socket->recvPos, buffer, got);
		socket->totalBytesIn += got;
		socket->recvPos += got;
	}
}

static void handleWrite(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
	if (cnx->coClosing && (socket->sentPos == other_socket->recvPos)) {
		PERROR("rinetd: local closed and no more output");
		logEvent(cnx, cnx->server, cnx->coLog);
		if (socket->protocol == IPPROTO_TCP)
			closesocket(socket->fd);
		socket->fd = INVALID_SOCKET;
		return;
	}

	struct sockaddr const *addr = NULL;
	SOCKLEN_T addrlen = 0;
	if (socket->protocol == IPPROTO_UDP && socket == &cnx->remote) {
		addr = (struct sockaddr const*)&cnx->remoteAddress;
		addrlen = (SOCKLEN_T)sizeof(cnx->remoteAddress);
	}

	int wanted = other_socket->recvPos - socket->sentPos;
	int got = sendto(socket->fd, other_socket->buffer + socket->sentPos,
		wanted, 0, addr, addrlen);
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
		handleClose(cnx, socket, other_socket);
		return;
	}
	socket->sentPos += got;
	socket->totalBytesOut += got;
	if (got == wanted) {
		socket->sentPos = other_socket->recvPos = 0;
	}
}

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
	cnx->coClosing = 1;
	if (socket->protocol == IPPROTO_TCP) {
		/* One end fizzled out, so make sure we're all done with that */
		closesocket(socket->fd);
	} else /* if (socket->protocol == IPPROTO_UDP) */ {
		/* Nothing to do in UDP mode */
	}
	socket->fd = INVALID_SOCKET;

	if (other_socket->fd != INVALID_SOCKET) {
		if (other_socket->protocol == IPPROTO_TCP) {
#if !defined __linux__ && !defined _WIN32
			/* Now set up the other end for a polite closing */

			/* Request a low-water mark equal to the entire
				output buffer, so the next write notification
				tells us for sure that we can close the socket. */
			int arg = 1024;
			setsockopt(other_socket->fd, SOL_SOCKET, SO_SNDLOWAT,
				&arg, sizeof(arg));
#endif
		} else /* if (other_socket->protocol == IPPROTO_UDP) */ {
			if (other_socket == &cnx->local)
				closesocket(other_socket->fd);
			other_socket->fd = INVALID_SOCKET;
		}

		cnx->coLog = socket == &cnx->local ?
			logLocalClosedFirst : logRemoteClosedFirst;
	}
}

static void handleAccept(ServerInfo const *srv)
{
	int udpBytes = 0;

	struct sockaddr_storage addr;
	SOCKLEN_T addrlen = sizeof(addr);

	SOCKET nfd;
	if (srv->fromAddrInfo->ai_protocol == IPPROTO_TCP) {
		/* In TCP mode, get remote address using accept(). */
		nfd = accept(srv->fd, (struct sockaddr *)&addr, &addrlen);
		if (nfd == INVALID_SOCKET) {
			syslog(LOG_ERR, "accept(%llu): %m\n", (long long unsigned int)srv->fd);
			logEvent(NULL, srv, logAcceptFailed);
			return;
		}

		setSocketDefaults(nfd);
	} else /* if (srv->fromAddrInfo->ai_protocol == IPPROTO_UDP) */ {
		/* In UDP mode, get remote address using recvfrom() and check
			for an existing connection from this client. We need
			to read a lot of data otherwise the datagram contents
			may be lost later. */
		nfd = srv->fd;
		SSIZE_T ret = recvfrom(nfd, globalUdpBuffer,
				sizeof(globalUdpBuffer), 0, (struct sockaddr *)&addr, &addrlen);
		if (ret < 0) {
			if (GetLastError() == WSAEWOULDBLOCK) {
				return;
			}
			if (GetLastError() == WSAEINPROGRESS) {
				return;
			}
			syslog(LOG_ERR, "recvfrom(%llu): %m\n", (long long unsigned int)srv->fd);
			logEvent(NULL, srv, logAcceptFailed);
			return;
		}

		udpBytes = (int)ret;

		for (int i = 0; i < coTotal; ++i) {
			ConnectionInfo *cnx = &coInfo[i];
			struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
			if (cnx->remote.fd == nfd
				&& cnx->remoteAddress.sin_family == addr_in->sin_family
				&& cnx->remoteAddress.sin_port == addr_in->sin_port
				&& cnx->remoteAddress.sin_addr.s_addr == addr_in->sin_addr.s_addr) {
				cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
				handleUdpRead(cnx, globalUdpBuffer, udpBytes);
				return;
			}
		}
	}

	ConnectionInfo *cnx = findAvailableConnection();
	if (!cnx) {
		return;
	}

	cnx->local.fd = INVALID_SOCKET;
	cnx->local.protocol = srv->toProtocol;
	cnx->local.recvPos = cnx->local.sentPos = 0;
	cnx->local.totalBytesIn = cnx->local.totalBytesOut = 0;

	cnx->remote.fd = nfd;
	cnx->remote.protocol = srv->fromAddrInfo->ai_protocol;
	cnx->remote.recvPos = cnx->remote.sentPos = 0;
	cnx->remote.totalBytesIn = cnx->remote.totalBytesOut = 0;
	cnx->remoteAddress = *(struct sockaddr_in *)&addr;
	if (srv->fromAddrInfo->ai_protocol == IPPROTO_UDP)
		cnx->remoteTimeout = time(NULL) + srv->serverTimeout;

	cnx->coClosing = 0;
	cnx->coLog = logUnknownError;
	cnx->server = srv;

	int logCode = checkConnectionAllowed(cnx);
	if (logCode != logAllowed) {
		/* Local fd is not open yet, so only
			close the remote socket. */
		if (cnx->remote.protocol == IPPROTO_TCP)
			closesocket(cnx->remote.fd);
		cnx->remote.fd = INVALID_SOCKET;
		logEvent(cnx, cnx->server, logCode);
		return;
	}

	/* Now open a connection to the local server.
		This, too, is nonblocking. Why wait
		for anything when you don't have to? */
	struct sockaddr_in saddr;
	/* FIXME: don’t forget to switch to PF_INET6 for IPv6. */
	cnx->local.fd = socket(PF_INET, getSocketType(srv->toProtocol), srv->toProtocol);
	if (cnx->local.fd == INVALID_SOCKET) {
		syslog(LOG_ERR, "socket(): %m\n");
		if (cnx->remote.protocol == IPPROTO_TCP)
			closesocket(cnx->remote.fd);
		cnx->remote.fd = INVALID_SOCKET;
		logEvent(cnx, srv, logLocalSocketFailed);
		return;
	}

	if (srv->toProtocol == IPPROTO_TCP)
		setSocketDefaults(cnx->local.fd);

	/* Bind the local socket even though we use connect() later, so that
		we can specify a source address. */
	if (srv->sourceAddrInfo) {
		if (bind(cnx->local.fd, srv->sourceAddrInfo->ai_addr,
				srv->sourceAddrInfo->ai_addrlen) == SOCKET_ERROR) {
			syslog(LOG_ERR, "bind(): %m\n");
		}
	}

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr, &srv->localAddr, sizeof(struct in_addr));
	saddr.sin_port = srv->localPort;
	if (connect(cnx->local.fd, (struct sockaddr *)&saddr,
		sizeof(struct sockaddr_in)) == SOCKET_ERROR)
	{
		if ((GetLastError() != WSAEINPROGRESS) &&
			(GetLastError() != WSAEWOULDBLOCK))
		{
			PERROR("rinetd: connect");
			closesocket(cnx->local.fd);
			if (cnx->remote.protocol == IPPROTO_TCP)
				closesocket(cnx->remote.fd);
			cnx->remote.fd = INVALID_SOCKET;
			cnx->local.fd = INVALID_SOCKET;
			logEvent(cnx, srv, logLocalConnectFailed);
			return;
		}
	}

	/* Send a zero-size UDP packet to simulate a connection */
	if (srv->toProtocol == IPPROTO_UDP) {
		int got = sendto(cnx->local.fd, NULL, 0, 0,
		                 (struct sockaddr const *)&saddr,
		                 (SOCKLEN_T)sizeof(saddr));
		/* FIXME: we ignore errors here... is it safe? */
		(void)got;
	}

	/* Send UDP data to the other socket */
	if (srv->fromAddrInfo->ai_protocol == IPPROTO_UDP) {
		handleUdpRead(cnx, globalUdpBuffer, udpBytes);
	}

#ifndef _WIN32
	if (cnx->local.fd > maxfd) {
		maxfd = cnx->local.fd;
	}
	if (cnx->remote.fd > maxfd) {
		maxfd = cnx->remote.fd;
	}
#endif /* _WIN32 */

	logEvent(cnx, srv, logOpened);
}

static int checkConnectionAllowed(ConnectionInfo const *cnx)
{
	ServerInfo const *srv = cnx->server;
	char const *addressText = inet_ntoa(cnx->remoteAddress.sin_addr);

	/* 1. Check global allow rules. If there are no
		global allow rules, it's presumed OK at
		this step. If there are any, and it doesn't
		match at least one, kick it out. */
	int good = 1;
	for (int j = 0; j < globalRulesCount; ++j) {
		if (allRules[j].type == allowRule) {
			good = 0;
			if (match(addressText, allRules[j].pattern)) {
				good = 1;
				break;
			}
		}
	}
	if (!good) {
		return logNotAllowed;
	}
	/* 2. Check global deny rules. If it matches
		any of the global deny rules, kick it out. */
	for (int j = 0; j < globalRulesCount; ++j) {
		if (allRules[j].type == denyRule
			&& match(addressText, allRules[j].pattern)) {
			return logDenied;
		}
	}
	/* 3. Check allow rules specific to this forwarding rule.
		If there are none, it's OK. If there are any,
		it must match at least one. */
	good = 1;
	for (int j = 0; j < srv->rulesCount; ++j) {
		if (allRules[srv->rulesStart + j].type == allowRule) {
			good = 0;
			if (match(addressText,
				allRules[srv->rulesStart + j].pattern)) {
				good = 1;
				break;
			}
		}
	}
	if (!good) {
		return logNotAllowed;
	}
	/* 4. Check deny rules specific to this forwarding rule. If
		it matches any of the deny rules, kick it out. */
	for (int j = 0; j < srv->rulesCount; ++j) {
		if (allRules[srv->rulesStart + j].type == denyRule
			&& match(addressText, allRules[srv->rulesStart + j].pattern)) {
			return logDenied;
		}
	}

	return logAllowed;
}

static int getAddress(char const *host, struct in_addr *iaddr)
{
	/* If this is an IP address, use inet_addr() */
	int is_ipv4 = 1, is_ipv6 = 0;
	for (char const *p = host; *p; ++p) {
		is_ipv6 |= (*p == ':' || *p == '[' || *p == ']');
		is_ipv4 &= (isdigit(*p) || *p == '.');
	}
	if (is_ipv6) {
		fprintf(stderr, "IPv6 addresses are not supported yet: %s\n", host);
		return -1;
	}

	if (is_ipv4) {
		iaddr->s_addr = inet_addr(host);
		return 0;
	}

	/* Otherwise, use gethostbyname() */
	struct hostent *h = gethostbyname(host);
	if (h) {
#ifdef h_addr
		memcpy(&iaddr->s_addr, h->h_addr, 4);
#else
		memcpy(&iaddr->s_addr, h->h_addr_list[0], 4);
#endif
		return 0;
	}

	char const *msg = "(unknown DNS error)";
	switch (h_errno)
	{
	case HOST_NOT_FOUND:
		msg = "The specified host is unknown.";
		break;
#ifdef NO_DATA
	case NO_DATA:
#else
	case NO_ADDRESS:
#endif
		msg = "The requested name is valid but does not have an IP address.";
		break;
	case NO_RECOVERY:
		msg = "A non-recoverable name server error occurred.";
		break;
	case TRY_AGAIN:
		msg = "A temporary error occurred on an authoritative name server.  Try again later.";
		break;
	}
	syslog(LOG_ERR, "While resolving `%s' got: %s\n", host, msg);
	return -1;
}

#if !HAVE_SIGACTION && !_WIN32
RETSIGTYPE plumber(int s)
{
	/* Just reinstall */
	signal(SIGPIPE, plumber);
}
#endif

#if !_WIN32
RETSIGTYPE hup(int s)
{
	(void)s;
	syslog(LOG_INFO, "Received SIGHUP, reloading configuration...\n");
	/* Learn the new rules */
	clearConfiguration();
	readConfiguration(options.conf_file);
#if !HAVE_SIGACTION
	/* And reinstall the signal handler */
	signal(SIGHUP, hup);
#endif
}
#endif /* _WIN32 */

RETSIGTYPE quit(int s)
{
	(void)s;
	/* Obey the request, but first flush the log */
	if (logFile) {
		fclose(logFile);
	}
	/* ...and get rid of memory allocations */
	setConnectionCount(0);
	clearConfiguration();
	exit(0);
}

void registerPID(char const *pid_file_name)
{
#if defined(__linux__)
	FILE *pid_file = fopen(pid_file_name, "w");
	if (pid_file == NULL) {
		/* non-fatal, non-Linux may lack /var/run... */
		fprintf(stderr, "rinetd: Couldn't write to "
			"%s. PID was not logged.\n", pid_file_name);
		goto error;
	} else {
		fprintf(pid_file, "%d\n", getpid());
		/* errors aren't fatal */
		if (fclose(pid_file))
			goto error;
	}
	return;
error:
	syslog(LOG_ERR, "Couldn't write to "
		"%s. PID was not logged (%m).\n", pid_file_name);
#else
	/* add other systems with wherever they register processes */
	(void)pid_file_name;
#endif
}

static void logEvent(ConnectionInfo const *cnx, ServerInfo const *srv, int result)
{
	/* Bit of borrowing from Apache logging module here,
		thanks folks */
	int timz;
	char tstr[1024];
	struct tm *t = get_gmtoff(&timz);
	char sign = (timz < 0 ? '-' : '+');
	if (timz < 0) {
		timz = -timz;
	}
	strftime(tstr, sizeof(tstr), "%d/%b/%Y:%H:%M:%S ", t);

	char const *addressText = "?";
	int64_t bytesOut = 0, bytesIn = 0;
	if (cnx != NULL) {
		addressText = inet_ntoa(cnx->remoteAddress.sin_addr);
		bytesOut = cnx->remote.totalBytesOut;
		bytesIn = cnx->remote.totalBytesIn;
	}

	char const *fromHost = "?", *toHost = "?";
	uint16_t fromPort = 0, toPort = 0;
	if (srv != NULL) {
		fromHost = srv->fromHost;
		fromPort = getPort(srv->fromAddrInfo);
		toHost = srv->toHost;
		toPort = srv->toPort;
	}

	if (result==logNotAllowed || result==logDenied)
		syslog(LOG_INFO, "%s %s\n"
			, addressText
			, logMessages[result]);
	if (logFile) {
		if (logFormatCommon) {
			/* Fake a common log format log file in a way that
				most web analyzers can do something interesting with.
				We lie and say the protocol is HTTP because we don't
				want the web analyzer to reject the line. We also
				lie and claim success (code 200) because we don't
				want the web analyzer to ignore the line as an
				error and not analyze the "URL." We put a result
				message into our "URL" instead. The last field
				is an extra, giving the number of input bytes,
				after several placeholders meant to fill the
				positions frequently occupied by user agent,
				referrer, and server name information. */
			fprintf(logFile, "%s - - "
				"[%s %c%.2d%.2d] "
				"\"GET /rinetd-services/%s/%d/%s/%d/%s HTTP/1.0\" "
				"200 %llu - - - %llu\n",
				addressText,
				tstr,
				sign,
				timz / 60,
				timz % 60,
				fromHost, (int)fromPort,
				toHost, (int)toPort,
				logMessages[result],
				(unsigned long long int)bytesOut,
				(unsigned long long int)bytesIn);
		} else {
			/* Write an rinetd-specific log entry with a
				less goofy format. */
			fprintf(logFile, "%s\t%s\t%s\t%d\t%s\t%d\t%llu"
					"\t%llu\t%s\n",
				tstr,
				addressText,
				fromHost, (int)fromPort,
				toHost, (int)toPort,
				(unsigned long long int)bytesIn,
				(unsigned long long int)bytesOut,
				logMessages[result]);
		}
	}
}

static int readArgs (int argc, char **argv, RinetdOptions *options)
{
	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"conf-file",  1, 0, 'c'},
			{"foreground", 0, 0, 'f'},
			{"help",       0, 0, 'h'},
			{"version",    0, 0, 'v'},
			{0, 0, 0, 0}
		};
		int c = getopt_long (argc, argv, "c:fshv",
			long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'c':
				options->conf_file = optarg;
				if (!options->conf_file) {
					syslog(LOG_ERR, "Not enough memory to "
						"launch rinetd.\n");
					exit(1);
				}
				break;
			case 'f':
				options->foreground = 1;
				break;
			case 'h':
				printf("Usage: rinetd [OPTION]\n"
					"  -c, --conf-file FILE   read configuration "
					"from FILE\n"
					"  -f, --foreground       do not run in the "
					"background\n"
					"  -h, --help             display this help\n"
					"  -v, --version          display version "
					"number\n\n");
				printf("Most options are controlled through the\n"
					"configuration file. See the rinetd(8)\n"
					"manpage for more information.\n");
				exit (0);
			case 'v':
				printf ("rinetd %s\n", PACKAGE_VERSION);
				exit (0);
			case '?':
			default:
				exit (1);
		}
	}
	return 0;
}

/* get_gmtoff was borrowed from Apache. Thanks folks. */

static struct tm *get_gmtoff(int *tz)
{
	time_t tt = time(NULL);

	/* Assume we are never more than 24 hours away. */
	struct tm gmt = *gmtime(&tt); /* remember gmtime/localtime return ptr to static */
	struct tm *t = localtime(&tt); /* buffer... so be careful */
	int days = t->tm_yday - gmt.tm_yday;
	int hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
		+ t->tm_hour - gmt.tm_hour);
	int minutes = hours * 60 + t->tm_min - gmt.tm_min;
	*tz = minutes;
	return t;
}

