#if HAVE_CONFIG_H
#	include <config.h>
#endif

#ifndef RETSIGTYPE
#	define RETSIGTYPE void
#endif

#if _WIN32
#	include <windows.h>
#	include <winsock.h>
#	include "getopt.h"
#	define syslog fprintf
#	define LOG_ERR stderr
#	define LOG_INFO stdout
#else
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/ioctl.h>
#	include <unistd.h>
#	include <netdb.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <getopt.h>
#	include <errno.h>
#	include <syslog.h>
#	define INVALID_SOCKET (-1)
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
#	define ioctlsocket ioctl
#	define WSAEWOULDBLOCK EWOULDBLOCK
#	define WSAEAGAIN EAGAIN
#	define WSAEINPROGRESS EINPROGRESS
#	define WSAEINTR EINTR
#	define SOCKET int
static inline int GetLastError(void) {
	return errno;
}
#endif /* _WIN32 */

#ifdef DEBUG
#	define PERROR perror
#else
#	define PERROR(x)
#endif /* DEBUG */

/* We've got to get FIONBIO from somewhere. Try the Solaris location
	if it isn't defined yet by the above includes. */
#ifndef FIONBIO
#	include <sys/filio.h>
#endif /* FIONBIO */

#include "match.h"
#include "rinetd.h"

Rule *allRules = NULL;
int allRulesCount = 0;
int globalRulesCount = 0;

ServerInfo *seInfo = NULL;
int seTotal = 0;

ConnectionInfo *coInfo = NULL;
int coTotal = 0;

int maxfd = 0;
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

enum
{
	logUnknownError = 0,
	logLocalClosedFirst,
	logRemoteClosedFirst,
	logAcceptFailed,
	logLocalSocketFailed,
	logLocalBindFailed,
	logLocalConnectFailed,
	logOpened,
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
static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket);
static void handleAccept(ServerInfo const *srv);
static ConnectionInfo *findAvailableConnection(void);
static void setConnectionCount(int newCount);
static int getAddress(char const *host, struct in_addr *iaddr);
static void refuse(ConnectionInfo *cnx, int logCode);

static int readArgs (int argc, char **argv, RinetdOptions *options);
static int getConfLine(FILE *in, char *line, int space, int *lnum);
static void clearConfiguration(void);
static void readConfiguration(void);

static void registerPID(void);
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

	readConfiguration();
	registerPID();

	syslog(LOG_INFO, "Starting redirections...");
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

static void readConfiguration(void) {
	/* Parse the configuration file. */
	FILE *in = fopen(options.conf_file, "r");
	if (!in) {
		goto lowMemory;
	}
	for (int lnum = 0; ; ) {
		char line[16384];
		if (!getConfLine(in, line, sizeof(line), &lnum)) {
			break;
		}
		char const *currentToken = strtok(line, " \t\r\n");
		if (!currentToken) {
			syslog(LOG_ERR, "no bind address specified "
				"on file %s, line %d.\n", options.conf_file, lnum);
			continue;
		}
		if (!strcmp(currentToken, "allow")
			|| !strcmp(currentToken, "deny")) {
			char const *pattern = strtok(0, " \t\r\n");
			if (!pattern) {
				syslog(LOG_ERR, "nothing to %s "
					"specified on file %s, line %d.\n", currentToken, options.conf_file, lnum);
				continue;
			}
			int bad = 0;
			for (char const *p = pattern; *p; ++p) {
				if (!strchr("0123456789?*.", *p)) {
					bad = 1;
					break;
				}
			}
			if (bad) {
				syslog(LOG_ERR, "illegal allow or "
					"deny pattern. Only digits, ., and\n"
					"the ? and * wild cards are allowed. "
					"For performance reasons, rinetd\n"
					"does not look up complete "
					"host names.\n");
				continue;
			}

			allRules = (Rule *)
				realloc(allRules, sizeof(Rule *) * (allRulesCount + 1));
			if (!allRules) {
				goto lowMemory;
			}
			allRules[allRulesCount].pattern = strdup(pattern);
			if (!allRules[allRulesCount].pattern) {
				goto lowMemory;
			}
			allRules[allRulesCount].type = currentToken[0] == 'a' ? allowRule : denyRule;
			if (seTotal > 0) {
				if (seInfo[seTotal - 1].rulesStart == 0) {
					seInfo[seTotal - 1].rulesStart = allRulesCount;
				}
				++seInfo[seTotal - 1].rulesCount;
			} else {
				++globalRulesCount;
			}
			++allRulesCount;
		} else if (!strcmp(currentToken, "logfile")) {
			char const *nt = strtok(0, " \t\r\n");
			if (!nt) {
				syslog(LOG_ERR, "no log file name "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			logFileName = strdup(nt);
			if (!logFileName) {
				goto lowMemory;
			}
		} else if (!strcmp(currentToken, "pidlogfile")) {
			char const *nt = strtok(0, " \t\r\n");
			if (!nt) {
				syslog(LOG_ERR, "no PID log file name "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			pidLogFileName = strdup(nt);
			if (!pidLogFileName) {
				goto lowMemory;
			}
		} else if (!strcmp(currentToken, "logcommon")) {
			logFormatCommon = 1;
		} else {
			/* A regular forwarding rule. */
			char const *bindAddress = currentToken;
			char const *bindPortS = strtok(0, " \t\r\n");
			if (!bindPortS) {
				syslog(LOG_ERR, "no bind port "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			struct servent *bindService = getservbyname(bindPortS, "tcp");
			unsigned int bindPort = bindService ? ntohs(bindService->s_port) : atoi(bindPortS);
			if (bindPort == 0 || bindPort >= 65536) {
				syslog(LOG_ERR, "bind port missing "
					"or out of range on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			char const *connectAddress = strtok(0, " \t\r\n");
			if (!connectAddress) {
				syslog(LOG_ERR, "no connect address "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			char const *connectPortS = strtok(0, " \t\r\n");
			if (!connectPortS) {
				syslog(LOG_ERR, "no connect port "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			struct servent *connectService = getservbyname(connectPortS, "tcp");
			unsigned int connectPort = connectService ? ntohs(connectService->s_port) : atoi(connectPortS);
			if (connectPort == 0 || connectPort >= 65536) {
				syslog(LOG_ERR, "bind port missing "
					"or out of range on file %s,  %d.\n", options.conf_file, lnum);
				continue;
			}
			/* Turn all of this stuff into reasonable addresses */
			struct in_addr iaddr;
			if (getAddress(bindAddress, &iaddr) < 0) {
				fprintf(stderr, "rinetd: host %s could not be "
					"resolved on line %d.\n",
					bindAddress, lnum);
				continue;
			}
			/* Make a server socket */
			int fd = socket(PF_INET, SOCK_STREAM, 0);
			if (fd == INVALID_SOCKET) {
				syslog(LOG_ERR, "couldn't create "
					"server socket! (%m)\n");
				continue;
			}
			struct sockaddr_in saddr;
			saddr.sin_family = AF_INET;
			memcpy(&saddr.sin_addr, &iaddr, sizeof(iaddr));
			saddr.sin_port = htons(bindPort);
			int tmp = 1;
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				(const char *) &tmp, sizeof(tmp));
			if (bind(fd, (struct sockaddr *)
				&saddr, sizeof(saddr)) == SOCKET_ERROR)
			{
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "couldn't bind to "
					"address %s port %d (%m)\n",
					bindAddress, bindPort);
				closesocket(fd);
				continue;
			}
			if (listen(fd, RINETD_LISTEN_BACKLOG) == SOCKET_ERROR) {
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "couldn't listen to "
					"address %s port %d (%m)\n",
					bindAddress, bindPort);
				closesocket(fd);
				continue;
			}
			ioctlsocket(fd, FIONBIO, &tmp);
			if (getAddress(connectAddress, &iaddr) < 0) {
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "host %s could not be "
					"resolved on file %s, line %d.\n",
					bindAddress, options.conf_file, lnum);
				closesocket(fd);
				continue;
			}
			/* Allocate server info */
			seInfo = (ServerInfo *)
				realloc(seInfo, sizeof(ServerInfo) * (seTotal + 1));
			if (!seInfo) {
				goto lowMemory;
			}
			ServerInfo *srv = &seInfo[seTotal];
			memset(srv, 0, sizeof(*srv));
			srv->fd = fd;
			srv->localAddr = iaddr;
			srv->localPort = htons(connectPort);
			srv->fromHost = strdup(bindAddress);
			if (!srv->fromHost) {
				goto lowMemory;
			}
			srv->fromPort = bindPort;
			srv->toHost = strdup(connectAddress);
			if (!srv->toHost) {
				goto lowMemory;
			}
			srv->toPort = connectPort;
#ifndef _WIN32
			if (fd > maxfd) {
				maxfd = fd;
			}
#endif
			++seTotal;
		}
	}
	fclose(in);
	/* Open the log file */
	if (logFile) {
		fclose(logFile);
		logFile = NULL;
	}
	if (logFileName) {
		logFile = fopen(logFileName, "a");
		if (logFile) {
			setvbuf(logFile, NULL, _IONBF, 0);
		} else {
			syslog(LOG_ERR, "could not open %s to append (%m).\n",
				logFileName);
		}
	}
	return;
lowMemory:
	syslog(LOG_ERR, "not enough memory to start rinetd.\n");
	exit(1);
}

static int getConfLine(FILE *in, char *line, int space, int *lnum)
{
	while (1) {
		(*lnum)++;
		if (!fgets(line, space, in)) {
			return 0;
		}
		char const *p = line;
		while (isspace(*p)) {
			p++;
		}
		if (!(*p)) {
			/* Blank lines are OK */
			continue;
		}
		if (*p == '#') {
			/* Comment lines are also OK */
			continue;
		}
		return 1;
	}
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

static void selectPass(void) {

	int const fdSetCount = maxfd / FD_SETSIZE + 1;
#	define FD_ZERO_EXT(ar) for (int i = 0; i < fdSetCount; ++i) { FD_ZERO(&(ar)[i]); }
#	define FD_SET_EXT(fd, ar) FD_SET((fd) % FD_SETSIZE, &(ar)[(fd) / FD_SETSIZE])
#	define FD_ISSET_EXT(fd, ar) FD_ISSET((fd) % FD_SETSIZE, &(ar)[(fd) / FD_SETSIZE])

	fd_set readfds[fdSetCount], writefds[fdSetCount];
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
			}
			/* Send more output if we have any, or if we’re closing */
			if (cnx->remote.sentPos < cnx->local.recvPos || cnx->coClosing) {
				FD_SET_EXT(cnx->remote.fd, writefds);
			}
		}
	}
	select(maxfd + 1, readfds, writefds, 0, 0);
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		if (cnx->remote.fd != INVALID_SOCKET) {
			if (FD_ISSET_EXT(cnx->remote.fd, readfds)) {
				handleRead(cnx, &cnx->remote, &cnx->local);
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
	int got = recv(socket->fd, socket->buffer + socket->recvPos,
		RINETD_BUFFER_SIZE - socket->recvPos, 0);
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
	socket->recvBytes += got;
	socket->recvPos += got;
}

static void handleWrite(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
	if (cnx->coClosing && (socket->sentPos == other_socket->recvPos)) {
		PERROR("rinetd: local closed and no more output");
		logEvent(cnx, cnx->server, cnx->coLog);
		closesocket(socket->fd);
		socket->fd = INVALID_SOCKET;
		return;
	}
	int got = send(socket->fd, other_socket->buffer + socket->sentPos,
		other_socket->recvPos - socket->sentPos, 0);
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
	socket->sentBytes += got;
	if (socket->sentPos == other_socket->recvPos) {
		socket->sentPos = other_socket->recvPos = 0;
	}
}

static void handleClose(ConnectionInfo *cnx, Socket *socket, Socket *other_socket)
{
	cnx->coClosing = 1;
	/* One end fizzled out, so make sure we're all done with that */
	closesocket(socket->fd);
	socket->fd = INVALID_SOCKET;
	if (other_socket->fd != INVALID_SOCKET) {
#ifndef __linux__
#ifndef _WIN32
		/* Now set up the other end for a polite closing */

		/* Request a low-water mark equal to the entire
			output buffer, so the next write notification
			tells us for sure that we can close the socket. */
		int arg = 1024;
		setsockopt(other_socket->fd, SOL_SOCKET, SO_SNDLOWAT,
			&arg, sizeof(arg));
#endif /* _WIN32 */
#endif /* __linux__ */
		cnx->coLog = socket == &cnx->local ?
			logLocalClosedFirst : logRemoteClosedFirst;
	}
}

static void handleAccept(ServerInfo const *srv)
{
	ConnectionInfo *cnx = findAvailableConnection();
	if (!cnx) {
		return;
	}

	struct sockaddr addr;
	struct in_addr address;
#if HAVE_SOCKLEN_T
	socklen_t addrlen;
#else
	int addrlen;
#endif
	addrlen = sizeof(addr);
	SOCKET nfd = accept(srv->fd, &addr, &addrlen);
	if (nfd == INVALID_SOCKET) {
		syslog(LOG_ERR, "accept(%d): %m", srv->fd);
		logEvent(NULL, srv, logAcceptFailed);
		return;
	}

	int tmp = 1;
	ioctlsocket(nfd, FIONBIO, &tmp);
#ifndef _WIN32
	tmp = 0;
	setsockopt(nfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
#endif

	cnx->local.fd = INVALID_SOCKET;
	cnx->local.recvPos = cnx->local.sentPos = 0;
	cnx->local.recvBytes = cnx->local.sentBytes = 0;
	cnx->remote.fd = nfd;
	cnx->remote.recvPos = cnx->remote.sentPos = 0;
	cnx->remote.recvBytes = cnx->remote.sentBytes = 0;
	cnx->coClosing = 0;
	cnx->coLog = logUnknownError;
	cnx->server = srv;

	struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
	cnx->reAddresses.s_addr = address.s_addr = sin->sin_addr.s_addr;
	char const *addressText = inet_ntoa(address);

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
		refuse(cnx, logNotAllowed);
		return;
	}
	/* 2. Check global deny rules. If it matches
		any of the global deny rules, kick it out. */
	for (int j = 0; j < globalRulesCount; ++j) {
		if (allRules[j].type == denyRule
			&& match(addressText, allRules[j].pattern)) {
			refuse(cnx, logDenied);
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
		refuse(cnx, logNotAllowed);
		return;
	}
	/* 4. Check deny rules specific to this forwarding rule. If
		it matches any of the deny rules, kick it out. */
	for (int j = 0; j < srv->rulesCount; ++j) {
		if (allRules[srv->rulesStart + j].type == denyRule
			&& match(addressText, allRules[srv->rulesStart + j].pattern)) {
			refuse(cnx, logDenied);
		}
	}
	/* Now open a connection to the local server.
		This, too, is nonblocking. Why wait
		for anything when you don't have to? */
	struct sockaddr_in saddr;
	cnx->local.fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (cnx->local.fd == INVALID_SOCKET) {
		syslog(LOG_ERR, "socket(): %m");
		closesocket(cnx->remote.fd);
		cnx->remote.fd = INVALID_SOCKET;
		logEvent(cnx, srv, logLocalSocketFailed);
		return;
	}

#if 0 // You don't need bind(2) on a socket you'll use for connect(2).
	/* Bind the local socket */
	saddr.sin_family = AF_INET;
	saddr.sin_port = INADDR_ANY;
	saddr.sin_addr.s_addr = 0;
	if (bind(cnx->local.fd, (struct sockaddr *) &saddr, sizeof(saddr)) == SOCKET_ERROR) {
		closesocket(cnx->local.fd);
		closesocket(cnx->remote.fd);
		cnx->remote.fd = INVALID_SOCKET;
		cnx->local.fd = INVALID_SOCKET;
		logEvent(cnx, srv, logLocalBindFailed);
		return;
	}
#endif

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr, &srv->localAddr, sizeof(struct in_addr));
	saddr.sin_port = srv->localPort;

#ifndef _WIN32
#ifdef __linux__
	tmp = 0;
	setsockopt(cnx->local.fd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
#else
	tmp = 1024;
	setsockopt(cnx->local.fd, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(tmp));
#endif /* __linux__ */
#endif /* _WIN32 */
	tmp = 1;
	ioctlsocket(cnx->local.fd, FIONBIO, &tmp);

	if (connect(cnx->local.fd, (struct sockaddr *)&saddr,
		sizeof(struct sockaddr_in)) == INVALID_SOCKET)
	{
		if ((GetLastError() != WSAEINPROGRESS) &&
			(GetLastError() != WSAEWOULDBLOCK))
		{
			PERROR("rinetd: connect");
			closesocket(cnx->local.fd);
			closesocket(cnx->remote.fd);
			cnx->remote.fd = INVALID_SOCKET;
			cnx->local.fd = INVALID_SOCKET;
			logEvent(cnx, srv, logLocalConnectFailed);
			return;
		}
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

static void refuse(ConnectionInfo *cnx, int logCode)
{
	/* Local fd is not open yet when we refuse(), so only
		close the remote socket. */
	closesocket(cnx->remote.fd);
	cnx->remote.fd = INVALID_SOCKET;
	logEvent(cnx, cnx->server, logCode);
}

static int getAddress(char const *host, struct in_addr *iaddr)
{
	/* If this is an IP address, use inet_addr() */
	int is_ipaddr = 1;
	for (char const *p = host; *p; ++p) {
		if (!isdigit(*p) && *p != '.') {
			is_ipaddr = 0;
			break;
		}
	}
	if (is_ipaddr) {
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
	syslog(LOG_ERR, "While resolving `%s' got: %s", host, msg);
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
	syslog(LOG_INFO, "Received SIGHUP, reloading configuration...");
	/* Learn the new rules */
	clearConfiguration();
	readConfiguration();
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

void registerPID(void)
{
	char const *pid_file_name = RINETD_PID_FILE;
	if (pidLogFileName) {
		pid_file_name = pidLogFileName;
	}
/* add other systems with wherever they register processes */
#if	defined(__linux__)
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
#endif	/* __linux__ */
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
	int bytesOutput = 0;
	int bytesInput = 0;
	if (cnx != NULL) {
		struct in_addr const *reAddress = &cnx->reAddresses;
		addressText = inet_ntoa(*reAddress);
		bytesOutput = cnx->remote.sentBytes;
		bytesInput = cnx->remote.recvBytes;
	}

	char const *fromHost = "?";
	int fromPort = 0;
	char const *toHost =  "?";
	int toPort =  0;
	if (srv != NULL) {
		fromHost = srv->fromHost;
		fromPort = srv->fromPort;
		toHost = srv->toHost;
		toPort = srv->toPort;
	}

	if (result==logNotAllowed || result==logDenied)
		syslog(LOG_INFO, "%s %s"
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
				"200 %d - - - %d\n",
				addressText,
				tstr,
				sign,
				timz / 60,
				timz % 60,
				fromHost, fromPort,
				toHost, toPort,
				logMessages[result],
				bytesOutput,
				bytesInput);
		} else {
			/* Write an rinetd-specific log entry with a
				less goofy format. */
			fprintf(logFile, "%s\t%s\t%s\t%d\t%s\t%d\t%d"
					"\t%d\t%s\n",
				tstr,
				addressText,
				fromHost, fromPort,
				toHost, toPort,
				bytesInput,
				bytesOutput,
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

static struct tm *get_gmtoff(int *tz) {
	time_t tt = time(NULL);
	struct tm gmt;
	struct tm *t;
	int days, hours, minutes;

	/* Assume we are never more than 24 hours away. */
	gmt = *gmtime(&tt); /* remember gmtime/localtime return ptr to static */
	t = localtime(&tt); /* buffer... so be careful */
	days = t->tm_yday - gmt.tm_yday;
	hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24)
		+ t->tm_hour - gmt.tm_hour);
	minutes = hours * 60 + t->tm_min - gmt.tm_min;
	*tz = minutes;
	return t;
}

