#if HAVE_CONFIG_H
#	include <config.h>
#endif

#ifndef RETSIGTYPE
#	define RETSIGTYPE void
#endif

#ifdef WIN32
#	include <windows.h>
#	include <winsock.h>
#	include "getopt.h"
#	define syslog fprintf
#	define LOG_ERR stderr
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
#endif /* WIN32 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#if WIN32 || (!TIME_WITH_SYS_TIME && !HAVE_SYS_TIME_H)
#	include <time.h>
#endif
#include <ctype.h>

#ifndef WIN32
	/* Windows sockets compatibility defines */
#	define INVALID_SOCKET (-1)
#	define SOCKET_ERROR (-1)
static int closesocket(int s) {
	return close(s);
}
#	define ioctlsocket ioctl
#	define MAKEWORD(a, b)
#	define WSAStartup(a, b) (0)
#	define	WSACleanup()
#	ifdef __MAC__
		/* The constants for these are a little screwy in the prelinked
			MSL GUSI lib and we can't rebuild it, so roll with it */
#		define WSAEWOULDBLOCK EWOULDBLOCK
#		define WSAEAGAIN EAGAIN
#		define WSAEINPROGRESS EINPROGRESS
#	else
#		define WSAEWOULDBLOCK EWOULDBLOCK
#		define WSAEAGAIN EAGAIN
#		define WSAEINPROGRESS EINPROGRESS
#	endif /* __MAC__ */
#	define WSAEINTR EINTR
#	define SOCKET int
#	define GetLastError() (errno)
typedef struct {
	int dummy;
} WSADATA;
#else
	/* WIN32 doesn't really have WSAEAGAIN */
#	ifndef WSAEAGAIN
#		define WSAEAGAIN WSAEWOULDBLOCK
#	endif
#endif /* WIN32 */

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

typedef struct _server_info ServerInfo;
struct _server_info
{
	SOCKET fd;

	/* In network order, for network purposes */
	struct in_addr localAddr;
	unsigned short localPort;

	/* In ASCII and local byte order, for logging purposes */
	char *fromHost, *toHost;
	int fromPort, toPort;

	/* Offsets into list of allow and deny rules. Any rules
		prior to globalAllowRules and globalDenyRules are global rules. */
	int allowRules, denyRules;
	int allowRulesTotal, denyRulesTotal;
};

ServerInfo *seInfo = 0;

int globalAllowRules = 0;
int globalDenyRules = 0;

typedef struct _connection_info ConnectionInfo;
struct _connection_info
{
	SOCKET reFd, loFd;
	struct in_addr reAddresses;
	int inputRPos, inputWPos;
	int outputRPos, outputWPos;
	int bytesInput, bytesOutput;
	int coClosed;
	int coClosing;
	int reClosed; // remote closed
	int loClosed; // local closed
	int coLog;
	int server; // only useful for logEvent
	char *input, *output;
};

ConnectionInfo *coInfo = 0;

char **allowRules = 0;
char **denyRules = 0;
int *denyRulesFor = 0;
int seTotal = 0;
int coTotal = 0;
int allowRulesTotal = 0;
int denyRulesTotal = 0;
int maxfd = 0;
char *logFileName = 0;
char *pidLogFileName = 0;
int logFormatCommon = 0;
FILE *logFile = 0;

/*
	se: (se)rver sockets
	re: (re)mote sockets
	lo: (lo)cal sockets (being redirected to)
	co: connections
*/

static int const bufferSpace = 1024;

void readConfiguration();

/* Signal handlers */
RETSIGTYPE plumber(int s);
RETSIGTYPE hup(int s);
RETSIGTYPE term(int s);

void initArrays(void);
void RegisterPID(void);

void selectLoop(void);

void logEvent(ConnectionInfo const *cnx, int i, int result);

int getAddress(char *host, struct in_addr *iaddr);

char const *logMessages[] = {
	"done-local-closed",
	"done-remote-closed",
	"accept-failed -",
	0,
	"local-socket-failed -",
	0,
	"local-bind-failed -",
	0,
	"local-connect-failed -",
	0,
	"opened",
	0,
	"not-allowed",
	0,
	"denied",
	0,
};

enum
{
	logDone = 0,
	logAcceptFailed = 2,
	logLocalSocketFailed = 4,
	logLocalBindFailed = 6,
	logLocalConnectFailed = 8,
	logOpened = 10,
	logNotAllowed = 12,
	logDenied = 14,

	logLocalClosedFirst = 0,
	logRemoteClosedFirst = 1,
};

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
	char const *conf_file;
	int foreground;
};

RinetdOptions options = {
	"/etc/rinetd.conf",
	0,
};

int readArgs (int argc,
	char **argv,
	RinetdOptions *options);

int main(int argc, char *argv[])
{
#ifdef WIN32
	WSADATA wsaData;
#endif
	int result;
#ifndef WIN32
	openlog("rinetd", LOG_PID, LOG_DAEMON);
#endif
	result = WSAStartup(MAKEWORD(1, 1), &wsaData);
	if (result != 0) {
		fprintf(stderr, "Your computer was not connected "
			"to the Internet at the time that "
			"this program was launched, or you "
			"do not have a 32-bit "
			"connection to the Internet.");
		exit(1);
	}
	readArgs(argc, argv, &options);
#ifndef WIN32
#ifdef DEBUG
	{
#elif HAVE_DAEMON
	if (options.foreground || !daemon(0, 0)) {
#else
	if (options.foreground || !fork()) {
#endif
#ifdef HAVE_SIGACTION
			struct sigaction act;
			act.sa_handler=SIG_IGN;
			sigemptyset (&act.sa_mask);
			act.sa_flags=SA_RESTART;
			sigaction(SIGPIPE, &act, NULL);
			act.sa_handler=&hup;
			sigaction(SIGHUP, &act, NULL);
#else
			signal(SIGPIPE, plumber);
			signal(SIGHUP, hup);
#endif
#endif /* WIN32 */
			signal(SIGTERM, term);
			initArrays();
			readConfiguration();
			RegisterPID();
			syslog(LOG_INFO, "Starting redirections...");
			selectLoop();
#ifndef WIN32
#ifndef DEBUG
	} else {
		exit(0);
#endif
	}
#endif /* WIN32 */
	return 0;
}

int getConfLine(FILE *in, char *line, int space, int *lnum);

int patternBad(char *pattern);

void readConfiguration(void)
{
	FILE *in;
	char line[16384];
	int lnum = 0;
	int ai;
	int di;
	if (seInfo) {
		/* Close existing server sockets. */
		for (int i = 0; i < seTotal; ++i) {
			ServerInfo *srv = &seInfo[i];
			if (srv->fd != -1) {
				closesocket(srv->fd);
				free(srv->fromHost);
				free(srv->toHost);
			}
		}
		/* Free memory associated with previous set. */
		free(seInfo);
	}
	seTotal = 0;
	if (allowRules) {
		/* Forget existing allow rules. */
		for (int i = 0; i < allowRulesTotal; ++i) {
			free(allowRules[i]);
		}
		/* Free memory associated with previous set. */
		free(allowRules);
		globalAllowRules = 0;
	}
	allowRulesTotal = 0;
	if (denyRules) {
		/* Forget existing deny rules. */
		for (int i = 0; i < denyRulesTotal; ++i) {
			free(denyRules[i]);
		}
		/* Free memory associated with previous set. */
		free(denyRules);
		globalDenyRules = 0;
	}
	denyRulesTotal = 0;
	if (logFileName) {
		free(logFileName);
		logFileName = 0;
	}
	if (pidLogFileName) {
		free(pidLogFileName);
		pidLogFileName = 0;
	}
	/* 1. Count the non-comment lines of each type and
		allocate space for the data. */
	in = fopen(options.conf_file, "r");
	if (!in) {
		fprintf(stderr, "rinetd: can't open %s\n", options.conf_file);
		exit(1);
	}
	while (1) {
		char *t = 0;
		if (!getConfLine(in, line, sizeof(line), &lnum)) {
			break;
		}
		t = strtok(line, " \t\r\n");
		if (!strcmp(t, "logfile")) {
			continue;
		} else if (!strcmp(t, "pidlogfile")) {
			continue;
		} else if (!strcmp(t, "logcommon")) {
			continue;
		} else if (!strcmp(t, "allow")) {
			allowRulesTotal++;
		} else if (!strcmp(t, "deny")) {
			denyRulesTotal++;
		} else {
			/* A regular forwarding rule */
			seTotal++;
		}
	}
	fclose(in);
	seInfo = (ServerInfo *) malloc(sizeof(ServerInfo) * seTotal);
	if (!seInfo) {
		goto lowMemory;
	}
	for (int i = 0; i < seTotal; ++i) {
		memset(&seInfo[i], 0, sizeof(seInfo[i]));
		seInfo[i].fd = INVALID_SOCKET;
	}
	allowRules = (char **)
		malloc(sizeof(char *) * allowRulesTotal);
	if (!allowRules) {
		goto lowMemory;
	}
	denyRules = (char **)
		malloc(sizeof(char *) * denyRulesTotal);
	if (!denyRules) {
		goto lowMemory;
	}
	/* 2. Make a second pass to configure them. */
	ai = 0;
	di = 0;
	lnum = 0;
	in = fopen(options.conf_file, "r");
	if (!in) {
		goto lowMemory;
	}
	for (int i = 0; ; ) {
		char *bindAddress;
		unsigned int bindPort;
		char *connectAddress;
		char *bindPortS;
		char *connectPortS;
		unsigned int connectPort;
		struct in_addr iaddr;
		struct sockaddr_in saddr;
		struct servent *service;
		if (!getConfLine(in, line, sizeof(line), &lnum)) {
			break;
		}
		bindAddress = strtok(line, " \t\r\n");
		if (!bindAddress) {
			syslog(LOG_ERR, "no bind address specified "
				"on file %s, line %d.\n", options.conf_file, lnum);
			continue;
		}
		if (!strcmp(bindAddress, "allow")) {
			char *pattern = strtok(0, " \t\r\n");
			if (!pattern) {
				syslog(LOG_ERR, "nothing to allow "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			if (patternBad(pattern)) {
				syslog(LOG_ERR, "illegal allow or "
					"deny pattern. Only digits, ., and\n"
					"the ? and * wild cards are allowed. "
					"For performance reasons, rinetd\n"
					"does not look up complete "
					"host names.\n");
				continue;
			}

			allowRules[ai] = strdup(pattern);
			if (!allowRules[ai]) {
				goto lowMemory;
			}
			if (i > 0) {
				if (seInfo[i - 1].allowRulesTotal == 0) {
					seInfo[i - 1].allowRules = ai;
				}
				seInfo[i - 1].allowRulesTotal++;
			} else {
				globalAllowRules++;
			}
			ai++;
		} else if (!strcmp(bindAddress, "deny")) {
			char *pattern = strtok(0, " \t\r\n");
			if (!pattern) {
				syslog(LOG_ERR, "nothing to deny "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			denyRules[di] = strdup(pattern);
			if (!denyRules[di]) {
				goto lowMemory;
			}
			if (i > 0) {
				if (seInfo[i - 1].denyRulesTotal == 0) {
					seInfo[i - 1].denyRules = di;
				}
				seInfo[i - 1].denyRulesTotal++;
			} else {
				globalDenyRules++;
			}
			di++;
		} else if (!strcmp(bindAddress, "logfile")) {
			char *nt = strtok(0, " \t\r\n");
			if (!nt) {
				syslog(LOG_ERR, "no log file name "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			logFileName = strdup(nt);
			if (!logFileName) {
				goto lowMemory;
			}
		} else if (!strcmp(bindAddress, "pidlogfile")) {
			char *nt = strtok(0, " \t\r\n");
			if (!nt) {
				syslog(LOG_ERR, "no PID log file name "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			pidLogFileName = strdup(nt);
			if (!pidLogFileName) {
				goto lowMemory;
			}
		} else if (!strcmp(bindAddress, "logcommon")) {
			logFormatCommon = 1;
		} else {
			/* A regular forwarding rule. */
			ServerInfo *srv = &seInfo[i];
			bindPortS = strtok(0, " \t\r\n");
			if (!bindPortS) {
				syslog(LOG_ERR, "no bind port "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			service = getservbyname(bindPortS, "tcp");
			if (service) {
				bindPort = ntohs(service->s_port);
			} else {
				bindPort = atoi(bindPortS);
			}
			if (bindPort == 0 || bindPort >= 65536) {
				syslog(LOG_ERR, "bind port missing "
					"or out of range on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			connectAddress = strtok(0, " \t\r\n");
			if (!connectAddress) {
				syslog(LOG_ERR, "no connect address "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			connectPortS = strtok(0, " \t\r\n");
			if (!connectPortS) {
				syslog(LOG_ERR, "no connect port "
					"specified on file %s, line %d.\n", options.conf_file, lnum);
				continue;
			}
			service = getservbyname(connectPortS, "tcp");
			if (service) {
				connectPort = ntohs(service->s_port);
			} else {
				connectPort = atoi(connectPortS);
			}
			if (connectPort == 0 || connectPort >= 65536) {
				syslog(LOG_ERR, "bind port missing "
					"or out of range on file %s,  %d.\n", options.conf_file, lnum);
				continue;
			}
			/* Turn all of this stuff into reasonable addresses */
			if (!getAddress(bindAddress, &iaddr)) {
				fprintf(stderr, "rinetd: host %s could not be "
					"resolved on line %d.\n",
					bindAddress, lnum);
				continue;
			}
			/* Make a server socket */
			srv->fd = socket(PF_INET, SOCK_STREAM, 0);
			if (srv->fd == INVALID_SOCKET) {
				syslog(LOG_ERR, "couldn't create "
					"server socket! (%m)\n");
				srv->fd = -1;
				continue;
			}
#ifndef WIN32
			if (srv->fd > maxfd) {
				maxfd = srv->fd;
			}
#endif
			saddr.sin_family = AF_INET;
			memcpy(&saddr.sin_addr, &iaddr, sizeof(iaddr));
			saddr.sin_port = htons(bindPort);
			int tmp = 1;
			setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR,
				(const char *) &tmp, sizeof(tmp));
			if (bind(srv->fd, (struct sockaddr *)
				&saddr, sizeof(saddr)) == SOCKET_ERROR)
			{
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "couldn't bind to "
					"address %s port %d (%m)\n",
					bindAddress, bindPort);
				closesocket(srv->fd);
				srv->fd = INVALID_SOCKET;
				continue;
			}
			if (listen(srv->fd, 5) == SOCKET_ERROR) {
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "couldn't listen to "
					"address %s port %d (%m)\n",
					bindAddress, bindPort);
				closesocket(srv->fd);
				srv->fd = INVALID_SOCKET;
				continue;
			}
			ioctlsocket(srv->fd, FIONBIO, &tmp);
			if (!getAddress(connectAddress, &iaddr)) {
				/* Warn -- don't exit. */
				syslog(LOG_ERR, "host %s could not be "
					"resolved on file %s, line %d.\n",
					bindAddress, options.conf_file, lnum);
				closesocket(srv->fd);
				srv->fd = INVALID_SOCKET;
				continue;
			}
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
			i++;
		}
	}
	fclose(in);
	/* Open the log file */
	if (logFile) {
		fclose(logFile);
		logFile = 0;
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

int getConfLine(FILE *in, char *line, int space, int *lnum)
{
	char *p;
	while (1) {
		(*lnum)++;
		if (!fgets(line, space, in)) {
			return 0;
		}
		p = line;
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

void initArrays(void)
{
	coTotal = 64;
	coInfo = (ConnectionInfo *) malloc(sizeof(ConnectionInfo) * coTotal);
	if (!coInfo) {
		syslog(LOG_ERR, "not enough memory to start rinetd.\n");
		exit(1);
	}
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		memset(cnx, 0, sizeof(*cnx));
		cnx->coClosed = 1;
		cnx->input = (char *) malloc(sizeof(char) * 2 * bufferSpace);
		if (!cnx->input) {
			syslog(LOG_ERR, "not enough memory to start rinetd.\n");
			exit(1);
		}
		cnx->output = cnx->input + bufferSpace;
	}
}

void selectPass(void);

void selectLoop(void) {
	while (1) {
		selectPass();
	}
}

void handleRemoteWrite(ConnectionInfo *cnx);
void handleRemoteRead(ConnectionInfo *cnx);
void handleLocalWrite(ConnectionInfo *cnx);
void handleLocalRead(ConnectionInfo *cnx);
void handleCloseFromLocal(ConnectionInfo *cnx);
void handleCloseFromRemote(ConnectionInfo *cnx);
void handleAccept(int i);
void openLocalFd(int se, ConnectionInfo *cnx);
int getAddress(char *host, struct in_addr *iaddr);

void selectPass(void) {
	fd_set readfds, writefds;
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	/* Server sockets */
	for (int i = 0; i < seTotal; ++i) {
		if (seInfo[i].fd != INVALID_SOCKET) {
			FD_SET(seInfo[i].fd, &readfds);
		}
	}
	/* Connection sockets */
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		if (cnx->coClosed) {
			continue;
		}
		if (cnx->coClosing) {
			if (!cnx->reClosed) {
				FD_SET(cnx->reFd, &writefds);
			}
			if (!cnx->loClosed) {
				FD_SET(cnx->loFd, &writefds);
			}
		}
		/* Get more input if we have room for it */
		if ((!cnx->reClosed) && (cnx->inputRPos < bufferSpace)) {
			FD_SET(cnx->reFd, &readfds);
		}
		/* Send more output if we have any */
		if ((!cnx->reClosed) && (cnx->outputWPos < cnx->outputRPos)) {
			FD_SET(cnx->reFd, &writefds);
		}
		/* Accept more output from the local
			server if there's room */
		if ((!cnx->loClosed) && (cnx->outputRPos < bufferSpace)) {
			FD_SET(cnx->loFd, &readfds);
		}
		/* Send more input to the local server
			if we have any */
		if ((!cnx->loClosed) && (cnx->inputWPos < cnx->inputRPos)) {
			FD_SET(cnx->loFd, &writefds);
		}
	}
	select(maxfd + 1, &readfds, &writefds, 0, 0);
	for (int i = 0; i < seTotal; ++i) {
		if (seInfo[i].fd != -1) {
			if (FD_ISSET(seInfo[i].fd, &readfds)) {
				handleAccept(i);
			}
		}
	}
	for (int i = 0; i < coTotal; ++i) {
		ConnectionInfo *cnx = &coInfo[i];
		if (cnx->coClosed) {
			continue;
		}
		if (!cnx->reClosed) {
			if (FD_ISSET(cnx->reFd, &readfds)) {
				handleRemoteRead(cnx);
			}
		}
		if (!cnx->reClosed) {
			if (FD_ISSET(cnx->reFd, &writefds)) {
				handleRemoteWrite(cnx);
			}
		}
		if (!cnx->loClosed) {
			if (FD_ISSET(cnx->loFd, &readfds)) {
				handleLocalRead(cnx);
			}
		}
		if (!cnx->loClosed) {
			if (FD_ISSET(cnx->loFd, &writefds)) {
				handleLocalWrite(cnx);
			}
		}
		if (cnx->loClosed && cnx->reClosed) {
			cnx->coClosed = 1;
		}
	}
}

void handleRemoteRead(ConnectionInfo *cnx)
{
	int got;
	if (bufferSpace == cnx->inputRPos) {
		return;
	}
	got = recv(cnx->reFd, cnx->input + cnx->inputRPos,
		bufferSpace - cnx->inputRPos, 0);
	if (got == 0) {
		/* Prepare for closing */
		handleCloseFromRemote(cnx);
		return;
	}
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
		handleCloseFromRemote(cnx);
		return;
	}
	cnx->bytesInput += got;
	cnx->inputRPos += got;
}

void handleRemoteWrite(ConnectionInfo *cnx)
{
	int got;
	if (cnx->coClosing && (cnx->outputWPos == cnx->outputRPos)) {
		cnx->reClosed = 1;
		cnx->coClosed = 1;
		PERROR("rinetd: local closed and no more output");
		logEvent(cnx, cnx->server, logDone | cnx->coLog);
		closesocket(cnx->reFd);
		return;
	}
	got = send(cnx->reFd, cnx->output + cnx->outputWPos,
		cnx->outputRPos - cnx->outputWPos, 0);
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
		handleCloseFromRemote(cnx);
		return;
	}
	cnx->outputWPos += got;
	if (cnx->outputWPos == cnx->outputRPos) {
		cnx->outputWPos = 0;
		cnx->outputRPos = 0;
	}
	cnx->bytesOutput += got;
}

void handleLocalRead(ConnectionInfo *cnx)
{
	int got;
	if (bufferSpace == cnx->outputRPos) {
		return;
	}
	got = recv(cnx->loFd, cnx->output + cnx->outputRPos,
		bufferSpace - cnx->outputRPos, 0);
	if (got == 0) {
		handleCloseFromLocal(cnx);
		return;
	}
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
		handleCloseFromLocal(cnx);
		return;
	}
	cnx->outputRPos += got;
}

void handleLocalWrite(ConnectionInfo *cnx)
{
	int got;
	if (cnx->coClosing && (cnx->inputWPos == cnx->inputRPos)) {
		cnx->loClosed = 1;
		cnx->coClosed = 1;
		PERROR("remote closed and no more input");
		logEvent(cnx, cnx->server, logDone | cnx->coLog);
		closesocket(cnx->loFd);
		return;
	}
	got = send(cnx->loFd, cnx->input + cnx->inputWPos,
		cnx->inputRPos - cnx->inputWPos, 0);
	if (got < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return;
		}
		handleCloseFromLocal(cnx);
		return;
	}
	cnx->inputWPos += got;
	if (cnx->inputWPos == cnx->inputRPos) {
		cnx->inputWPos = 0;
		cnx->inputRPos = 0;
	}
}

void handleCloseFromLocal(ConnectionInfo *cnx)
{
	cnx->coClosing = 1;
	/* The local end fizzled out, so make sure
		we're all done with that */
	PERROR("close from local");
	closesocket(cnx->loFd);
	cnx->loClosed = 1;
	if (!cnx->reClosed) {
#ifndef __linux__
#ifndef WIN32
		/* Now set up the remote end for a polite closing */

		/* Request a low-water mark equal to the entire
			output buffer, so the next write notification
			tells us for sure that we can close the socket. */
		int arg = 1024;
		setsockopt(cnx->reFd, SOL_SOCKET, SO_SNDLOWAT,
			&arg, sizeof(arg));
#endif /* WIN32 */
#endif /* __linux__ */
		cnx->coLog = logLocalClosedFirst;
	}
}

void handleCloseFromRemote(ConnectionInfo *cnx)
{
	cnx->coClosing = 1;
	/* The remote end fizzled out, so make sure
		we're all done with that */
	PERROR("close from remote");
	closesocket(cnx->reFd);
	cnx->reClosed = 1;
	if (!cnx->loClosed) {
#ifndef __linux__
#ifndef WIN32
		/* Now set up the local end for a polite closing */

		/* Request a low-water mark equal to the entire
			output buffer, so the next write notification
			tells us for sure that we can close the socket. */
		int arg = 1024;
		setsockopt(cnx->loFd, SOL_SOCKET, SO_SNDLOWAT,
			&arg, sizeof(arg));
#endif /* WIN32 */
#endif /* __linux__ */
		cnx->loClosed = 0;
		cnx->coLog = logRemoteClosedFirst;
	}
}

void refuse(ConnectionInfo *cnx, int logCode);

void handleAccept(int i)
{
	ServerInfo *srv = &seInfo[i];
	ConnectionInfo *cnx = NULL;
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
		logEvent(NULL, i, logAcceptFailed);
		return;
	}
#ifndef WIN32
	if (nfd > maxfd) {
		maxfd = nfd;
	}
#endif /* WIN32 */

	int tmp = 1;
	ioctlsocket(nfd, FIONBIO, &tmp);
#ifndef WIN32
	tmp = 0;
	setsockopt(nfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
#endif

	for (int j = 0; j < coTotal; ++j) {
		if (coInfo[j].coClosed) {
			cnx = &coInfo[j];
			break;
		}
	}
	int o;
	if (cnx == NULL) {
		o = coTotal;
		coTotal *= 2;

		ConnectionInfo *newCoInfo = (ConnectionInfo *)
			malloc(sizeof(ConnectionInfo) * coTotal);
		if (!newCoInfo) {
			goto shortage;
		}
		memcpy(newCoInfo, coInfo, sizeof(ConnectionInfo) * o);
		free(coInfo);
		coInfo = newCoInfo;

		for (int j = o; j < coTotal; ++j) {
			memset(&coInfo[j], 0, sizeof(coInfo[j]));
			coInfo[j].coClosed = 1;
			coInfo[j].input = (char *)
				malloc(sizeof(char) * 2 * bufferSpace);
			if (!coInfo[j].input) {
				for (int k = o; k < j; ++k) {
					free(coInfo[k].input);
				}
				goto shortage;
			}
			coInfo[j].output = coInfo[j].input + bufferSpace;
		}
		cnx = &coInfo[o];
	}
	cnx->inputRPos = 0;
	cnx->inputWPos = 0;
	cnx->outputRPos = 0;
	cnx->outputWPos = 0;
	cnx->coClosed = 0;
	cnx->coClosing = 0;
	cnx->reClosed = 0;
	cnx->loClosed = 0;
	cnx->reFd = nfd;
	cnx->bytesInput = 0;
	cnx->bytesOutput = 0;
	cnx->coLog = 0;
	cnx->server = i;
	struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
	cnx->reAddresses.s_addr = address.s_addr = sin->sin_addr.s_addr;
	char const *addressText = inet_ntoa(address);

	/* 1. Check global allow rules. If there are no
		global allow rules, it's presumed OK at
		this step. If there are any, and it doesn't
		match at least one, kick it out. */
	if (globalAllowRules) {
		int good = 0;
		for (int j = 0; j < globalAllowRules; ++j) {
			if (match(addressText, allowRules[j])) {
				good = 1;
				break;
			}
		}
		if (!good) {
			refuse(cnx, logNotAllowed);
			return;
		}
	}
	/* 2. Check global deny rules. If it matches
		any of the global deny rules, kick it out. */
	if (globalDenyRules) {
		for (int j = 0; j < globalDenyRules; ++j) {
			if (match(addressText, denyRules[j])) {
				refuse(cnx, logDenied);
			}
		}
	}
	/* 3. Check allow rules specific to this forwarding rule.
		If there are none, it's OK. If there are any,
		it must match at least one. */
	if (srv->allowRulesTotal) {
		int good = 0;
		for (int j = 0; j < srv->allowRulesTotal; ++j) {
			if (match(addressText,
				allowRules[srv->allowRules + j])) {
				good = 1;
				break;
			}
		}
		if (!good) {
			refuse(cnx, logNotAllowed);
			return;
		}
	}
	/* 2. Check deny rules specific to this forwarding rule. If
		it matches any of the deny rules, kick it out. */
	if (srv->denyRulesTotal) {
		for (int j = 0; j < srv->denyRulesTotal; ++j) {
			if (match(addressText,
				denyRules[srv->denyRules + j])) {
				refuse(cnx, logDenied);
			}
		}
	}
	/* Now open a connection to the local server.
		This, too, is nonblocking. Why wait
		for anything when you don't have to? */
	openLocalFd(i, cnx);
	return;
shortage:
	syslog(LOG_ERR, "not enough memory to add slots. "
		"Currently %d slots.\n", o);
	/* Go back to the previous total number of slots */
	coTotal = o;
}

void openLocalFd(int se, ConnectionInfo *cnx)
{
	struct sockaddr_in saddr;
	cnx->loFd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (cnx->loFd == INVALID_SOCKET) {
		syslog(LOG_ERR, "socket(): %m");
		closesocket(cnx->reFd);
		cnx->reClosed = 1;
		cnx->loClosed = 1;
		cnx->coClosed = 1;
		logEvent(cnx, cnx->server, logLocalSocketFailed);
		return;
	}
#ifndef WIN32
	if (cnx->loFd > maxfd) {
		maxfd = cnx->loFd;
	}
#endif /* WIN32 */

#if 0 // You don't need bind(2) on a socket you'll use for connect(2).
	/* Bind the local socket */
	saddr.sin_family = AF_INET;
	saddr.sin_port = INADDR_ANY;
	saddr.sin_addr.s_addr = 0;
	if (bind(cnx->loFd, (struct sockaddr *) &saddr, sizeof(saddr)) == SOCKET_ERROR) {
		closesocket(cnx->loFd);
		closesocket(cnx->reFd);
		cnx->reClosed = 1;
		cnx->loClosed = 1;
		cnx->coClosed = 1;
		logEvent(cnx, cnx->server, logLocalBindFailed);
		return;
	}
#endif

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr, &seInfo[se].localAddr, sizeof(struct in_addr));
	saddr.sin_port = seInfo[se].localPort;

	int tmp;
#ifndef WIN32
#ifdef __linux__
	tmp = 0;
	setsockopt(cnx->loFd, SOL_SOCKET, SO_LINGER, &tmp, sizeof(tmp));
#else
	tmp = 1024;
	setsockopt(cnx->loFd, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(tmp));
#endif /* __linux__ */
#endif /* WIN32 */
	tmp = 1;
	ioctlsocket(cnx->loFd, FIONBIO, &tmp);

	if (connect(cnx->loFd, (struct sockaddr *)&saddr,
		sizeof(struct sockaddr_in)) == INVALID_SOCKET)
	{
		if ((GetLastError() != WSAEINPROGRESS) &&
			(GetLastError() != WSAEWOULDBLOCK))
		{
			PERROR("rinetd: connect");
			closesocket(cnx->loFd);
			closesocket(cnx->reFd);
			cnx->reClosed = 1;
			cnx->loClosed = 1;
			cnx->coClosed = 1;
			logEvent(cnx, cnx->server, logLocalConnectFailed);
			return;
		}
	}
	logEvent(cnx, cnx->server, logOpened);
}

int getAddress(char *host, struct in_addr *iaddr)
{
	char *p = host;
	int ishost = 0;
	while (*p) {
		if (!isdigit(*p) && (*p) != '.') {
			ishost = 1;
			break;
		}
		p++;
	}
	if (ishost) {
		struct hostent *h = gethostbyname(host);
		if (!h) {
			const char *msg = "(unknown DNS error)";
			switch(h_errno)
			{
			case HOST_NOT_FOUND:
				msg = "The specified host is unknown.";
				break;
			case NO_ADDRESS:
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
			return 0;
		}
		memcpy(
			(void *) &iaddr->s_addr,
			(void *) h->h_addr,
			4);
		return 1;
	} else {
		iaddr->s_addr = inet_addr(host);
		return 1;
	}
}

#ifndef WIN32
#ifndef HAVE_SIGACTION
RETSIGTYPE plumber(int s)
{
	/* Just reinstall */
	signal(SIGPIPE, plumber);
}
#endif

RETSIGTYPE hup(int s)
{
	(void)s;
	syslog(LOG_INFO, "Received SIGHUP, reloading configuration...");
	/* Learn the new rules */
	readConfiguration();
#ifndef HAVE_SIGACTION
	/* And reinstall the signal handler */
	signal(SIGHUP, hup);
#endif
}
#endif /* WIN32 */

RETSIGTYPE term(int s)
{
	(void)s;
	/* Obey the request, but first flush the log */
	if (logFile) {
		fclose(logFile);
	}
	exit(0);
}

void RegisterPID(void)
{
	FILE *pid_file;
	char const *pid_file_name = "/var/run/rinetd.pid";
	if (pidLogFileName) {
		pid_file_name = pidLogFileName;
	}
/* add other systems with wherever they register processes */
#if	defined(__linux__)
	pid_file = fopen(pid_file_name, "w");
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

struct in_addr nullAddress = { 0 };

struct tm *get_gmtoff(int *tz);

void logEvent(ConnectionInfo const *cnx, int i, int result)
{
	ServerInfo const *srv = &seInfo[i];
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

	struct in_addr const *reAddress = &nullAddress;
	int bytesOutput = 0;
	int bytesInput = 0;
	if (cnx != NULL) {
		reAddress = &cnx->reAddresses;
		bytesOutput = cnx->bytesOutput;
		bytesInput = cnx->bytesInput;
	}
	char const *addressText = inet_ntoa(*reAddress);

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
				srv->fromHost, srv->fromPort,
				srv->toHost, srv->toPort,
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
				srv->fromHost, srv->fromPort,
				srv->toHost, srv->toPort,
				bytesInput,
				bytesOutput,
				logMessages[result]);
		}
	}
}

int readArgs (int argc,
	char **argv,
	RinetdOptions *options)
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
			options->conf_file = strdup(optarg);
			if (!options->conf_file) {
				syslog(LOG_ERR, "Not enough memory to "
					"launch rinetd.\n");
				exit(1);
			}
			break;
			case 'f':
			options->foreground=1;
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

struct tm *get_gmtoff(int *tz) {
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

int patternBad(char *pattern)
{
	char *p = pattern;
	while (*p) {
		if (isdigit(*p) || ((*p) == '?') || ((*p) == '*') ||
			((*p) == '.'))
		{
			p++;
		}
		return 0;
	}
	return 1;
}

void refuse(ConnectionInfo *cnx, int logCode)
{
	closesocket(cnx->reFd);
	cnx->reClosed = 1;
	cnx->loClosed = 1;
	cnx->coClosed = 1;
	logEvent(cnx, cnx->server, logCode);
}

