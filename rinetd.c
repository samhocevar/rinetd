#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#ifdef DEBUG
#define PERROR perror
#else
#define PERROR(x) 
#endif /* DEBUG */

int *seFds;
struct in_addr *seLocalAddrs;
unsigned short *seLocalPorts;
int *reFds;
int *loFds;
int *coInputRPos;
int *coInputWPos;
int *coOutputRPos;
int *coOutputWPos;
int *coClosed;
int *coClosing;
int *reClosed;
int *loClosed;
char **coInput;
char **coOutput;
int seTotal;
int coTotal;
int maxfd = 0;

/* If 'newsize' bytes can be allocated, *data is set to point
	to them, the previous data is copied, and 1 is returned. 
	If 'size' bytes cannot be allocated, *data is UNCHANGED,
	and 0 is returned. */	

#define SAFE_REALLOC(x, y, z) safeRealloc((void **) (x), (y), (z))

int safeRealloc(void **data, int oldsize, int newsize);

/* 
	se: (se)rver sockets
	re: (re)mote sockets
	lo: (lo)cal sockets (being redirected to)
	co: connections
*/

#define bufferSpace 1024

void createServerSockets();

/* Signal handlers */
void plumber(int s);
void hup(int s);

void initArrays();
void RegisterPID();

void selectLoop();

int main(int argc, char *argv[])
{
#ifndef DEBUG
	if (!fork()) {
		if (!fork()) {
#endif /* DEBUG */
			signal(SIGPIPE, plumber);
			signal(SIGHUP, hup);
			initArrays();
			RegisterPID();
			createServerSockets();
			selectLoop();
#ifndef DEBUG
		} else {
			exit(0);
		}
	} else {
		exit(0);
	}
#endif /* DEBUG */
	return 0;
}

int getConfLine(FILE *in, char *line, int space, int *lnum);

void createServerSockets()
{
	FILE *in;
	char line[16384];
	int lnum = 0;
	int i;
	if (seTotal) {
		/* Close existing server sockets. */
		for (i = 0; (i < seTotal); i++) {
			close(seFds[i]);
		}	
		/* Free memory associated with previous set. */
		free(seFds);
		free(seLocalAddrs);
		free(seLocalPorts);
	}
	seTotal = 0;
	/* 1. Count the non-comment lines and make room
		for that many server sockets. */
	in = fopen("/etc/rinetd.conf", "r");
	if (!in) {
		fprintf(stderr, "Can't open rinetd.conf\n");
		exit(1);
	}
	while (1) {
		if (!getConfLine(in, line, sizeof(line), &lnum)) {
			break;
		}
		seTotal++;	
	}	
	fclose(in);
	seFds = (int *) malloc(sizeof(int) * seTotal);	
	if (!seFds) {
		fprintf(stderr, "Not enough memory to start rinetd.\n");
		exit(1);
	}
	seLocalAddrs = (struct in_addr *) malloc(sizeof(struct in_addr) *
		seTotal);	
	if (!seLocalAddrs) {
		fprintf(stderr, "Not enough memory to start rinetd.\n");
		exit(1);
	}
	seLocalPorts = (unsigned short *) 
		malloc(sizeof(unsigned short) * seTotal);	
	if (!seLocalPorts) {
		fprintf(stderr, "Not enough memory to start rinetd.\n");
		exit(1);
	}
	/* 2. Make a second pass to configure them. */	
	i = 0;
	lnum = 0;
	in = fopen("/etc/rinetd.conf", "r");
	if (!in) {
		fprintf(stderr, "Can't open rinetd.conf\n");
		exit(1);
	}
	while (1) {
		char *bindAddress;
		unsigned short bindPort;
		char *connectAddress;
		char *tempS;
		unsigned short connectPort;
		struct in_addr iaddr;
		struct sockaddr_in saddr;
		struct servent *service;
		int j;
		if (!getConfLine(in, line, sizeof(line), &lnum)) {
			break;
		}
		bindAddress = strtok(line, " \t\r\n");
		if (!bindAddress) {
			fprintf(stderr, "No bind address specified "
				"on line %d.\n", lnum);	
			exit(1);
		}	
		tempS = strtok(0, " \t\r\n");
		if (!tempS) {
			fprintf(stderr, "No bind port specified "
				"on line %d.\n", lnum);	
			exit(1);
		}
		service = getservbyname(tempS, "tcp");	
		if (service) {
			bindPort = ntohs(service->s_port);
		} else {
			bindPort = atoi(tempS);
		}
		if ((bindPort == 0) || (bindPort >= 65536)) {
			fprintf(stderr, "Bind port missing or out "
				"of range on line %d.\n", lnum);
			exit(1);
		}
		connectAddress = strtok(0, " \t\r\n");
		if (!connectAddress) {
			fprintf(stderr, "No connect address specified "
				"on line %d.\n", lnum);	
			exit(1);
		}	
		tempS = strtok(0, " \t\r\n");
		if (!tempS) {
			fprintf(stderr, "No connect port specified "
				"on line %d.\n", lnum);	
			exit(1);
		}
		service = getservbyname(tempS, "tcp");	
		if (service) {
			connectPort = ntohs(service->s_port);
		} else {
			connectPort = atoi(tempS);
		}
		if ((connectPort == 0) || (connectPort >= 65536)) {
			fprintf(stderr, "Bind port missing or out "
				"of range on line %d.\n", lnum);
			exit(1);
		}
		/* Turn all of this stuff into reasonable addresses */
		if (!getAddress(bindAddress, &iaddr)) {
			fprintf(stderr, "Host %s could not be resolved "
				"on line %d.\n", bindAddress, lnum);
			exit(1);
		}	
		/* Make a server socket */
		seFds[i] = socket(PF_INET, SOCK_STREAM, 0);
		if (seFds[i] < 0) {
			fprintf(stderr, "Couldn't create server socket!\n");
			exit(1);
		}
		if (seFds[i] > maxfd) {
			maxfd = seFds[i];
		}
		saddr.sin_family = AF_INET;
		memcpy(&saddr.sin_addr, &iaddr, sizeof(iaddr));
		saddr.sin_port = htons(bindPort);
		j = 1;
		setsockopt(seFds[i], SOL_SOCKET, SO_REUSEADDR,
			&j, sizeof(j));
		if (bind(seFds[i], (struct sockaddr *) 
			&saddr, sizeof(saddr)) < 0) 
		{
			fprintf(stderr, "Couldn't bind to address %s port %d\n",
				bindAddress, bindPort);	
			exit(1);
		}
		if (listen(seFds[i], 5) < 0) {
			fprintf(stderr, "Couldn't listen to address %s "
				"port %d\n",
				bindAddress, bindPort);	
			exit(1);
		}
		fcntl(seFds[i], F_SETFL, O_NONBLOCK);
		if (!getAddress(connectAddress, &iaddr)) {
			fprintf(stderr, "Host %s could not be resolved "
				"on line %d.\n", bindAddress, lnum);
			exit(1);
		}	
		seLocalAddrs[i] = iaddr;
		seLocalPorts[i] = htons(connectPort);
		i++;
	}
}

int getConfLine(FILE *in, char *line, int space, int *lnum)
{
	char *p;
	while (1) {
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
		(*lnum)++;
		return 1;
	}
}

void initArrays()
{
	int j;
	coTotal = 64;
	reFds = (int *) malloc(sizeof(int) * coTotal);
	loFds = (int *) malloc(sizeof(int) * coTotal);
	coInputRPos = (int *) malloc(sizeof(int) * coTotal);
	coInputWPos = (int *) malloc(sizeof(int) * coTotal);
	coOutputRPos = (int *) malloc(sizeof(int) * coTotal);
	coOutputWPos = (int *) malloc(sizeof(int) * coTotal);
	coClosed = (int *) malloc(sizeof(int) * coTotal);
	coClosing = (int *) malloc(sizeof(int) * coTotal);
	reClosed = (int *) malloc(sizeof(int) * coTotal);
	loClosed = (int *) malloc(sizeof(int) * coTotal);
	coInput = (char **) malloc(sizeof(char *) * coTotal);
	coOutput = (char **) malloc(sizeof(char *) * coTotal);
	if ((!reFds) || (!loFds) || (!coInputRPos) || (!coInputWPos) ||
		(!coOutputRPos) || (!coOutputWPos) || 
		(!coClosed) || (!coClosing) ||
		(!reClosed) || (!loClosed) ||
		(!coInput) || (!coOutput))
	{
		fprintf(stderr, "Not enough memory to start rinetd.\n");
		exit(1);
	}	
	for (j = 0; (j < coTotal); j++) {
		coClosed[j] = 1;
		coInput[j] = (char *) malloc(sizeof(char) * bufferSpace);
		coOutput[j] = (char *) malloc(sizeof(char) * bufferSpace);
		if ((!coInput[j]) || (!coOutput[j])) {
			fprintf(stderr, "Not enough memory to start rinetd.\n");
			exit(1);
		}
	}
}

void selectPass();

void selectLoop() {
	while (1) {
		selectPass();
	}
}

void handleRemoteWrite(int i);
void handleRemoteRead(int i);
void handleLocalWrite(int i);
void handleLocalRead(int i);
void handleCloseFromLocal(int i);
void handleCloseFromRemote(int i);
void handleAccept(int i);
void openLocalFd(int se, int i);
int getAddress(char *host, struct in_addr *iaddr);

void selectPass() {
	int i;
	fd_set readfds, writefds;
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	/* Server sockets */
	for (i = 0; (i < seTotal); i++) {
		FD_SET(seFds[i], &readfds);
	}
	/* Connection sockets */
	for (i = 0; (i < coTotal); i++) {
		if (coClosed[i]) {
			continue;
		}
		if (coClosing[i]) {
			if (!reClosed[i]) {
				FD_SET(reFds[i], &writefds);
			}	
			if (!loClosed[i]) {
				FD_SET(loFds[i], &writefds);
			}	
		}
		/* Get more input if we have room for it */
		if ((!reClosed[i]) && (coInputRPos[i] < bufferSpace)) {
			FD_SET(reFds[i], &readfds);
		}
		/* Send more output if we have any */	
		if ((!reClosed[i]) && (coOutputWPos[i] < coOutputRPos[i])) {
			FD_SET(reFds[i], &writefds);
		}	
		/* Accept more output from the local 
			server if there's room */
		if ((!loClosed[i]) && (coOutputRPos[i] < bufferSpace)) {
			FD_SET(loFds[i], &readfds);
		}
		/* Send more input to the local server 
			if we have any */
		if ((!loClosed[i]) && (coInputWPos[i] < coInputRPos[i])) {
			FD_SET(loFds[i], &writefds);
		}	
	}
	select(maxfd + 1, &readfds, &writefds, 0, 0);
	for (i = 0; (i < seTotal); i++) {
		if (FD_ISSET(seFds[i], &readfds)) {
			handleAccept(i);
		}
	}
	for (i = 0; (i < coTotal); i++) {
		if (coClosed[i]) {
			continue;
		}
		if (!reClosed[i]) {
			if (FD_ISSET(reFds[i], &readfds)) {
				handleRemoteRead(i);
			}
		}
		if (!reClosed[i]) {
			if (FD_ISSET(reFds[i], &writefds)) {
				handleRemoteWrite(i);
			}
		}
		if (!loClosed[i]) {
			if (FD_ISSET(loFds[i], &readfds)) {
				handleLocalRead(i);
			}
		}
		if (!loClosed[i]) {
			if (FD_ISSET(loFds[i], &writefds)) {
				handleLocalWrite(i);
			}
		}
		if (loClosed[i] && reClosed[i]) {
			coClosed[i] = 1;
		}	
	}
}

void handleRemoteRead(int i)
{
	int got;
	if (bufferSpace == coInputRPos[i]) {
		return;
	}
	got = recv(reFds[i], coInput[i] + coInputRPos[i],
		bufferSpace - coInputRPos[i], 0);
	if (got == 0) {
		/* Prepare for closing */
		handleCloseFromRemote(i);
		return;
	}
	if (got < 0) {
		if (errno == EWOULDBLOCK) {
			return;
		}
		if (errno == EINPROGRESS) {
			return;
		}
		handleCloseFromRemote(i);
		return;
	}
	coInputRPos[i] += got;
}

void handleRemoteWrite(int i)
{
	int got;
	if (coClosing[i] && (coOutputWPos[i] == coOutputRPos[i])) {
		reClosed[i] = 1;
		coClosed[i] = 1;
		PERROR("local closed and no more output");
		close(reFds[i]);
		return;
	}
	got = send(reFds[i], coOutput[i] + coOutputWPos[i],
		coOutputRPos[i] - coOutputWPos[i], 0);
	if (got < 0) {
		if (errno == EWOULDBLOCK) {
			return;
		}
		if (errno == EINPROGRESS) {
			return;
		}
		handleCloseFromRemote(i);
		return;
	}
	coOutputWPos[i] += got;
	if (coOutputWPos[i] == coOutputRPos[i]) {
		coOutputWPos[i] = 0;
		coOutputRPos[i] = 0;
	}
}

void handleLocalRead(int i)
{
	int got;
	if (bufferSpace == coOutputRPos[i]) {
		return;
	}
	got = recv(loFds[i], coOutput[i] + coOutputRPos[i], 
		bufferSpace - coOutputRPos[i], 0);
	if (got == 0) {
		handleCloseFromLocal(i);
		return;
	}
	if (got < 0) {
		if (errno == EWOULDBLOCK) {
			return;
		}
		if (errno == EINPROGRESS) {
			return;
		}
		handleCloseFromLocal(i);
		return;
	}
	coOutputRPos[i] += got;
}

void handleLocalWrite(int i)
{
	int got;
	if (coClosing[i] && (coInputWPos[i] == coInputRPos[i])) {
		loClosed[i] = 1;
		coClosed[i] = 1;
		PERROR("remote closed and no more input");
		close(loFds[i]);
		return;
	}
	got = send(loFds[i], coInput[i] + coInputWPos[i],
		coInputRPos[i] - coInputWPos[i], 0);
	if (got < 0) {
		if (errno == EWOULDBLOCK) {
			return;
		}
		if (errno == EINPROGRESS) {
			return;
		}
		handleCloseFromLocal(i);
		return;
	}
	coInputWPos[i] += got;
	if (coInputWPos[i] == coInputRPos[i]) {
		coInputWPos[i] = 0;
		coInputRPos[i] = 0;
	}
}

void handleCloseFromLocal(int i)
{
	int arg;
	coClosing[i] = 1;
	/* The local end fizzled out, so make sure
		we're all done with that */
	PERROR("close from local");
	close(loFds[i]);
	loClosed[i] = 1;
	if (!reClosed[i]) {
#ifndef LINUX 
		/* Now set up the remote end for a polite closing */

		/* Request a low-water mark equal to the entire
			output buffer, so the next write notification
			tells us for sure that we can close the socket. */
		arg = 1024;
		setsockopt(reFds[i], SOL_SOCKET, SO_SNDLOWAT, 
			&arg, sizeof(arg));	
#endif /* LINUX */
	}
}

void handleCloseFromRemote(int i)
{
	int arg;
	coClosing[i] = 1;
	/* The remote end fizzled out, so make sure
		we're all done with that */
	PERROR("close from remote");
	close(reFds[i]);
	reClosed[i] = 1;
	if (!loClosed[i]) {
#ifndef LINUX
		/* Now set up the local end for a polite closing */

		/* Request a low-water mark equal to the entire
			output buffer, so the next write notification
			tells us for sure that we can close the socket. */
		arg = 1024;
		setsockopt(loFds[i], SOL_SOCKET, SO_SNDLOWAT, 
			&arg, sizeof(arg));	
#endif /* LINUX */
		loClosed[i] = 0;
	}
}

void handleAccept(int i)
{
	struct sockaddr addr;
	int j;
	int addrlen;
	int index = -1;
	int o;
	int nfd = accept(seFds[i], &addr, &addrlen);
	if (nfd < 0) {
		return;
	}
	if (nfd > maxfd) {
		maxfd = nfd;
	}
	j = 1;
	fcntl(nfd, F_SETFL, O_NONBLOCK);
	j = 0;
	setsockopt(nfd, SOL_SOCKET, SO_LINGER, &j, sizeof(j));
	for (j = 0; (j < coTotal); j++) {	
		if (coClosed[j]) {
			index = j;
			break;
		}
	}
	if (index == -1) {
		o = coTotal;
		coTotal *= 2;
		if (!SAFE_REALLOC(&reFds, sizeof(int) * o,
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&loFds, sizeof(int) * o,
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coInputRPos, 
			sizeof(int) * o, sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coInputWPos, 
			sizeof(int) * o, sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coOutputRPos, 
			sizeof(int) * o, sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coOutputWPos, sizeof(int) * o, 
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coClosed, sizeof(int) * o, 
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&reClosed, sizeof(int) * o, 
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&loClosed, sizeof(int) * o, 
			sizeof(int) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coInput, sizeof(char *) * o,
			sizeof(char *) * coTotal)) 
		{
			goto shortage;
		}
		if (!SAFE_REALLOC(&coOutput, sizeof(char *) * o,
			sizeof(char *) * coTotal)) 
		{
			goto shortage;
		}
		for (j = o; (j < coTotal); j++) {
			coClosed[j] = 1;
			coInput[j] = (char *) 
				malloc(sizeof(char) * bufferSpace);
			if (!coInput[j]) {
				int k;
				for (k = o; (k < j); k++) {
					free(coInput[k]);
					free(coOutput[k]);
				}
				goto shortage;
			}
			coOutput[j] = (char *) 
				malloc(sizeof(char) * bufferSpace);
			if (!coOutput[j]) {
				int k;
				free(coInput[j]);
				for (k = o; (k < j); k++) {
					free(coInput[k]);
					free(coOutput[k]);
				}
				goto shortage;
			}
		}
		index = coTotal;
	}
	coInputRPos[index] = 0;
	coInputWPos[index] = 0;
	coOutputRPos[index] = 0;
	coOutputWPos[index] = 0;
	coClosed[index] = 0;
	coClosing[index] = 0;
	reClosed[index] = 0;
	loClosed[index] = 0;
	reFds[index] = nfd;
	/* Now open a connection to the local server.
		This, too, is nonblocking. Why wait
		for anything when you don't have to? */
	openLocalFd(i, index);	
	return;
shortage:
	fprintf(stderr, "rinetd: not enough memory to "
		"add slots. Currently %d slots.\n", o);
	/* Go back to the previous total number of slots */
	coTotal = o;	
}

void openLocalFd(int se, int i)
{
	int j;
	struct sockaddr_in saddr;
	loFds[i] = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (loFds[i] < 0) {
		close(reFds[i]);
		reClosed[i] = 1;
		loClosed[i] = 1;
		coClosed[i] = 1;	
		return;
	}
	if (loFds[i] > maxfd) {
		maxfd = loFds[i];
	}
	/* Bind the local socket */
	saddr.sin_family = AF_INET;
	saddr.sin_port = INADDR_ANY;
	saddr.sin_addr.s_addr = 0;
	if (bind(loFds[i], (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		close(loFds[i]);
		close(reFds[i]);
		reClosed[i] = 1;
		loClosed[i] = 1;
		coClosed[i] = 1;	
		return;
	}
	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr, &seLocalAddrs[se], sizeof(struct in_addr));
	saddr.sin_port = seLocalPorts[se];
#ifdef LINUX
	j = 0;
	setsockopt(loFds[i], SOL_SOCKET, SO_LINGER, &j, sizeof(j));
#else
	j = 1024;
	setsockopt(loFds[i], SOL_SOCKET, SO_SNDBUF, &j, sizeof(j));
#endif /* LINUX */
	j = 1;
	fcntl(loFds[i], F_SETFL, O_NONBLOCK);
	if (connect(loFds[i], (struct sockaddr *)&saddr, 
		sizeof(struct sockaddr_in)) < 0) 
	{
		if (errno != EINPROGRESS) {
			PERROR("connect");
			close(loFds[i]);
			close(reFds[i]);
			reClosed[i] = 1;
			loClosed[i] = 1;
			coClosed[i] = 1;	
			return;
		}
	}
}

int getAddress(char *host, struct in_addr *iaddr)
{
	char *p = host;
	int ishost = 0;
	while (*p) {
		if (!(isdigit(*p) || ((*p) == '.'))) {
			ishost = 1;
			break;
		}
		p++;
	}
	if (ishost) {
		struct hostent *h;
		h = gethostbyname(host);
		if (!h) {
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

void plumber(int s)
{
	/* Just reinstall */
	signal(SIGPIPE, plumber);
}

void hup(int s)
{
	/* Recreate server sockets */
	createServerSockets();
	/* And reinstall */
	signal(SIGHUP, hup);
}

int safeRealloc(void **data, int oldsize, int newsize)
{
	void *newData = malloc(newsize + 1);
	if (!newData) {
		return 0;
	}
	if (newsize < oldsize) {
		memcpy(newData, *data, newsize);
	} else {	
		memcpy(newData, *data, oldsize);
	}
	*data = newData;
	return 1;
}

void
RegisterPID()
{
	FILE *pid_file;

/* add other systems with wherever they register processes */
#if	defined(LINUX)
	pid_file = fopen("/var/run/rinetd.pid", "w");
	if (pid_file == NULL) {
		/* non-fatal, non-Linux may lack /var/run... */
		fprintf(stderr, "PID unregistered\n");
	} else {
		/* error checking deliberately omitted */
		fprintf(pid_file, "%d\n", getpid());
		fclose(pid_file);
	}
#endif	/* LINUX */
}
