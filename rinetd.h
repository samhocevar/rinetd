/* Constants */

static int const RINETD_BUFFER_SIZE = 16384;
static int const RINETD_LISTEN_BACKLOG = 128;

#define RINETD_CONFIG_FILE "/etc/rinetd.conf"
#define RINETD_PID_FILE "/var/run/rinetd.pid"

/* Program state */

enum ruleType {
	allowRule,
	denyRule,
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

	/* In ASCII and local byte order, for logging purposes */
	char *fromHost, *toHost;
	int fromPort, toPort;

	/* Offset and count into list of allow and deny rules. Any rules
		prior to globalAllowRules and globalDenyRules are global rules. */
	int rulesStart, rulesCount;
};

typedef struct _socket Socket;
struct _socket
{
	SOCKET fd;
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
	struct in_addr reAddresses;
	int coClosing;
	int coLog;
	int server; // only useful for logEvent
};

/* Option parsing */

typedef struct _rinetd_options RinetdOptions;
struct _rinetd_options
{
	char const *conf_file;
	int foreground;
};

