/* Copyright © 1997—1999 Thomas Boutell <boutell@boutell.com>
                         and Boutell.Com, Inc.
             © 2003—2017 Sam Hocevar <sam@hocevar.net>

   This software is released for free use under the terms of
   the GNU Public License, version 2 or higher. NO WARRANTY
   IS EXPRESSED OR IMPLIED. USE THIS SOFTWARE AT YOUR OWN RISK. */

#pragma once

/* Syslog feature */

#if _WIN32
#	include <stdio.h>
#	define syslog fprintf
#	define LOG_ERR stderr
#	define LOG_INFO stdout
#else
#	include <syslog.h>
#endif /* _WIN32 */

/* Constants */

static int const RINETD_BUFFER_SIZE = 16384;
static int const RINETD_LISTEN_BACKLOG = 128;
static int const RINETD_DEFAULT_UDP_TIMEOUT = 72;

#define RINETD_CONFIG_FILE "/etc/rinetd.conf"
#define RINETD_PID_FILE "/var/run/rinetd.pid"

/* Global configuration */

extern Rule *allRules;
extern int allRulesCount;
extern int globalRulesCount;

extern ServerInfo *seInfo;
extern int seTotal;

extern char *logFileName;
extern char *pidLogFileName;
extern int logFormatCommon;
extern FILE *logFile;

/* Functions */

void addServer(char *bindAddress, int bindPort, int bindProto,
               char *connectAddress, int connectPort, int connectProto,
               int serverTimeout, char *sourceAddress);

