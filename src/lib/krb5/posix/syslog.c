/*
 * Copyright (c) 1983, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* based on @(#)syslog.c	5.20 (Berkeley) 1/19/89 */

/*
 * SYSLOG -- print message on log file
 *
 * This routine looks a lot like printf, except that it outputs to the
 * log file instead of the standard output.  Also:
 *	adds a timestamp,
 *	prints the module name in front of the message,
 *	has some other formatting types (or will sometime),
 *	adds a newline on the end of the message.
 *
 * The output of this routine is intended to be read by syslogd(8).
 *
 * Author: Eric Allman
 * Modified to use UNIX domain IPC by Ralph Campbell
 */

#if !defined(_WIN32) && !defined(macintosh)

#if defined(__STDC__) || defined(_WIN32)
#include <stdarg.h>
#else
#define const
#include <varargs.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <syslog.h>
#include <sys/wait.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

#define	LOGNAME	"/dev/log"
#define	CONSOLE	"/dev/console"

static int	LogFile = -1;		/* fd for log */
static int	connected;		/* have done connect */
static int	LogStat = 0;		/* status bits, set by openlog() */
static const char *LogTag = "syslog";	/* string to tag the entry with */
static int	LogFacility = LOG_USER;	/* default facility code */


void
#if defined(__STDC__) || defined(_WIN32)
syslog(int pri, const char *fmt, ...)
#else
syslog(pri, fmt, va_alist)
	int pri;
	char *fmt;
	va_dcl
#endif
{
    va_list pvar;
    void vsyslog();
#if defined(__STDC__) || defined(_WIN32)
    va_start(pvar, fmt);
#else
    va_start(pvar);
#endif
    vsyslog(pri, fmt, pvar);
    va_end(pvar);
}

void
vsyslog(pri, fmt, ap)
	int pri;
	const register char *fmt;
	va_list ap;
{
	register int cnt;
	register char *p;
	time_t now, time();
	int pid, saved_errno;
	char tbuf[2048], fmt_cpy[1024], *ctime();
	void openlog();

	saved_errno = errno;

	/* see if we should just throw out this message */
	if ((u_int)LOG_FAC(pri) >= LOG_NFACILITIES ||
	    !LOG_MASK(LOG_PRI(pri)) || (pri &~ (LOG_PRIMASK|LOG_FACMASK)))
		return;
	if (LogFile < 0 || !connected)
		openlog(LogTag, LogStat | LOG_NDELAY, 0);

	/* set default facility if none specified */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	/* build the message */
	(void)time(&now);
	(void)sprintf(tbuf, "<%d>%.15s ", pri, ctime(&now) + 4);
	for (p = tbuf; *p; ++p);
	if (LogTag) {
		(void)strncpy(p, LogTag, sizeof(tbuf) - 1 - (p - tbuf));
		for (; *p; ++p);
	}
	if (LogStat & LOG_PID) {
		(void)sprintf(p, "[%d]", getpid());
		for (; *p; ++p);
	}
	if (LogTag) {
		*p++ = ':';
		*p++ = ' ';
	}

	/* substitute error message for %m */
	{
		register char ch, *t1, *t2;
#ifndef strerror
		extern char *strerror();
#endif
		
		for (t1 = fmt_cpy; ch = *fmt; ++fmt)
			if (ch == '%' && fmt[1] == 'm') {
				++fmt;
				for (t2 = strerror(saved_errno);
				    *t1 = *t2++; ++t1);
			}
			else
				*t1++ = ch;
		*t1 = '\0';
	}

	(void)vsprintf(p, fmt_cpy, ap);
	/* Bounds checking??  If a system doesn't have syslog, we
	   probably can't rely on it having vsnprintf either.  Try not
	   to let a buffer overrun be exploited.  */
	if (strlen (tbuf) >= sizeof (tbuf))
	  abort ();

	/* output the message to the local logger */
	if (send(LogFile, tbuf, cnt = strlen(tbuf), 0) >= 0 ||
	    !(LogStat&LOG_CONS))
		return;

	/* output the message to the console */
#if defined(SYSV) || defined(_AIX)
	pid = fork();
#else
	pid = vfork();
#endif
	if (pid == -1)
		return;
	if (pid == 0) {
		int fd;

		(void)signal(SIGALRM, SIG_DFL);
		sigsetmask((long)~sigmask(SIGALRM));
		(void)alarm((u_int)5);
		if ((fd = open(CONSOLE, O_WRONLY, 0)) < 0)
			return;
		(void)alarm((u_int)0);
		tbuf[sizeof(tbuf) - 1] = '\0';
		(void)strncat(tbuf, "\r", sizeof(tbuf) - 1 - strlen(tbuf));
		p = strchr(tbuf, '>') + 1;
		(void)write(fd, p, cnt + 1 - (p - tbuf));
		(void)close(fd);
		_exit(0);
	}
#if defined(SYSV) || defined(_AIX) || defined(_POSIX_SOURCE)
#define	cast int *
#else
#define cast union wait *
#endif
	if (!(LogStat & LOG_NOWAIT))
		while ((cnt = wait((cast)0)) > 0 && cnt != pid);
#undef cast
}

static struct sockaddr SyslogAddr;	/* AF_UNIX address of local logger */
/*
 * OPENLOG -- open system log
 */
void
openlog(ident, logstat, logfac)
	const char *ident;
	int logstat, logfac;
{
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
		LogFacility = logfac;
	if (LogFile == -1) {
		SyslogAddr.sa_family = AF_UNIX;
		strncpy(SyslogAddr.sa_data, LOGNAME, sizeof SyslogAddr.sa_data);
		if (LogStat & LOG_NDELAY) {
			LogFile = socket(AF_UNIX, SOCK_DGRAM, 0);
			fcntl(LogFile, F_SETFD, 1);
		}
	}
	if (LogFile != -1 && !connected &&
	    connect(LogFile, &SyslogAddr, sizeof(SyslogAddr)) != -1)
		connected = 1;
}

/*
 * CLOSELOG -- close the system log
 */
void
closelog()
{
	(void) close(LogFile);
	LogFile = -1;
	connected = 0;
}

static int	LogMask = 0xff;		/* mask of priorities to be logged */
/*
 * SETLOGMASK -- set the log mask level
 */
int
setlogmask(pmask)
	int pmask;
{
	int omask;

	omask = LogMask;
	if (pmask != 0)
		LogMask = pmask;
	return (omask);
}
#else /* Windows or Mac */

/* Windows doesn't have the concept of a system log, so just
** do nothing here.
*/
void
syslog(int pri, const char *fmt, ...)
{
   return;
}
#endif
