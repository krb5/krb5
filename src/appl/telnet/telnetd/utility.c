/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* based on @(#)utility.c	8.1 (Berkeley) 6/4/93 */

#include <stdarg.h>
#define PRINTOPTIONS
#include "telnetd.h"

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#if	defined(AUTHENTICATION)
#include <libtelnet/auth.h>
#endif
#ifdef ENCRYPTION
#include <libtelnet/encrypt.h>
#endif

/*
 * utility functions performing io related tasks
 */

/*
 * ttloop
 *
 *	A small subroutine to flush the network output buffer, get some data
 * from the network, and pass it through the telnet state machine.  We
 * also flush the pty input buffer (by dropping its data) if it becomes
 * too full.
 */

    void
ttloop()
{
    void netflush();

    DIAG(TD_REPORT, netputs("td: ttloop\r\n"));
    if (nfrontp-nbackp) {
	netflush();
    }
read_again:
    ncc = read(net, netibuf, sizeof netibuf);
    if (ncc < 0) {
	if (errno == EINTR)
	    goto read_again;
	syslog(LOG_INFO, "ttloop:  read: %m");
	exit(1);
    } else if (ncc == 0) {
	syslog(LOG_INFO, "ttloop:  peer died: %m");
	exit(1);
    }
    DIAG(TD_REPORT, netprintf("td: ttloop read %d chars\r\n", ncc));
    netip = netibuf;
    telrcv();			/* state machine */
    if (ncc > 0) {
	pfrontp = pbackp = ptyobuf;
	telrcv();
    }
}  /* end of ttloop */

/* 
 * ttsuck - This is a horrible kludge to deal with a bug in
 * HostExplorer. HostExplorer thinks it knows how to do krb5 auth, but
 * it doesn't really. So if you offer it krb5 as an auth choice before
 * krb4, it will sabotage the connection. So we peek ahead into the
 * input stream to see if the client is a UNIX client, and then
 * (later) offer krb5 first only if it is. Since no Mac/PC telnet
 * clients do auto switching between krb4 and krb5 like the UNIX
 * client does, it doesn't matter what order they see the choices in
 * (except for HostExplorer).
 *
 * It is actually not possible to do this without looking ahead into
 * the input stream: the client and server both try to begin
 * auth/encryption negotiation as soon as possible, so if we let the
 * server process things normally, it will already have sent the list
 * of supported auth types before seeing the NEW-ENVIRON option. If
 * you change the code to hold off sending the list of supported auth
 * types until after it knows whether or not the remote side supports
 * NEW-ENVIRON, then the auth negotiation and encryption negotiation
 * race conditions won't interact properly, and encryption negotiation
 * will reliably fail.
 */

    void
ttsuck()
{
    extern int auth_client_non_unix;
    int nread;
    struct timeval tv;
    fd_set fds;
    char *p, match[] = {IAC, WILL, TELOPT_NEW_ENVIRON};

    if (nfrontp-nbackp) {
	netflush();
    }
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_SET(net, &fds);

    while (select(net + 1, &fds, NULL, NULL, &tv) == 1)
      {
	nread = read(net, netibuf + ncc, sizeof(netibuf) - ncc);
	if (nread <= 0)
	  break;
	ncc += nread;
      }

    auth_client_non_unix = 1;
    for (p = netibuf; p < netibuf + ncc; p++)
      {
	if (!memcmp(p, match, sizeof(match)))
	  {
	    auth_client_non_unix = 0;
	    break;
	  }
      }

    if (ncc > 0)
      telrcv();
}

/*
 * Check a descriptor to see if out of band data exists on it.
 */
    int
stilloob(s)
    int	s;		/* socket number */
{
    static struct timeval timeout = { 0 };
    fd_set	excepts;
    int value;

    do {
	FD_ZERO(&excepts);
	FD_SET(s, &excepts);
	value = select(s+1, (fd_set *)0, (fd_set *)0, &excepts, &timeout);
    } while ((value == -1) && (errno == EINTR));

    if (value < 0) {
	fatalperror(pty, "select");
    }
    if (FD_ISSET(s, &excepts)) {
	return 1;
    } else {
	return 0;
    }
}

	void
ptyflush()
{
	int n;

	if ((n = pfrontp - pbackp) > 0) {
		DIAG((TD_REPORT | TD_PTYDATA),
		     netprintf("td: ptyflush %d chars\r\n", n));
		DIAG(TD_PTYDATA, printdata("pd", pbackp, n));
		n = write(pty, pbackp, (unsigned) n);
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK || errno == EINTR)
			return;
		(void)signal(SIGCHLD, SIG_DFL);
		cleanup(0);
	}
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */
static char *
nextitem(current)
    char	*current;
{
    if ((*current&0xff) != IAC) {
	return current+1;
    }
    switch (*(current+1)&0xff) {
    case DO:
    case DONT:
    case WILL:
    case WONT:
	return current+3;
    case SB:		/* loop forever looking for the SE */
	{
	    register char *look = current+2;

	    for (;;) {
		if ((*look++&0xff) == IAC) {
		    if ((*look++&0xff) == SE) {
			return look;
		    }
		}
	    }
	}
    default:
	return current+2;
    }
}  /* end of nextitem */


/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */
    void
netclear()
{
    register char *thisitem, *next;
    char *good;
#define	wewant(p)	((nfrontp > p) && ((*p&0xff) == IAC) && \
				((*(p+1)&0xff) != EC) && ((*(p+1)&0xff) != EL))

#ifdef	ENCRYPTION
    thisitem = nclearto > netobuf ? nclearto : netobuf;
#else	/* ENCRYPTION */
    thisitem = netobuf;
#endif	/* ENCRYPTION */

    while ((next = nextitem(thisitem)) <= nbackp) {
	thisitem = next;
    }

    /* Now, thisitem is first before/at boundary. */

#ifdef	ENCRYPTION
    good = nclearto > netobuf ? nclearto : netobuf;
#else	/* ENCRYPTION */
    good = netobuf;	/* where the good bytes go */
#endif	/* ENCRYPTION */

    while (nfrontp > thisitem) {
	if (wewant(thisitem)) {
	    unsigned int length;

	    next = thisitem;
	    do {
		next = nextitem(next);
	    } while (wewant(next) && (nfrontp > next));
	    length = next-thisitem;
	    memcpy(good, thisitem, length);
	    good += length;
	    thisitem = next;
	} else {
	    thisitem = nextitem(thisitem);
	}
    }

    nbackp = netobuf;
    nfrontp = good;		/* next byte to be sent */
    neturg = 0;
}  /* end of netclear */

/*
 *  netflush
 *		Send as much data as possible to the network,
 *	handling requests for urgent data.
 */
void
netflush()
{
    int n;
    extern int not42;

    if ((n = nfrontp - nbackp) > 0) {
	DIAG(TD_REPORT, {netprintf_noflush("td: netflush %d chars\r\n", n);
			 n = nfrontp - nbackp;});
#ifdef	ENCRYPTION
	if (encrypt_output) {
		char *s = nclearto ? nclearto : nbackp;
		if (nfrontp - s > 0) {
			(*encrypt_output)((unsigned char *)s, nfrontp-s);
			nclearto = nfrontp;
		}
	}
#endif	/* ENCRYPTION */
	/*
	 * if no urgent data, or if the other side appears to be an
	 * old 4.2 client (and thus unable to survive TCP urgent data),
	 * write the entire buffer in non-OOB mode.
	 */
	if ((neturg == 0) || (not42 == 0)) {
	    n = write(net, nbackp, (unsigned) n);	/* normal write */
	} else {
	    n = neturg - nbackp;
	    /*
	     * In 4.2 (and 4.3) systems, there is some question about
	     * what byte in a sendOOB operation is the "OOB" data.
	     * To make ourselves compatible, we only send ONE byte
	     * out of band, the one WE THINK should be OOB (though
	     * we really have more the TCP philosophy of urgent data
	     * rather than the Unix philosophy of OOB data).
	     */
	    if (n > 1) {
		n = send(net, nbackp, n-1, 0);	/* send URGENT all by itself */
	    } else {
		n = send(net, nbackp, n, MSG_OOB);	/* URGENT data */
	    }
	}
    }
    if (n < 0) {
	if (errno == EWOULDBLOCK || errno == EINTR)
		return;
	(void)signal(SIGCHLD, SIG_DFL);
	cleanup(0);
    }
    nbackp += n;
#ifdef	ENCRYPTION
    if (nbackp > nclearto)
	nclearto = 0;
#endif	/* ENCRYPTION */
    if (nbackp >= neturg) {
	neturg = 0;
    }
    if (nbackp == nfrontp) {
	nbackp = nfrontp = netobuf;
#ifdef	ENCRYPTION
	nclearto = 0;
#endif	/* ENCRYPTION */
    }
    return;
}  /* end of netflush */

/*
 * L8_256(x) = log8(256**x), rounded up, including sign (for decimal
 * strings too).  log8(256) = 8/3, but we use integer math to round
 * up.
 */
#define L8_256(x) (((x * 8 + 2) / 3) + 1)

/*
 * netprintf
 *
 * Do the equivalent of printf() to the NETOBUF "ring buffer",
 * possibly calling netflush() if needed.
 *
 * Thou shalt not call this with a "%s" format; use netputs instead.
 * We also don't deal with floating point widths in here.
 */
static void
netprintf_ext(int noflush, int seturg, const char *fmt, va_list args)
#if !defined(__cplusplus) && (__GNUC__ > 2)
    __attribute__((__format__(__printf__, 3, 0)))
#endif
    ;

static void
netprintf_ext(int noflush, int seturg, const char *fmt, va_list args)
{
	size_t remain;
	size_t maxoutlen;
	char buf[BUFSIZ];
	const char *cp;
	int len;

	buf[0] = '\0';		/* nul-terminate */
	remain = sizeof(netobuf) - (nfrontp - netobuf);
	for (maxoutlen = 0, cp = fmt; *cp; cp++) {
		if (*cp == '%')
			/* Ok so this is slightly overkill... */
			maxoutlen += L8_256(sizeof(long));
		else
			maxoutlen++;
	}
	if (maxoutlen >= sizeof(buf))
		return;		/* highly unlikely */

	len = vsnprintf(buf, sizeof(buf), fmt, args);

	/*
	 * The return value from sprintf()-like functions may be the
	 * number of characters that *would* have been output, not the
	 * number actually output.
	 */
	if (len <= 0 || len > sizeof(buf))
		return;
	if (remain < len && !noflush) {
		netflush();
		remain = sizeof(netobuf) - (nfrontp - netobuf);
	}
	if (remain < len)
		return;		/* still not enough space? */
	memcpy(nfrontp, buf, (size_t)len);
	nfrontp += len;
	if (seturg)
		neturg = nfrontp - 1;
}

void
netprintf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	netprintf_ext(0, 0, fmt, args);
	va_end(args);
}

void
netprintf_urg(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	netprintf_ext(0, 1, fmt, args);
	va_end(args);
}

void
netprintf_noflush(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	netprintf_ext(1, 0, fmt, args);
	va_end(args);
}

/*
 * netwrite
 *
 * Copy BUF into the NETOBUF "ring buffer", possibly calling
 * netflush() if needed.
 */
int
netwrite(const unsigned char *buf, size_t len)
{
	size_t remain;

	remain = sizeof(netobuf) - (nfrontp - netobuf);
	if (remain < len) {
		netflush();
		remain = sizeof(netobuf) - (nfrontp - netobuf);
	}
	if (remain < len)
		return 0;
	memcpy(nfrontp, buf, len);
	nfrontp += len;
	return len;
}

/*
 * netputs
 *
 * Write S to the NETOBUF "ring buffer".  Does not write a '\n'.
 */
void
netputs(const char *s)
{
	netwrite((const unsigned char *) s, strlen(s));
}

/*
 * miscellaneous functions doing a variety of little jobs follow ...
 */


	void
fatal(f, msg)
	int f;
	const char *msg;
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof(buf), "telnetd: %s.\r\n", msg);
#ifdef	ENCRYPTION
	if (encrypt_output) {
		/*
		 * Better turn off encryption first....
		 * Hope it flushes...
		 */
		encrypt_send_end();
		netflush();
	}
#endif	/* ENCRYPTION */
	(void) write(f, buf, strlen(buf));
	sleep(1);	/*XXX*/
	exit(1);
}

	void
fatalperror(f, msg)
	int f;
	const char *msg;
{
	char buf[BUFSIZ], *strerror();

	(void) snprintf(buf, sizeof(buf), "%s: %s\r\n", msg, strerror(errno));
	fatal(f, buf);
}

char editedhost[32];

	void
edithost(pat, host)
	register char *pat;
	register char *host;
{
	register char *res = editedhost;

	if (!pat)
		pat = "";
	while (*pat) {
		switch (*pat) {

		case '#':
			if (*host)
				host++;
			break;

		case '@':
			if (*host)
				*res++ = *host++;
			break;

		default:
			*res++ = *pat;
			break;
		}
		if (res == &editedhost[sizeof editedhost - 1]) {
			*res = '\0';
			return;
		}
		pat++;
	}
	if (*host)
		(void) strncpy(res, host,
				sizeof editedhost - (res - editedhost) -1);
	else
		*res = '\0';
	editedhost[sizeof editedhost - 1] = '\0';
}

static char *putlocation;

static	void
putstr(s)
	register char *s;
{

	while (*s)
		putchr(*s++);
}

	void
putchr(cc)
	int cc;
{
	*putlocation++ = cc;
}

/*
 * This is split on two lines so that SCCS will not see the M
 * between two % signs and expand it...
 */
static char fmtstr[] = { "%l:%M\
%P on %A, %d %B %Y" };

	void
putf(cp, where)
	register char *cp;
	char *where;
{
	char *slash;
	time_t t;
	char db[100];
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname utsinfo;

	(void) uname(&utsinfo);
#endif

	putlocation = where;

	while (*cp) {
		if (*cp != '%') {
			putchr(*cp++);
			continue;
		}
		switch (*++cp) {

		case 't':
#ifdef	STREAMSPTY
			/* names are like /dev/pts/2 -- we want pts/2 */
			slash = strchr(line+1, '/');
#else
			slash = strrchr(line, '/');
#endif
			if (slash == (char *) 0)
				putstr(line);
			else
				putstr(&slash[1]);
			break;

		case 'h':
			putstr(editedhost);
			break;

		case 'd':
			(void)time(&t);
			(void)strftime(db, sizeof(db), fmtstr, localtime(&t));
			putstr(db);
			break;

#ifdef HAVE_SYS_UTSNAME_H
		case 's':
			putstr(utsinfo.sysname);
			break;

		case 'm':
			putstr(utsinfo.machine);
			break;

		case 'r':
			putstr(utsinfo.release);
			break;

		case 'v':
			putstr(utsinfo.version);
			break;
#endif

		case '%':
			putchr('%');
			break;
		}
		cp++;
	}
}

#ifdef DIAGNOSTICS
/*
 * Print telnet options and commands in plain text, if possible.
 */
void
printoption(fmt, option)
	register char *fmt;
	register int option;
{
	netputs(fmt);
	netputs(" ");
	if (TELOPT_OK(option)) {
		netputs(TELOPT(option));
		netputs("\r\n");
	} else if (TELCMD_OK(option)) {
		netputs(TELCMD(option));
		netputs("\r\n");
	} else {
		netprintf("%d\r\n", option);
	}
	return;
}

void
printsub(direction, pointer, length)
    char		direction;	/* '<' or '>' */
    unsigned char	*pointer;	/* where suboption data sits */
    int			length;		/* length of suboption data */
{
    register int i = 0;
    char buf[512];

        if (!(diagnostic & TD_OPTIONS))
		return;

	if (direction) {
	    netputs("td: ");
	    netputs(direction == '<' ? "recv" : "send");
	    netputs(" suboption ");
	    if (length >= 3) {
		register int j;

		i = pointer[length-2];
		j = pointer[length-1];

		if (i != IAC || j != SE) {
		    netputs("(terminated by ");
		    if (TELOPT_OK(i))
			netputs(TELOPT(i));
		    else if (TELCMD_OK(i))
			netputs(TELCMD(i));
		    else
			netprintf("%d", i);
		    netputs(" ");
		    if (TELOPT_OK(j))
			netputs(TELOPT(j));
		    else if (TELCMD_OK(j))
			netputs(TELCMD(j));
		    else
			netprintf("%d", j);
		    netputs(", not IAC SE!) ");
		}
	    }
	    length -= 2;
	}
	if (length < 1) {
	    netputs("(Empty suboption??\?)");
	    return;
	}
	switch (pointer[0]) {
	case TELOPT_TTYPE:
	    netputs("TERMINAL-TYPE ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netputs("IS \"");
		netwrite(pointer + 2, (size_t)(length - 2));
		netputs("\"");
		break;
	    case TELQUAL_SEND:
		netputs("SEND");
		break;
	    default:
		netprintf("- unknown qualifier %d (0x%x).",
			  pointer[1], pointer[1]);
	    }
	    break;
	case TELOPT_TSPEED:
	    netputs("TERMINAL-SPEED ");
	    if (length < 2) {
		netputs("(empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netputs("IS ");
		netwrite(pointer + 2, (size_t)(length - 2));
		break;
	    default:
		if (pointer[1] == 1)
		    netputs("SEND");
		else
		    netprintf("%d (unknown)", pointer[1]);
		for (i = 2; i < length; i++)
		    netprintf(" ?%d?", pointer[i]);
		break;
	    }
	    break;

	case TELOPT_LFLOW:
	    netputs("TOGGLE-FLOW-CONTROL ");
	    if (length < 2) {
		netputs("(empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case LFLOW_OFF:
		netputs("OFF"); break;
	    case LFLOW_ON:
		netputs("ON"); break;
	    case LFLOW_RESTART_ANY:
		netputs("RESTART-ANY"); break;
	    case LFLOW_RESTART_XON:
		netputs("RESTART-XON"); break;
	    default:
		netprintf("%d (unknown)", pointer[1]);
	    }
	    for (i = 2; i < length; i++)
		netprintf(" ?%d?", pointer[i]);
	    break;

	case TELOPT_NAWS:
	    netputs("NAWS");
	    if (length < 2) {
		netputs(" (empty suboption??\?)");
		break;
	    }
	    if (length == 2) {
		netprintf(" ?%d?", pointer[1]);
		break;
	    }
	    netprintf(" %d %d (%d)",
		pointer[1], pointer[2],
		(int)((((unsigned int)pointer[1])<<8)|((unsigned int)pointer[2])));
	    if (length == 4) {
		netprintf(" ?%d?", pointer[3]);
		break;
	    }
	    netprintf(" %d %d (%d)",
		pointer[3], pointer[4],
		(int)((((unsigned int)pointer[3])<<8)|((unsigned int)pointer[4])));
	    for (i = 5; i < length; i++)
		netprintf(" ?%d?", pointer[i]);
	    break;

	case TELOPT_LINEMODE:
	    netputs("LINEMODE ");
	    if (length < 2) {
		netputs("(empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case WILL:
		netputs("WILL ");
		goto common;
	    case WONT:
		netputs("WONT ");
		goto common;
	    case DO:
		netputs("DO ");
		goto common;
	    case DONT:
		netputs("DONT ");
	    common:
		if (length < 3) {
		    netputs("(no option??\?)");
		    break;
		}
		switch (pointer[2]) {
		case LM_FORWARDMASK:
		    netputs("Forward Mask");
		    for (i = 3; i < length; i++)
			netprintf(" %x", pointer[i]);
		    break;
		default:
		    netprintf("%d (unknown)", pointer[2]);
		    for (i = 3; i < length; i++)
			netprintf(" %d", pointer[i]);
		    break;
		}
		break;
		
	    case LM_SLC:
		netputs("SLC");
		for (i = 2; i < length - 2; i += 3) {
		    if (SLC_NAME_OK(pointer[i+SLC_FUNC])) {
			netputs(" ");
			netputs(SLC_NAME(pointer[i+SLC_FUNC]));
		    } else
			netprintf(" %d", pointer[i+SLC_FUNC]);
		    switch (pointer[i+SLC_FLAGS]&SLC_LEVELBITS) {
		    case SLC_NOSUPPORT:
			netputs(" NOSUPPORT"); break;
		    case SLC_CANTCHANGE:
			netputs(" CANTCHANGE"); break;
		    case SLC_VARIABLE:
			netputs(" VARIABLE"); break;
		    case SLC_DEFAULT:
			netputs(" DEFAULT"); break;
		    }
		    netputs(pointer[i+SLC_FLAGS]&SLC_ACK
			    ? "|ACK" : "");
		    netputs(pointer[i+SLC_FLAGS]&SLC_FLUSHIN
			    ? "|FLUSHIN" : "");
		    netputs(pointer[i+SLC_FLAGS]&SLC_FLUSHOUT
			    ? "|FLUSHOUT" : "");
		    if (pointer[i+SLC_FLAGS]& ~(SLC_ACK|SLC_FLUSHIN|
						SLC_FLUSHOUT| SLC_LEVELBITS)) {
			netprintf("(0x%x)", pointer[i+SLC_FLAGS]);
		    }
		    netprintf(" %d;", pointer[i+SLC_VALUE]);
		    if ((pointer[i+SLC_VALUE] == IAC) &&
			(pointer[i+SLC_VALUE+1] == IAC))
				i++;
		}
		for (; i < length; i++)
		    netprintf(" ?%d?", pointer[i]);
		break;

	    case LM_MODE:
		netputs("MODE ");
		if (length < 3) {
		    netputs("(no mode??\?)");
		    break;
		}
		{
		    int wrotemode = 0;

#define NETPUTS_MODE(x)				\
do {						\
	if (pointer[2] & (MODE_##x)) {		\
		if (wrotemode) netputs("|");	\
		netputs(#x);			\
		wrotemode++;			\
	}					\
} while (0)
		    NETPUTS_MODE(EDIT);
		    NETPUTS_MODE(TRAPSIG);
		    NETPUTS_MODE(SOFT_TAB);
		    NETPUTS_MODE(LIT_ECHO);
		    NETPUTS_MODE(ACK);
#undef NETPUTS_MODE
		    if (!wrotemode)
			netputs("0");
		}
		if (pointer[2] & ~(MODE_EDIT|MODE_TRAPSIG|MODE_ACK))
		    netprintf(" (0x%x)", pointer[2]);
		for (i = 3; i < length; i++)
		    netprintf(" ?0x%x?", pointer[i]);
		break;
	    default:
		netprintf("%d (unknown)", pointer[1]);
		for (i = 2; i < length; i++)
		    netprintf(" %d", pointer[i]);
	    }
	    break;

	case TELOPT_STATUS: {
	    register char *cp;
	    register int j, k;

	    netputs("STATUS");

	    switch (pointer[1]) {
	    default:
		if (pointer[1] == TELQUAL_SEND)
		    netputs(" SEND");
		else
		    netprintf(" %d (unknown)", pointer[1]);
		for (i = 2; i < length; i++)
		    netprintf(" ?%d?", pointer[i]);
		break;
	    case TELQUAL_IS:
		netputs(" IS\r\n");

		for (i = 2; i < length; i++) {
		    switch(pointer[i]) {
		    case DO:	cp = "DO"; goto common2;
		    case DONT:	cp = "DONT"; goto common2;
		    case WILL:	cp = "WILL"; goto common2;
		    case WONT:	cp = "WONT"; goto common2;
		    common2:
			i++;
			netputs(" ");
			netputs(cp);
			netputs(" ");
			if (TELOPT_OK(pointer[i]))
			    netputs(TELOPT(pointer[i]));
			else
			    netprintf("%d", pointer[i]);

			netputs("\r\n");
			break;

		    case SB:
			netputs(" SB ");
			i++;
			j = k = i;
			while (j < length) {
			    if (pointer[j] == SE) {
				if (j+1 == length)
				    break;
				if (pointer[j+1] == SE)
				    j++;
				else
				    break;
			    }
			    pointer[k++] = pointer[j++];
			}
			printsub(0, &pointer[i], k - i);
			if (i < length) {
			    netputs(" SE");
			    i = j;
			} else
			    i = j - 1;

			netputs("\r\n");

			break;
				
		    default:
			netprintf(" %d", pointer[i]);
			break;
		    }
		}
		break;
	    }
	    break;
	  }

	case TELOPT_XDISPLOC:
	    netputs("X-DISPLAY-LOCATION ");
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netputs("IS \"");
		netwrite(pointer + 2, (size_t)(length - 2));
		netputs("\"");
		break;
	    case TELQUAL_SEND:
		netputs("SEND");
		break;
	    default:
		netprintf("- unknown qualifier %d (0x%x).",
			  pointer[1], pointer[1]);
	    }
	    break;

	case TELOPT_NEW_ENVIRON:
	    netputs("NEW-ENVIRON ");
	    goto env_common1;
	case TELOPT_OLD_ENVIRON:
	    netputs("OLD-ENVIRON ");
	env_common1:
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		netputs("IS ");
		goto env_common;
	    case TELQUAL_SEND:
		netputs("SEND ");
		goto env_common;
	    case TELQUAL_INFO:
		netputs("INFO ");
	    env_common:
		{
		    register int noquote = 2;
		    for (i = 2; i < length; i++ ) {
			switch (pointer[i]) {
			case NEW_ENV_VAR:
			    netputs("\" VAR " + noquote);
			    noquote = 2;
			    break;

			case NEW_ENV_VALUE:
			    netputs("\" VALUE " + noquote);
			    noquote = 2;
			    break;

			case ENV_ESC:
			    netputs("\" ESC " + noquote);
			    noquote = 2;
			    break;

			case ENV_USERVAR:
			    netputs("\" USERVAR " + noquote);
			    noquote = 2;
			    break;

			default:
			    if (isprint(pointer[i]) && pointer[i] != '"') {
				if (noquote) {
				    netputs("\"");
				    noquote = 0;
				}
				netprintf("%c", pointer[i]);
			    } else {
				netprintf("\" %03o " + noquote,
					  pointer[i]);
				noquote = 2;
			    }
			    break;
			}
		    }
		    if (!noquote)
			netputs("\"");
		    break;
		}
	    }
	    break;

#if	defined(AUTHENTICATION)
	case TELOPT_AUTHENTICATION:
	    netputs("AUTHENTICATION");
	
	    if (length < 2) {
		netputs(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case TELQUAL_REPLY:
	    case TELQUAL_IS:
		netputs((pointer[1] == TELQUAL_IS) ? " IS " : " REPLY ");
		if (AUTHTYPE_NAME_OK(pointer[2]))
		    netputs(AUTHTYPE_NAME(pointer[2]));
		else
		    netprintf(" %d ", pointer[2]);
		if (length < 3) {
		    netputs("(partial suboption??\?)");
		    break;
		}
		netputs(((pointer[3] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT)
			? "CLIENT|" : "SERVER|");
		netputs(((pointer[3] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
			? "MUTUAL" : "ONE-WAY");
		netputs(((pointer[3] & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_ON)
			? "|ENCRYPT" : "");

		auth_printsub(&pointer[1], length - 1, (unsigned char *)buf, 
			      sizeof(buf));
		netputs(buf);
		break;

	    case TELQUAL_SEND:
		i = 2;
		netputs(" SEND ");
		while (i < length) {
		    if (AUTHTYPE_NAME_OK(pointer[i]))
			netputs(AUTHTYPE_NAME(pointer[i]));
		    else
			netprintf("%d", pointer[i]);
		    netputs(" ");
		    if (++i >= length) {
			netputs("(partial suboption??\?)");
			break;
		    }
		    netputs(((pointer[i] & AUTH_WHO_MASK) == AUTH_WHO_CLIENT)
			    ? "CLIENT|" : "SERVER|");
		    netputs(((pointer[i] & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
			    ? "MUTUAL" : "ONE-WAY");
		    if ((pointer[3] & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_ON)
			netputs("|ENCRYPT");
		    ++i;
		}
		break;

	    case TELQUAL_NAME:
		i = 2;
		netputs(" NAME \"");
		while (i < length) {
		    if (isprint(pointer[i]))
			netprintf("%c", pointer[i++]);
		    else {
			netprintf("\\%03o", pointer[i++]);
		    }
		}
		netputs("\"");
		break;

	    default:
		    for (i = 2; i < length; i++)
			netprintf(" ?%d?", pointer[i]);
		    break;
	    }
	    break;
#endif

#ifdef	ENCRYPTION
	case TELOPT_ENCRYPT:
	    netputs("ENCRYPT");
	    if (length < 2) {
		netputs(" (empty suboption??\?)");
		break;
	    }
	    switch (pointer[1]) {
	    case ENCRYPT_START:
		netputs(" START");
		break;

	    case ENCRYPT_END:
		netputs(" END");
		break;

	    case ENCRYPT_REQSTART:
		netputs(" REQUEST-START");
		break;

	    case ENCRYPT_REQEND:
		netputs(" REQUEST-END");
		break;

	    case ENCRYPT_IS:
	    case ENCRYPT_REPLY:
		netputs((pointer[1] == ENCRYPT_IS)
			? " IS " : " REPLY ");
		if (length < 3) {
		    netputs(" (partial suboption??\?)");
		    nfrontp += strlen(nfrontp);
		    break;
		}
		if (ENCTYPE_NAME_OK(pointer[2]))
		    netputs(ENCTYPE_NAME(pointer[2]));
		else
		    netprintf("%d (unknown)", pointer[2]);
		netputs(" ");

		encrypt_printsub(&pointer[1], length - 1, 
				 (unsigned char *) buf, sizeof(buf));
		netputs(buf);
		break;

	    case ENCRYPT_SUPPORT:
		i = 2;
		netputs(" SUPPORT ");
		nfrontp += strlen(nfrontp);
		while (i < length) {
		    if (ENCTYPE_NAME_OK(pointer[i]))
			netputs(ENCTYPE_NAME(pointer[i]));
		    else
			netprintf("%d", pointer[i]);
		    netputs(" ");
		    i++;
		}
		break;

	    case ENCRYPT_ENC_KEYID:
		netputs(" ENC_KEYID");
		goto encommon;

	    case ENCRYPT_DEC_KEYID:
		netputs(" DEC_KEYID");
		goto encommon;

	    default:
		netprintf(" %d (unknown)", pointer[1]);
	    encommon:
		for (i = 2; i < length; i++)
		    netprintf(" %d", pointer[i]);
		break;
	    }
	    break;
#endif	/* ENCRYPTION */

	default:
	    if (TELOPT_OK(pointer[0]))
	        netputs(TELOPT(pointer[0]));
	    else
	        netprintf("%d", pointer[0]);
	    netputs(" (unknown)");
	    for (i = 1; i < length; i++)
		netprintf(" %d", pointer[i]);
	    break;
	}
	netputs("\r\n");
}

/*
 * Dump a data buffer in hex and ascii to the output data stream.
 */
	void
printdata(tag, ptr, cnt)
	register char *tag;
	register char *ptr;
	register int cnt;
{
	register int i;
	char xbuf[30];

	while (cnt) {
		/* add a line of output */
		netputs(tag);
		netputs(": ");
		for (i = 0; i < 20 && cnt; i++) {
			netprintf(nfrontp, "%02x", *ptr);
			nfrontp += strlen(nfrontp); 
			if (isprint((int) *ptr)) {
				xbuf[i] = *ptr;
			} else {
				xbuf[i] = '.';
			}
			if (i % 2)
				netputs(" ");
			cnt--;
			ptr++;
		}
		xbuf[i] = '\0';
		netputs(" ");
		netputs(xbuf);
		netputs("\r\n");
	} 
}
#endif /* DIAGNOSTICS */
