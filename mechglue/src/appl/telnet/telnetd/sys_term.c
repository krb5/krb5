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

/* baesd on @(#)sys_term.c	8.1 (Berkeley) 6/4/93 */

#include "telnetd.h"
#include "pathnames.h"
#include <com_err.h>

#ifndef LOGIN_PROGRAM
#define LOGIN_PROGRAM _PATH_LOGIN
#endif

#include <libpty.h>
#if	defined(AUTHENTICATION)
#include <libtelnet/auth.h>
#endif

#if	defined(KRB5)
#include "k5-int.h"
#endif

char *login_program = LOGIN_PROGRAM;

#ifdef	NEWINIT
#include <initreq.h>
int	utmp_len = MAXHOSTNAMELEN;	/* sizeof(init_request.host) */
#else	/* NEWINIT*/

#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif

#ifdef _PATH_WTMP
char	wtmpf[] = _PATH_WTMP;
#else
char	wtmpf[]	= "/usr/adm/wtmp";
#endif

#ifdef _PATH_UTMP
char 	utmpf[] = _PATH_UTMP;
#else
char	utmpf[] = "/etc/utmp";
#endif
  
# ifdef CRAY
#include <tmpdir.h>
#include <sys/wait.h>
#  if defined(_SC_CRAY_SECURE_SYS) && !defined(SCM_SECURITY)
   /*
    * UNICOS 6.0/6.1 do not have SCM_SECURITY defined, so we can
    * use it to tell us to turn off all the socket security code,
    * since that is only used in UNICOS 7.0 and later.
    */
#   undef _SC_CRAY_SECURE_SYS
#  endif

#  if defined(_SC_CRAY_SECURE_SYS)
#include <sys/sysv.h>
#include <sys/secstat.h>
extern int secflag;
extern struct sysv sysv;
#  endif /* _SC_CRAY_SECURE_SYS */
# endif	/* CRAY */
#endif	/* NEWINIT */

#ifdef	STREAMSPTY
#ifdef HAVE_SAC_H
#include <sac.h> 
#endif
#include <sys/stropts.h>
#endif

#define SCPYN(a, b)	(void) strncpy(a, b, sizeof(a))
#define SCMPN(a, b)	strncmp(a, b, sizeof(a))

#ifdef	HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#ifdef __hpux
#include <sys/resource.h>
#include <sys/proc.h>
#endif
	/* For what platforms do we really need sys/tty.h? */
#ifdef HAVE_SYS_TTY_H
#include <sys/tty.h>
#endif
	
#ifdef	t_erase
#undef	t_erase
#undef	t_kill
#undef	t_intrc
#undef	t_quitc
#undef	t_startc
#undef	t_stopc
#undef	t_eofc
#undef	t_brkc
#undef	t_suspc
#undef	t_dsuspc
#undef	t_rprntc
#undef	t_flushc
#undef	t_werasc
#undef	t_lnextc
#endif

#if defined(UNICOS5) && defined(CRAY2) && !defined(EXTPROC)
# define EXTPROC 0400
#endif

#ifndef	USE_TERMIO
struct termbuf {
	struct sgttyb sg;
	struct tchars tc;
	struct ltchars ltc;
	int state;
	int lflags;
} termbuf, termbuf2;
# define	cfsetospeed(tp, val)	(tp)->sg.sg_ospeed = (val)
# define	cfsetispeed(tp, val)	(tp)->sg.sg_ispeed = (val)
# define	cfgetospeed(tp)		(tp)->sg.sg_ospeed
# define	cfgetispeed(tp)		(tp)->sg.sg_ispeed
#else	/* USE_TERMIO */
# ifdef	SYSV_TERMIO
#	define termios termio
# endif
# ifndef	TCSANOW
#  ifdef TCSETS
#   define	TCSANOW		TCSETS
#   define	TCSADRAIN	TCSETSW
#   define	tcgetattr(f, t)	ioctl(f, TCGETS, (char *)t)
#  else
#   ifdef TCSETA
#    define	TCSANOW		TCSETA
#    define	TCSADRAIN	TCSETAW
#    define	tcgetattr(f, t)	ioctl(f, TCGETA, (char *)t)
#   else
#    define	TCSANOW		TIOCSETA
#    define	TCSADRAIN	TIOCSETAW
#    define	tcgetattr(f, t)	ioctl(f, TIOCGETA, (char *)t)
#   endif
#  endif
#  define	tcsetattr(f, a, t)	ioctl(f, a, t)
#  define	cfsetospeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
					(tp)->c_cflag |= (val)
#  define	cfgetospeed(tp)		((tp)->c_cflag & CBAUD)
#  ifdef CIBAUD
#   define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CIBAUD; \
					(tp)->c_cflag |= ((val)<<IBSHIFT)
#   define	cfgetispeed(tp)		(((tp)->c_cflag & CIBAUD)>>IBSHIFT)
#  else
#   define	cfsetispeed(tp, val)	(tp)->c_cflag &= ~CBAUD; \
					(tp)->c_cflag |= (val)
#   define	cfgetispeed(tp)		((tp)->c_cflag & CBAUD)
#  endif
# endif /* TCSANOW */
struct termios termbuf, termbuf2;	/* pty control structure */
# ifdef  STREAMSPTY
int ttyfd = -1;
# endif
#endif	/* USE_TERMIO */

#ifndef SETPGRP_TWOARG
#define setpgrp(a,b) setpgrp()
#endif

int dup_tty(int);
static char **addarg(char **, char *);

/*
 * init_termbuf()
 * copy_termbuf(cp)
 * set_termbuf()
 *
 * These three routines are used to get and set the "termbuf" structure
 * to and from the kernel.  init_termbuf() gets the current settings.
 * copy_termbuf() hands in a new "termbuf" to write to the kernel, and
 * set_termbuf() writes the structure into the kernel.
 */

	void
init_termbuf()
{
#ifndef	USE_TERMIO
	(void) ioctl(pty, TIOCGETP, (char *)&termbuf.sg);
	(void) ioctl(pty, TIOCGETC, (char *)&termbuf.tc);
	(void) ioctl(pty, TIOCGLTC, (char *)&termbuf.ltc);
# ifdef	TIOCGSTATE
	(void) ioctl(pty, TIOCGSTATE, (char *)&termbuf.state);
# endif
#else
# ifdef  STREAMSPTY
	(void) tcgetattr(ttyfd, &termbuf);
# else
	(void) tcgetattr(pty, &termbuf);
# endif
#endif
	termbuf2 = termbuf;
}

#if	defined(LINEMODE) && defined(TIOCPKT_IOCTL)
	void
copy_termbuf(cp, len)
	char *cp;
	int len;
{
	if (len > sizeof(termbuf))
		len = sizeof(termbuf);
	memcpy((char *)&termbuf, cp, len);
	termbuf2 = termbuf;
}
#endif	/* defined(LINEMODE) && defined(TIOCPKT_IOCTL) */

	void
set_termbuf()
{
	/*
	 * Only make the necessary changes.
	 */
#ifndef	USE_TERMIO
	if (memcmp((char *)&termbuf.sg, (char *)&termbuf2.sg, sizeof(termbuf.sg)))
		(void) ioctl(pty, TIOCSETN, (char *)&termbuf.sg);
	if (memcmp((char *)&termbuf.tc, (char *)&termbuf2.tc, sizeof(termbuf.tc)))
		(void) ioctl(pty, TIOCSETC, (char *)&termbuf.tc);
	if (memcmp((char *)&termbuf.ltc, (char *)&termbuf2.ltc,
							sizeof(termbuf.ltc)))
		(void) ioctl(pty, TIOCSLTC, (char *)&termbuf.ltc);
	if (termbuf.lflags != termbuf2.lflags)
		(void) ioctl(pty, TIOCLSET, (char *)&termbuf.lflags);
#else	/* USE_TERMIO */
	if (memcmp((char *)&termbuf, (char *)&termbuf2, sizeof(termbuf)))
# ifdef  STREAMSPTY
		(void) tcsetattr(ttyfd, TCSANOW, &termbuf);
# else
		(void) tcsetattr(pty, TCSANOW, &termbuf);
# endif
# if	defined(CRAY2) && defined(UNICOS5)
	needtermstat = 1;
# endif
#endif	/* USE_TERMIO */
}


/*
 * spcset(func, valp, valpp)
 *
 * This function takes various special characters (func), and
 * sets *valp to the current value of that character, and
 * *valpp to point to where in the "termbuf" structure that
 * value is kept.
 *
 * It returns the SLC_ level of support for this function.
 */

#ifndef	USE_TERMIO
	int
spcset(func, valp, valpp)
	int func;
	cc_t *valp;
	cc_t **valpp;
{
	switch(func) {
	case SLC_EOF:
		*valp = termbuf.tc.t_eofc;
		*valpp = (cc_t *)&termbuf.tc.t_eofc;
		return(SLC_VARIABLE);
	case SLC_EC:
		*valp = termbuf.sg.sg_erase;
		*valpp = (cc_t *)&termbuf.sg.sg_erase;
		return(SLC_VARIABLE);
	case SLC_EL:
		*valp = termbuf.sg.sg_kill;
		*valpp = (cc_t *)&termbuf.sg.sg_kill;
		return(SLC_VARIABLE);
	case SLC_IP:
		*valp = termbuf.tc.t_intrc;
		*valpp = (cc_t *)&termbuf.tc.t_intrc;
		return(SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_ABORT:
		*valp = termbuf.tc.t_quitc;
		*valpp = (cc_t *)&termbuf.tc.t_quitc;
		return(SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_XON:
		*valp = termbuf.tc.t_startc;
		*valpp = (cc_t *)&termbuf.tc.t_startc;
		return(SLC_VARIABLE);
	case SLC_XOFF:
		*valp = termbuf.tc.t_stopc;
		*valpp = (cc_t *)&termbuf.tc.t_stopc;
		return(SLC_VARIABLE);
	case SLC_AO:
		*valp = termbuf.ltc.t_flushc;
		*valpp = (cc_t *)&termbuf.ltc.t_flushc;
		return(SLC_VARIABLE);
	case SLC_SUSP:
		*valp = termbuf.ltc.t_suspc;
		*valpp = (cc_t *)&termbuf.ltc.t_suspc;
		return(SLC_VARIABLE);
	case SLC_EW:
		*valp = termbuf.ltc.t_werasc;
		*valpp = (cc_t *)&termbuf.ltc.t_werasc;
		return(SLC_VARIABLE);
	case SLC_RP:
		*valp = termbuf.ltc.t_rprntc;
		*valpp = (cc_t *)&termbuf.ltc.t_rprntc;
		return(SLC_VARIABLE);
	case SLC_LNEXT:
		*valp = termbuf.ltc.t_lnextc;
		*valpp = (cc_t *)&termbuf.ltc.t_lnextc;
		return(SLC_VARIABLE);
	case SLC_FORW1:
		*valp = termbuf.tc.t_brkc;
		*valpp = (cc_t *)&termbuf.ltc.t_lnextc;
		return(SLC_VARIABLE);
	case SLC_BRK:
	case SLC_SYNCH:
	case SLC_AYT:
	case SLC_EOR:
		*valp = (cc_t)0;
		*valpp = (cc_t *)0;
		return(SLC_DEFAULT);
	default:
		*valp = (cc_t)0;
		*valpp = (cc_t *)0;
		return(SLC_NOSUPPORT);
	}
}

#else	/* USE_TERMIO */

	int
spcset(func, valp, valpp)
	int func;
	cc_t *valp;
	cc_t **valpp;
{

#define	setval(a, b)	*valp = termbuf.c_cc[a]; \
			*valpp = &termbuf.c_cc[a]; \
			return(b);
#define	defval(a) *valp = ((cc_t)a); *valpp = (cc_t *)0; return(SLC_DEFAULT);

	switch(func) {
	case SLC_EOF:
		setval(VEOF, SLC_VARIABLE);
	case SLC_EC:
		setval(VERASE, SLC_VARIABLE);
	case SLC_EL:
		setval(VKILL, SLC_VARIABLE);
	case SLC_IP:
		setval(VINTR, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_ABORT:
		setval(VQUIT, SLC_VARIABLE|SLC_FLUSHIN|SLC_FLUSHOUT);
	case SLC_XON:
#ifdef	VSTART
		setval(VSTART, SLC_VARIABLE);
#else
		defval(0x13);
#endif
	case SLC_XOFF:
#ifdef	VSTOP
		setval(VSTOP, SLC_VARIABLE);
#else
		defval(0x11);
#endif
	case SLC_EW:
#ifdef	VWERASE
		setval(VWERASE, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_RP:
#ifdef	VREPRINT
		setval(VREPRINT, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_LNEXT:
#ifdef	VLNEXT
		setval(VLNEXT, SLC_VARIABLE);
#else
		defval(0);
#endif
	case SLC_AO:
#if	!defined(VDISCARD) && defined(VFLUSHO)
# define VDISCARD VFLUSHO
#endif
#ifdef	VDISCARD
		setval(VDISCARD, SLC_VARIABLE|SLC_FLUSHOUT);
#else
		defval(0);
#endif
	case SLC_SUSP:
#ifdef	VSUSP
		setval(VSUSP, SLC_VARIABLE|SLC_FLUSHIN);
#else
		defval(0);
#endif
#ifdef	VEOL
	case SLC_FORW1:
		setval(VEOL, SLC_VARIABLE);
#endif
#ifdef	VEOL2
	case SLC_FORW2:
		setval(VEOL2, SLC_VARIABLE);
#endif
	case SLC_AYT:
#ifdef	VSTATUS
		setval(VSTATUS, SLC_VARIABLE);
#else
		defval(0);
#endif

	case SLC_BRK:
	case SLC_SYNCH:
	case SLC_EOR:
		defval(0);

	default:
		*valp = 0;
		*valpp = 0;
		return(SLC_NOSUPPORT);
	}
}
#endif	/* USE_TERMIO */

#ifdef CRAY
/*
 * getnpty()
 *
 * Return the number of pty's configured into the system.
 */
	int
getnpty()
{
#ifdef _SC_CRAY_NPTY
	int numptys;

	if ((numptys = sysconf(_SC_CRAY_NPTY)) != -1)
		return numptys;
	else
#endif /* _SC_CRAY_NPTY */
		return 128;
}
#endif /* CRAY */

#ifndef	convex
/*
 * getpty()
 *
 * Allocate a pty.  As a side effect, the external character
 * array "line" contains the name of the slave side.
 *
 * Returns the file descriptor of the opened pty.
 */
static char Xline[17];
char *line = Xline;

#ifdef	CRAY
char *myline = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#endif	/* CRAY */


#endif	/* convex */

static pid_t slavepid = 0;

#ifdef	LINEMODE
/*
 * tty_flowmode()	Find out if flow control is enabled or disabled.
 * tty_linemode()	Find out if linemode (external processing) is enabled.
 * tty_setlinemod(on)	Turn on/off linemode.
 * tty_isecho()		Find out if echoing is turned on.
 * tty_setecho(on)	Enable/disable character echoing.
 * tty_israw()		Find out if terminal is in RAW mode.
 * tty_binaryin(on)	Turn on/off BINARY on input.
 * tty_binaryout(on)	Turn on/off BINARY on output.
 * tty_isediting()	Find out if line editing is enabled.
 * tty_istrapsig()	Find out if signal trapping is enabled.
 * tty_setedit(on)	Turn on/off line editing.
 * tty_setsig(on)	Turn on/off signal trapping.
 * tty_issofttab()	Find out if tab expansion is enabled.
 * tty_setsofttab(on)	Turn on/off soft tab expansion.
 * tty_islitecho()	Find out if typed control chars are echoed literally
 * tty_setlitecho()	Turn on/off literal echo of control chars
 * tty_tspeed(val)	Set transmit speed to val.
 * tty_rspeed(val)	Set receive speed to val.
 */

#ifdef convex
static int linestate;
#endif

	int
tty_linemode()
{
#ifndef convex
#ifndef	USE_TERMIO
	return(termbuf.state & TS_EXTPROC);
#else
	return(termbuf.c_lflag & EXTPROC);
#endif
#else
	return(linestate);
#endif
}

	void
tty_setlinemode(on)
	int on;
{
#ifdef	TIOCEXT
# ifndef convex
	set_termbuf();
# else
	linestate = on;
# endif
	(void) ioctl(pty, TIOCEXT, (char *)&on);
# ifndef convex
	init_termbuf();
# endif
#else	/* !TIOCEXT */
# ifdef	EXTPROC
	if (on)
		termbuf.c_lflag |= EXTPROC;
	else
		termbuf.c_lflag &= ~EXTPROC;
# endif
#endif	/* TIOCEXT */
}
#endif	/* LINEMODE */

	int
tty_isecho()
{
#ifndef USE_TERMIO
	return (termbuf.sg.sg_flags & ECHO);
#else
	return (termbuf.c_lflag & ECHO);
#endif
}

	int
tty_flowmode()
{
#ifndef USE_TERMIO
	return(((termbuf.tc.t_startc) > 0 && (termbuf.tc.t_stopc) > 0) ? 1 : 0);
#else
	return((termbuf.c_iflag & IXON) ? 1 : 0);
#endif
}

	int
tty_restartany()
{
#ifndef USE_TERMIO
# ifdef	DECCTQ
	return((termbuf.lflags & DECCTQ) ? 0 : 1);
# else
	return(-1);
# endif
#else
	return((termbuf.c_iflag & IXANY) ? 1 : 0);
#endif
}

	void
tty_setecho(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		termbuf.sg.sg_flags |= ECHO|CRMOD;
	else
		termbuf.sg.sg_flags &= ~(ECHO|CRMOD);
#else
	if (on)
		termbuf.c_lflag |= ECHO;
	else
		termbuf.c_lflag &= ~ECHO;
#endif
}

	int
tty_israw()
{
#ifndef USE_TERMIO
	return(termbuf.sg.sg_flags & RAW);
#else
	return(!(termbuf.c_lflag & ICANON));
#endif
}

#if	defined (AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	int
tty_setraw(on)
{
#  ifndef USE_TERMIO
	if (on)
		termbuf.sg.sg_flags |= RAW;
	else
		termbuf.sg.sg_flags &= ~RAW;
#  else
	if (on)
		termbuf.c_lflag &= ~ICANON;
	else
		termbuf.c_lflag |= ICANON;
#  endif
}
#endif

	void
tty_binaryin(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		termbuf.lflags |= LPASS8;
	else
		termbuf.lflags &= ~LPASS8;
#else
	if (on) {
		termbuf.c_iflag &= ~ISTRIP;
	} else {
		termbuf.c_iflag |= ISTRIP;
	}
#endif
}

	void
tty_binaryout(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		termbuf.lflags |= LLITOUT;
	else
		termbuf.lflags &= ~LLITOUT;
#else
	if (on) {
		termbuf.c_cflag &= ~(CSIZE|PARENB);
		termbuf.c_cflag |= CS8;
		termbuf.c_oflag &= ~OPOST;
	} else {
		termbuf.c_cflag &= ~CSIZE;
		termbuf.c_cflag |= CS7|PARENB;
		termbuf.c_oflag |= OPOST;
	}
#endif
}

	int
tty_isbinaryin()
{
#ifndef	USE_TERMIO
	return(termbuf.lflags & LPASS8);
#else
	return(!(termbuf.c_iflag & ISTRIP));
#endif
}

	int
tty_isbinaryout()
{
#ifndef	USE_TERMIO
	return(termbuf.lflags & LLITOUT);
#else
	return(!(termbuf.c_oflag&OPOST));
#endif
}

#ifdef	LINEMODE
	int
tty_isediting()
{
#ifndef USE_TERMIO
	return(!(termbuf.sg.sg_flags & (CBREAK|RAW)));
#else
	return(termbuf.c_lflag & ICANON);
#endif
}

	int
tty_istrapsig()
{
#ifndef USE_TERMIO
	return(!(termbuf.sg.sg_flags&RAW));
#else
	return(termbuf.c_lflag & ISIG);
#endif
}

	void
tty_setedit(on)
	int on;
{
#ifndef USE_TERMIO
	if (on)
		termbuf.sg.sg_flags &= ~CBREAK;
	else
		termbuf.sg.sg_flags |= CBREAK;
#else
	if (on)
		termbuf.c_lflag |= ICANON;
	else
		termbuf.c_lflag &= ~ICANON;
#endif
}

	void
tty_setsig(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		;
#else
	if (on)
		termbuf.c_lflag |= ISIG;
	else
		termbuf.c_lflag &= ~ISIG;
#endif
}
#endif	/* LINEMODE */

	int
tty_issofttab()
{
#ifndef	USE_TERMIO
	return (termbuf.sg.sg_flags & XTABS);
#else
# ifdef	OXTABS
	return (termbuf.c_oflag & OXTABS);
# endif
# ifdef	TABDLY
	return ((termbuf.c_oflag & TABDLY) == TAB3);
# endif
#endif
}

	void
tty_setsofttab(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		termbuf.sg.sg_flags |= XTABS;
	else
		termbuf.sg.sg_flags &= ~XTABS;
#else
	if (on) {
# ifdef	OXTABS
		termbuf.c_oflag |= OXTABS;
# endif
# ifdef	TABDLY
		termbuf.c_oflag &= ~TABDLY;
		termbuf.c_oflag |= TAB3;
# endif
	} else {
# ifdef	OXTABS
		termbuf.c_oflag &= ~OXTABS;
# endif
# ifdef	TABDLY
		termbuf.c_oflag &= ~TABDLY;
		termbuf.c_oflag |= TAB0;
# endif
	}
#endif
}

	int
tty_islitecho()
{
#ifndef	USE_TERMIO
	return (!(termbuf.lflags & LCTLECH));
#else
# ifdef	ECHOCTL
	return (!(termbuf.c_lflag & ECHOCTL));
# endif
# ifdef	TCTLECH
	return (!(termbuf.c_lflag & TCTLECH));
# endif
# if	!defined(ECHOCTL) && !defined(TCTLECH)
	return (0);	/* assumes ctl chars are echoed '^x' */
# endif
#endif
}

	void
tty_setlitecho(on)
	int on;
{
#ifndef	USE_TERMIO
	if (on)
		termbuf.lflags &= ~LCTLECH;
	else
		termbuf.lflags |= LCTLECH;
#else
# ifdef	ECHOCTL
	if (on)
		termbuf.c_lflag &= ~ECHOCTL;
	else
		termbuf.c_lflag |= ECHOCTL;
# endif
# ifdef	TCTLECH
	if (on)
		termbuf.c_lflag &= ~TCTLECH;
	else
		termbuf.c_lflag |= TCTLECH;
# endif
#endif
}

	int
tty_iscrnl()
{
#ifndef	USE_TERMIO
	return (termbuf.sg.sg_flags & CRMOD);
#else
	return (termbuf.c_iflag & ICRNL);
#endif
}

/*
 * A table of available terminal speeds
 */
struct termspeeds {
	int	speed;
	speed_t	value;
} termspeeds[] = {
	{ 0,     B0 },    { 50,    B50 },   { 75,    B75 },
	{ 110,   B110 },  { 134,   B134 },  { 150,   B150 },
	{ 200,   B200 },  { 300,   B300 },  { 600,   B600 },
	{ 1200,  B1200 }, { 1800,  B1800 }, { 2400,  B2400 },
	{ 4800,  B4800 }, { 9600,  B9600 }, { 19200, B9600 },
	{ 38400, B9600 }, { -1,    B9600 }
};

	void
tty_tspeed(val)
	int val;
{
	register struct termspeeds *tp;

	for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++)
		;
	cfsetospeed(&termbuf, tp->value);
}

	void
tty_rspeed(val)
	int val;
{
	register struct termspeeds *tp;

	for (tp = termspeeds; (tp->speed != -1) && (val > tp->speed); tp++)
		;
	cfsetispeed(&termbuf, tp->value);
}

#if	defined(CRAY2) && defined(UNICOS5)
	int
tty_isnewmap()
{
	return((termbuf.c_oflag & OPOST) && (termbuf.c_oflag & ONLCR) &&
			!(termbuf.c_oflag & ONLRET));
}
#endif


#ifndef	NEWINIT
#endif

/*
 * getptyslave()
 *
 * Open the slave side of the pty, and do any initialization
 * that is necessary.  The return value is a file descriptor
 * for the slave side.
 */
static void
getptyslave()
{
     int t = -1;
     long retval;

#if	!defined(CRAY) || !defined(NEWINIT)
# ifdef	LINEMODE
	int waslm;
# endif
# ifdef	TIOCGWINSZ
	struct winsize ws;
	extern int def_row, def_col;
# endif
	extern int def_tspeed, def_rspeed;
	/*
	 * Opening the slave side may cause initilization of the
	 * kernel tty structure.  We need remember the state of
	 * 	if linemode was turned on
	 *	terminal window size
	 *	terminal speed
	 * so that we can re-set them if we need to.
	 */
# ifdef	LINEMODE
	waslm = tty_linemode();
# endif

	if ( (retval = pty_open_slave (line, &t)) != 0 )
	    {
		fatalperror(net,  error_message(retval));
	    }

#ifdef  STREAMSPTY
#ifdef	USE_TERMIO
	ttyfd = t;
#endif
	if (ioctl(pty, I_PUSH, "pckt") < 0) {
#ifndef _AIX
		fatal(net, "I_PUSH pckt");
#endif
	}
#endif

	/*
	 * set up the tty modes as we like them to be.
	 */
	init_termbuf();
# ifdef	TIOCGWINSZ
	if (def_row || def_col) {
		memset((char *)&ws, 0, sizeof(ws));
		ws.ws_col = def_col;
		ws.ws_row = def_row;
		(void)ioctl(t, TIOCSWINSZ, (char *)&ws);
	}
# endif

	/*
	 * Settings for sgtty based systems
	 */
# ifndef	USE_TERMIO
	termbuf.sg.sg_flags |= CRMOD|ANYP|ECHO|XTABS;
# endif	/* USE_TERMIO */

	/*
	 * Settings for UNICOS (and HPUX)
	 */
# if defined(CRAY) || defined(__hpux)
	termbuf.c_oflag = OPOST|ONLCR|TAB3;
	termbuf.c_iflag = IGNPAR|ISTRIP|ICRNL|IXON;
	termbuf.c_lflag = ISIG|ICANON|ECHO|ECHOE|ECHOK;
	termbuf.c_cflag = EXTB|HUPCL|CS8;
# endif

	/*
	 * Settings for all other termios/termio based
	 * systems, other than 4.4BSD.  In 4.4BSD the
	 * kernel does the initial terminal setup.
	 */
# if defined(USE_TERMIO) && !(defined(CRAY) || defined(__hpux)) && (BSD <= 43)
#  ifndef	OXTABS
#   define OXTABS	0
#  endif
	termbuf.c_lflag |= ECHO|ICANON|IEXTEN|ISIG;
	termbuf.c_oflag |= ONLCR|OXTABS|OPOST;
	termbuf.c_iflag |= ICRNL|IGNPAR;
termbuf.c_cflag |= HUPCL;
	termbuf.c_iflag &= ~IXOFF;
# endif /* defined(USE_TERMIO) && !defined(CRAY) && (BSD <= 43) */
	tty_rspeed((def_rspeed > 0) ? def_rspeed : 9600);
	tty_tspeed((def_tspeed > 0) ? def_tspeed : 9600);
# ifdef	LINEMODE
	if (waslm)
		tty_setlinemode(1);
# endif	/* LINEMODE */

	/*
	 * Set the tty modes, and make this our controlling tty.
	 */
	set_termbuf();
	if (dup_tty(t) == -1)
		fatalperror(net, "dup_tty");
#endif	/* !defined(CRAY) || !defined(NEWINIT) */
	if (net > 2)
		(void) close(net);
#if	defined(AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	/*
	 * Leave the pty open so that we can write out the rlogin
	 * protocol for /bin/login, if the authentication works.
	 */
#else
	if (pty > 2) {
		(void) close(pty);
		pty = -1;
	}
#endif
}

#if	!defined(CRAY) || !defined(NEWINIT)
#ifndef	O_NOCTTY
#define	O_NOCTTY	0
#endif
#endif	/* !defined(CRAY) || !defined(NEWINIT) */



	int
dup_tty(t)
	int t;
{
	if (t != 0)
		(void) dup2(t, 0);
	if (t != 1)
		(void) dup2(t, 1);
	if (t != 2)
		(void) dup2(t, 2);
	if (t > 2)
		close(t);
	return(0);
}


#ifdef	NEWINIT
char *gen_id = "fe";
#endif

/*
 * startslave(host)
 *
 * Given a hostname, do whatever
 * is necessary to startup the login process on the slave side of the pty.
 */


/* ARGSUSED */
	void
startslave(host, autologin, autoname)
	char *host;
	int autologin;
	char *autoname;
{
	int syncpipe[2];
	register int i;
#ifdef	NEWINIT
	extern char *ptyip;
	struct init_request request;
	void nologinproc();
	register int n;
#endif	/* NEWINIT */

	if ( pipe(syncpipe) < 0 ) 
		fatal(net, "failed getting synchronization pipe");
    
#if	defined(AUTHENTICATION)
	if (!autoname || !autoname[0])
		autologin = 0;

	if (autologin < auth_level) {
		fatal(net, "Authorization failed");
		exit(1);
	}
#endif

#ifndef	NEWINIT

	if ((i = fork()) < 0)
		fatalperror(net, "fork");
	if (i) {
		char c;

		void sigjob (int);
		slavepid = i; /* So we can clean it up later */
#ifdef	CRAY
		(void) signal(WJSIGNAL, sigjob);
#endif

		/* Wait for child before writing to parent side of pty.*/
		(void) close(syncpipe[1]);
		if ( read(syncpipe[0], &c, 1) == 0 ) {
			/* Slave side died */
			fatal ( net, "Slave failed to initialize");
		}

		close(syncpipe[0]);
		
	} else {
		
		pty_update_utmp (PTY_LOGIN_PROCESS, getpid(), "LOGIN", line,
				 host, PTY_TTYSLOT_USABLE);
		getptyslave();

		/* Notify our parent we're ready to continue.*/
		write(syncpipe[1],"y",1);
		close(syncpipe[0]);
		close(syncpipe[1]);
		
		start_login(host, autologin, autoname);
		/*NOTREACHED*/
	}
#else	/* NEWINIT */

	/*
	 * Init will start up login process if we ask nicely.  We only wait
	 * for it to start up and begin normal telnet operation.
	 */
	if ((i = open(INIT_FIFO, O_WRONLY)) < 0) {
		char tbuf[128];
		(void) sprintf(tbuf, "Can't open %s\n", INIT_FIFO);
		fatalperror(net, tbuf);
	}
	memset((char *)&request, 0, sizeof(request));
	request.magic = INIT_MAGIC;
	SCPYN(request.gen_id, gen_id);
	SCPYN(request.tty_id, &line[8]);
	SCPYN(request.host, host);
	SCPYN(request.term_type, *terminaltype ? terminaltype : "network");
#if	!defined(UNICOS5)
	request.signal = SIGCLD;
	request.pid = getpid();
#endif
#ifdef BFTPDAEMON
	/*
	 * Are we working as the bftp daemon?
	 */
	if (bftpd) {
		SCPYN(request.exec_name, BFTPPATH);
	}
#endif /* BFTPDAEMON */
	if (write(i, (char *)&request, sizeof(request)) < 0) {
		char tbuf[128];
		(void) sprintf(tbuf, "Can't write to %s\n", INIT_FIFO);
		fatalperror(net, tbuf);
	}
	(void) close(i);
	(void) signal(SIGALRM, nologinproc);
	for (i = 0; ; i++) {
		char tbuf[128];
		alarm(15);
		n = read(pty, ptyip, BUFSIZ);
		if (i == 3 || n >= 0 || !gotalarm)
			break;
		gotalarm = 0;
		sprintf(tbuf, "telnetd: waiting for /etc/init to start login process on %s\r\n", line);
		(void) write(net, tbuf, strlen(tbuf));
	}
	if (n < 0 && gotalarm)
		fatal(net, "/etc/init didn't start login process");
	pcc += n;
	alarm(0);
	(void) signal(SIGALRM, SIG_DFL);

	return;
#endif	/* NEWINIT */
}

char	*envinit[3];
extern char **environ;

	void
init_env()
{
	extern char *getenv();
	char **envp;

	envp = envinit;
	if ((*envp = getenv("TZ")))
		*envp++ -= 3;
#if	defined(CRAY) || defined(__hpux)
	else
		*envp++ = "TZ=GMT0";
#endif
	*envp = 0;
	environ = envinit;
}

#ifndef	NEWINIT

/*
 * start_login(host)
 *
 * Assuming that we are now running as a child processes, this
 * function will turn us into the login process.
 */

	void
start_login(host, autologin, name)
	char *host;
	int autologin;
	char *name;
{
	register char **argv;
	extern char *getenv();

#ifdef SOLARIS
	char *term;
	char termbuf[64];
#endif


	/*
	 * -h : pass on name of host.
	 *		WARNING:  -h is accepted by login if and only if
	 *			getuid() == 0.
	 * -p : don't clobber the environment (so terminal type stays set).
	 *
	 * -f : force this login, he has already been authenticated
	 */
	argv = addarg(0, "login");

#if	!defined(NO_LOGIN_H)

# if	defined (AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	/*
	 * Don't add the "-h host" option if we are going
	 * to be adding the "-r host" option down below...
	 */
	if ((auth_level < 0) || (autologin != AUTH_VALID))
# endif
	{
		argv = addarg(argv, "-h");
		argv = addarg(argv, host);
#ifdef	SOLARIS
		/*
		 * SVR4 version of -h takes TERM= as second arg, or -
		 */
		term = getenv("TERM");
		if (term == NULL || term[0] == 0) {
			term = "-";
		} else {
			strcpy(termbuf, "TERM=");
			strncat(termbuf, term, sizeof(termbuf) - 6);
			termbuf[sizeof(termbuf) - 1] = '\0';
			term = termbuf;
		}
		argv = addarg(argv, term);
#endif
	}
#endif
#if	!defined(NO_LOGIN_P)
	argv = addarg(argv, "-p");
#endif
#ifdef	BFTPDAEMON
	/*
	 * Are we working as the bftp daemon?  If so, then ask login
	 * to start bftp instead of shell.
	 */
	if (bftpd) {
		argv = addarg(argv, "-e");
		argv = addarg(argv, BFTPPATH);
	} else 
#endif
#if	defined (SecurID)
	/*
	 * don't worry about the -f that might get sent.
	 * A -s is supposed to override it anyhow.
	 */
	if (require_SecurID)
		argv = addarg(argv, "-s");
#endif
#if	defined (AUTHENTICATION)
	if (auth_level >= 0 && autologin == AUTH_VALID) {
# if	!defined(NO_LOGIN_F)
#if	defined(LOGIN_CAP_F)
		argv = addarg(argv, "-F");
#else
		argv = addarg(argv, "-f");
#endif
		argv = addarg(argv, name);
# else
#  if defined(LOGIN_R)
		/*
		 * We don't have support for "login -f", but we
		 * can fool /bin/login into thinking that we are
		 * rlogind, and allow us to log in without a
		 * password.  The rlogin protocol expects
		 *	local-user\0remote-user\0term/speed\0
		 */

		if (pty > 2) {
			register char *cp;
			char speed[1024];
			int isecho, israw, xpty, len;
			extern int def_rspeed;
#  ifndef LOGIN_HOST
			/*
			 * Tell login that we are coming from "localhost".
			 * If we passed in the real host name, then the
			 * user would have to allow .rhost access from
			 * every machine that they want authenticated
			 * access to work from, which sort of defeats
			 * the purpose of an authenticated login...
			 * So, we tell login that the session is coming
			 * from "localhost", and the user will only have
			 * to have "localhost" in their .rhost file.
			 */
#			define LOGIN_HOST "localhost"
#  endif
			argv = addarg(argv, "-r");
			argv = addarg(argv, LOGIN_HOST);

			xpty = pty;
# ifndef  STREAMSPTY
			pty = 0;
# else
			ttyfd = 0;
# endif
			init_termbuf();
			isecho = tty_isecho();
			israw = tty_israw();
			if (isecho || !israw) {
				tty_setecho(0);		/* Turn off echo */
				tty_setraw(1);		/* Turn on raw */
				set_termbuf();
			}
			len = strlen(name)+1;
			write(xpty, name, len);
			write(xpty, name, len);
			memset(speed, 0, sizeof(speed));
			strncpy(speed,
				(cp = getenv("TERM")) ? cp : "",
				sizeof(speed)-1-(10*sizeof(def_rspeed)/4)-1);
			/* 1 for /, () for the number, 1 for trailing 0. */
			sprintf(speed + strlen(speed),
				"/%d",
				(def_rspeed > 0) ? def_rspeed : 9600);
			len = strlen(speed)+1;
			write(xpty, speed, len);

			if (isecho || !israw) {
				init_termbuf();
				tty_setecho(isecho);
				tty_setraw(israw);
				set_termbuf();
				if (!israw) {
					/*
					 * Write a newline to ensure
					 * that login will be able to
					 * read the line...
					 */
					write(xpty, "\n", 1);
				}
			}
			pty = xpty;
		}
#  else
		argv = addarg(argv, name);
#  endif
# endif
	} else
#endif
	if (getenv("USER")) {
		argv = addarg(argv, getenv("USER"));
#if	defined(LOGIN_ARGS) && defined(NO_LOGIN_P)
		{
			register char **cpp;
			for (cpp = environ; *cpp; cpp++)
				argv = addarg(argv, *cpp);
		}
#endif
		/*
		 * Assume that login will set the USER variable
		 * correctly.  For SysV systems, this means that
		 * USER will no longer be set, just LOGNAME by
		 * login.  (The problem is that if the auto-login
		 * fails, and the user then specifies a different
		 * account name, he can get logged in with both
		 * LOGNAME and USER in his environment, but the
		 * USER value will be wrong.
		 */
		unsetenv("USER");
	}
#if	defined(AUTHENTICATION) && defined(NO_LOGIN_F) && defined(LOGIN_R)
	if (pty > 2)
		close(pty);
#endif
	closelog();
	execv(login_program, argv);

	syslog(LOG_ERR, "%s: %m", login_program);
	fatalperror(net, login_program);
	/*NOTREACHED*/
}

/*
 * This code returns a pointer to the first element of the array and
 * expects the same to be called with.
 * Therefore the -1 reference is legal. 
 */

static char **
addarg(argv, val)
	register char **argv;
	register char *val;
{
	register char **cpp;

	if (argv == NULL) {
		/*
		 * 10 entries, a leading length, and a null
		 */
		argv = (char **)malloc(sizeof(*argv) * 12);
		if (argv == NULL)
			return(NULL);
		*argv++ = (char *)10;
		*argv = (char *)0;
	}
	for (cpp = argv; *cpp; cpp++)
		;
	if (cpp == &argv[(long)argv[-1]]) {
		--argv;
		*argv = (char *)((long)(*argv) + 10);
		argv = (char **)realloc(argv, sizeof(*argv) * ((long)(*argv) + 2));
		if (argv == NULL)
			return(NULL);
		argv++;
		cpp = &argv[(long)argv[-1] - 10];
	}
	*cpp++ = val;
	*cpp = 0;
	return(argv);
}
#endif	/* NEWINIT */

/*
 * cleanup()
 *
 * This is the routine to call when we are all through, to
 * clean up anything that needs to be cleaned up.
 */
	/* ARGSUSED */
	void
cleanup(sig)
	int sig;
{
	pty_cleanup(line,slavepid,1);
#ifdef KRB5
	kerberos5_cleanup();
#endif
    
	(void) shutdown(net, 2);
	exit(1);
}





