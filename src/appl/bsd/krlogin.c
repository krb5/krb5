/*
 *    appl/bsd/krlogin.c
 */

/*
 * Copyright (c) 1983 The Regents of the University of California.
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
char copyright[] =
  "@(#) Copyright (c) 1983 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

/* based on @(#)rlogin.c	5.12 (Berkeley) 9/19/88 */

     
     /*
      * rlogin - remote login
      */
     
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif


#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>
     
#ifdef HAVE_SYS_FILIO_H
/* Solaris needs <sys/filio.h> for FIONREAD */
#include <sys/filio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef POSIX_TERMIOS
#include <termios.h>
#ifndef CNUL
#define CNUL (char) 0
#endif

#else /* POSIX_TERMIOS */
#include <sgtty.h>
#endif /* POSIX_TERMIOS */

#ifdef HAVE_SYS_SOCKIO_H
/* for SIOCATMARK */
#include <sys/sockio.h>
#endif

#ifdef HAVE_STREAMS
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

#ifdef __SCO__
/* for TIOCPKT_* */
#include <sys/spt.h>
/* for struct winsize */
#include <sys/ptem.h>
#endif

#ifdef HAVE_STREAMS
#ifdef HAVE_SYS_PTYVAR_H
#include <sys/tty.h>
#include <sys/ttold.h>
/* solaris actually uses packet mode, so the real macros are needed too */
#include <sys/ptyvar.h>
#endif
#endif

#ifndef TIOCPKT_NOSTOP
/* These values are over-the-wire protocol, *not* local values */
#define TIOCPKT_NOSTOP          0x10
#define TIOCPKT_DOSTOP          0x20
#define TIOCPKT_FLUSHWRITE      0x02
#endif

#ifdef HAVE_SYS_IOCTL_COMPAT_H
#include <sys/ioctl_compat.h>
#endif

#ifdef CRAY
#include <sys/ttold.h>
#endif


#ifdef KERBEROS
#include <krb5.h>
#include <com_err.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif
#include "defines.h"
     
#define RLOGIN_BUFSIZ 5120

void try_normal();
char *krb_realm = (char *)0;
int encrypt_flag = 0;
int fflag = 0, Fflag = 0;
krb5_creds *cred;
struct sockaddr_in local, foreign;
krb5_context bsd_context;
krb5_auth_context auth_context;

#ifdef KRB5_KRB4_COMPAT
Key_schedule v4_schedule;
CREDENTIALS v4_cred;
#endif

#ifndef UCB_RLOGIN
#define UCB_RLOGIN      "/usr/ucb/rlogin"
#endif

#include "rpaths.h"
#endif /* KERBEROS */

# ifndef TIOCPKT_WINDOW
# define TIOCPKT_WINDOW 0x80
# endif /* TIOCPKT_WINDOW */

#ifndef ONOCR
#define ONOCR 0
#endif

#ifdef POSIX_TERMIOS
struct termios deftty;
#endif

char	*getenv();

char	*name;
int 	rem = -1;		/* Remote socket fd */
int	do_inband = 0;
char	cmdchar = '~';
int	eight = 1;		/* Default to 8 bit transmission */
int	no_local_escape = 0;
int	null_local_username = 0;
int	flow = 1;			/* Default is to allow flow
					   control at the local terminal */
int	flowcontrol;			/* Since emacs can alter the
					   flow control characteristics
					   of a session we need a
					   variable to keep track of
					   the original characteristics */
int	confirm = 0;			/* ask if ~. is given before dying. */
int	litout;
#if defined(hpux) || defined(__hpux)
char	*speeds[] =
{ "0", "50", "75", "110", "134", "150", "200", "300", "600",
    "900", "1200", "1800", "2400", "3600", "4800", "7200", "9600",
    "19200", "38400", "EXTA", "EXTB" };
#else
/* Solaris note: There are higher values we could use.  But Casper Dik
   <Casper.Dik@Holland.Sun.Com> mentions in article
   <casper.938167062@uk-usenet.uk.sun.com> in comp.protocols.kerberos
   on 1999-09-24 some problems in sending higher values to remote
   systems (for non-Kerberos rlogind?).  So let's stick with this
   list.  Even if our current klogind doesn't have the problems, older
   versions are likely to.

   Daniel S. Riley <dsr@mail.lns.cornell.edu> gives 57600, 76800,
   115200, 153600, 230400, 307200, 460800 as the higher values.
   (article <sh6711s713.fsf@lnscu4.lns.cornell.edu> in
   comp.protocols.kerberos, 1999-09-23) */
char    *speeds[] =
{ "0", "50", "75", "110", "134", "150", "200", "300",
    "600", "1200", "1800", "2400", "4800", "9600", "19200", "38400" };
#endif
char	term[256] = "network";

#ifndef POSIX_SIGNALS
#ifndef sigmask
#define sigmask(m)    (1 << ((m)-1))
#endif
#endif /* POSIX_SIGNALS */

#ifdef NO_WINSIZE
struct winsize {
    unsigned short ws_row, ws_col;
    unsigned short ws_xpixel, ws_ypixel;
};
#endif /* NO_WINSIZE */
int	dosigwinch = 0;
struct	winsize winsize;

char	*host=0;			/* external, so it can be
					   reached from confirm_death() */

krb5_sigtype	sigwinch (int);
int server_message (int);
void oob (void);
krb5_sigtype	lostpeer (int);
void setsignal (int sig, krb5_sigtype (*act)());
static int read_wrapper(int fd, char *buf, int size, int *got_esc);
static void prf(char *f);
void try_normal(char **);
static void mode(int);
#ifdef POSIX_SIGNALS
static int reader(sigset_t *);
static void doit(sigset_t *);
#else
static int reader(int);
static void doit(int);
#endif
static int control(char *, unsigned int);
static void sendwindow(void);
static void stop(int), echo(int);
static void writer(void), done(int);
static int confirm_death (void);


/* to allow exits from signal handlers, without conflicting declarations */
static krb5_sigtype exit_handler() {
  exit(1);
}


/*
 * The following routine provides compatibility (such as it is)
 * between 4.2BSD Suns and others.  Suns have only a `ttysize',
 * so we convert it to a winsize.
 */
#ifdef TIOCGWINSZ
#define get_window_size(fd, wp)       ioctl(fd, TIOCGWINSZ, wp)
#else
#ifdef SYSV
#ifndef SIGWINCH
#define SIGWINCH SIGWINDOW
#endif
struct ttysize {
    int ts_lines;
    int ts_cols;
};
#define DEFAULT_LINES 24
#define DEFAULT_COLS 80
#endif



int
  get_window_size(fd, wp)
int fd;
struct winsize *wp;
{
    struct ttysize ts;
    int error;
#ifdef SYSV
    char *envbuf;
    ts.ts_lines = DEFAULT_LINES;
    ts.ts_cols = DEFAULT_COLS;
    if (( envbuf = getenv("LINES")) != (char *) 0)
      ts.ts_lines = atoi(envbuf);
    if (( envbuf = getenv("COLUMNS")) != (char *) 0)
      ts.ts_cols = atoi(envbuf);
#else
    if ((error = ioctl(0, TIOCGSIZE, &ts)) != 0)
      return (error);
#endif
    
    wp->ws_row = ts.ts_lines;
    wp->ws_col = ts.ts_cols;
    wp->ws_xpixel = 0;
    wp->ws_ypixel = 0;
    return (0);
}
#endif /* TIOCGWINSZ */


#ifdef POSIX_TERMIOS
/* Globals for terminal modes and flow control */
struct  termios defmodes;
struct  termios ixon_state;
#else
#ifdef USE_TERMIO
/* Globals for terminal modes and flow control */
struct  termio defmodes;
struct  termio ixon_state;
#endif
#endif


int
main(argc, argv)
     int argc;
     char **argv;
{
    char *cp = (char *) NULL;
#ifdef POSIX_TERMIOS
    struct termios ttyb;
#else
#ifdef USE_TERMIO
    struct termio ttyb;
#else
    struct sgttyb ttyb;
#endif
#endif
    struct passwd *pwd;
    struct servent *sp;
    struct servent defaultservent;
    int uid, options = 0;
#ifdef POSIX_SIGNALS
    struct sigaction sa;
    sigset_t *oldmask, omask, urgmask;
#else
    int oldmask;
#endif
    int on = 1;
#ifdef KERBEROS
    char **orig_argv = argv;
    int sock;
    krb5_flags authopts;
    krb5_error_code status;
#ifdef KRB5_KRB4_COMPAT
    KTEXT_ST v4_ticket;
    MSG_DAT v4_msg_data;
    int v4only = 0;
#endif
#endif
    int port, debug_port = 0;
    enum kcmd_proto kcmd_proto = KCMD_PROTOCOL_COMPAT_HACK;

    memset(&defaultservent, 0, sizeof(struct servent));
    if (strrchr(argv[0], '/'))
      argv[0] = strrchr(argv[0], '/')+1;

    if ( argc < 2 ) goto usage;
    argc--;
    argv++;

  another:
    if (argc > 0 && host == 0 && strncmp(*argv, "-", 1)) {
	host = *argv;
	argv++, argc--;
	goto another;
    }

    if (argc > 0 && !strcmp(*argv, "-D")) {
	argv++; argc--;
	if (*argv == NULL) {
	    fprintf (stderr,
		     "rlogin: -D flag must be followed by the debug port.\n");
	    exit (1);
	}
	debug_port = htons(atoi(*argv));
	argv++; argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-d")) {
	argv++, argc--;
	options |= SO_DEBUG;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-c")) {
	confirm = 1;
	argv++; argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-a")) {	   /* ask -- make remote */
	argv++; argc--;			/* machine ask for password */
	null_local_username = 1;	/* by giving null local user */
	goto another;			/* id */
    }
    if (argc > 0 && !strcmp(*argv, "-t")) {
	argv++; argc--;
	if (argc == 0) goto usage;
	cp = *argv++; argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-n")) {
	no_local_escape = 1;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-7")) {  /* Pass only 7 bits */
	eight = 0;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-noflow")) {
	flow = 0;		/* Turn off local flow control so
				   that ^S can be passed to emacs. */
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-l")) {
	argv++, argc--;
	if (argc == 0)
	  goto usage;
	name = *argv++; argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-e", 2)) {
	cmdchar = argv[0][2];
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-8")) {
	eight = 1;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-L")) {
	litout = 1;
	argv++, argc--;
	goto another;
    }
#ifdef KERBEROS
    if (argc > 0 && !strcmp(*argv, "-k")) {
	argv++, argc--;
	if (argc == 0) {
	    fprintf(stderr,
		    "rlogin: -k flag must be followed with a realm name.\n");
	    exit (1);
	}
	if(!(krb_realm = strdup(*argv))){
	    fprintf(stderr, "rlogin: Cannot malloc.\n");
	    exit(1);
	}
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-x")) {
	encrypt_flag++;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-f")) {
	if (Fflag) {
	    fprintf(stderr, "rlogin: Only one of -f and -F allowed\n");
	    goto usage;
	}
	fflag++;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-F")) {
	if (fflag) {
	    fprintf(stderr, "rlogin: Only one of -f and -F allowed\n");
	    goto usage;
	}
	Fflag++;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-PO")) {
	kcmd_proto = KCMD_OLD_PROTOCOL;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-PN")) {
	kcmd_proto = KCMD_NEW_PROTOCOL;
	argv++, argc--;
	goto another;
    }
#ifdef KRB5_KRB4_COMPAT
    if (argc > 0 && !strcmp(*argv, "-4")) {
	v4only++;
	argv++, argc--;
	goto another;
    }
#endif /* krb4 */
#endif /* KERBEROS */
    if (host == 0)
      goto usage;
    if (argc > 0)
      goto usage;
#ifdef KRB5_KRB4_COMPAT
    if (kcmd_proto != KCMD_PROTOCOL_COMPAT_HACK && v4only) {
	com_err (argv[0], 0,
		 "-4 is incompatible with -PO/-PN");
	exit(1);
    }
#endif
    pwd = getpwuid(getuid());
    if (pwd == 0) {
	fprintf(stderr, "Who are you?\n");
	exit(1);
    }
#ifdef KERBEROS
    status = krb5_init_context(&bsd_context);
    if (status) {
	    com_err(argv[0], status, "while initializing krb5");
	    exit(1);
    }
#endif


    if (debug_port)
      port = debug_port;
    else {
#ifdef KERBEROS
    /*
     * if there is an entry in /etc/services for Kerberos login,
     * attempt to login with Kerberos. 
     * If we fail at any step,  use the standard rlogin
     */
      if (encrypt_flag)
	sp = getservbyname("eklogin","tcp");
      else 
	sp = getservbyname("klogin","tcp");
      if (sp == 0) {
		sp = &defaultservent;   /* ANL */
		sp->s_port = encrypt_flag ? htons(2105) : htons(543);
      }
#else
      sp = getservbyname("login", "tcp");
      if (sp == 0) {
	fprintf(stderr, "rlogin: login/tcp: unknown service\n");
	exit(2);
      }
#endif /* KERBEROS */

      port = sp->s_port;
    }


    if (cp == (char *) NULL) cp = getenv("TERM");
    if (cp) {
      (void) strncpy(term, cp, sizeof (term));
      term[sizeof (term) - 1] = '\0';
    }
#ifdef POSIX_TERMIOS
	if (tcgetattr(0, &ttyb) == 0) {
		int ospeed = cfgetospeed (&ttyb);

                term[sizeof(term) - 1] = '\0';
		(void) strncat(term, "/", sizeof(term) - 1 - strlen(term));
		if (ospeed >= 50)
			/* On some systems, ospeed is the baud rate itself,
			   not a table index.  */
			sprintf (term + strlen (term), "%d", ospeed);
		else if (ospeed >= sizeof(speeds)/sizeof(char*))
			/* Past end of table, but not high enough to
			   look like a real speed.  */
			(void) strncat (term, speeds[sizeof(speeds)/sizeof(char*) - 1], sizeof(term) - 1 - strlen(term));
		else {
			(void) strncat(term, speeds[ospeed], sizeof(term) - 1 - strlen(term));
		}
                term[sizeof (term) - 1] = '\0';
	}
#else
    if (ioctl(0, TIOCGETP, &ttyb) == 0) {
	(void) strncat(term, "/", sizeof(term) - 1 - strlen(term));
	(void) strncat(term, speeds[ttyb.sg_ospeed], sizeof(term) - 1 - strlen(term));
    }
#endif
    (void) get_window_size(0, &winsize);
    
#ifdef POSIX_TERMIOS
    tcgetattr(0, &defmodes);
    tcgetattr(0, &ixon_state);
#else
#ifdef USE_TERMIO
    /**** moved before rcmd call so that if get a SIGPIPE in rcmd **/
    /**** we will have the defmodes set already. ***/
    (void)ioctl(fileno(stdin), TIOCGETP, &defmodes);
    (void)ioctl(fileno(stdin), TIOCGETP, &ixon_state);
#endif
#endif

    /* Catch SIGPIPE, as that means we lost the connection */
    /* will use SIGUSR1 for window size hack, so hold it off */
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = lostpeer;
    (void) sigaction(SIGPIPE, &sa, (struct sigaction *)0);
    
    (void) sigemptyset(&urgmask);
    (void) sigaddset(&urgmask, SIGUSR1);
    oldmask = &omask;
    (void) sigprocmask(SIG_BLOCK, &urgmask, oldmask);
#else
    (void) signal(SIGPIPE, lostpeer);
#ifdef sgi
    oldmask = sigignore( sigmask(SIGUSR1));
#else
    oldmask = sigblock( sigmask(SIGUSR1));
#endif
#endif /* POSIX_SIGNALS */

#ifdef KERBEROS
    authopts = AP_OPTS_MUTUAL_REQUIRED;

    /* Piggy-back forwarding flags on top of authopts; */
    /* they will be reset in kcmd */
    if (fflag || Fflag)
      authopts |= OPTS_FORWARD_CREDS;
    if (Fflag)
      authopts |= OPTS_FORWARDABLE_CREDS;

#ifdef KRB5_KRB4_COMPAT
    if (v4only)
	goto try_v4;
#endif
    status = kcmd(&sock, &host, port,
		  null_local_username ? "" : pwd->pw_name,
		  name ? name : pwd->pw_name, term,
		  0, "host", krb_realm,
		  &cred,
		  0,		/* No need for sequence number */
		  0,		/* No need for server seq # */
		  &local, &foreign,
		  &auth_context, authopts,
		  0,		/* Not any port # */
		  0,
		  &kcmd_proto);
    if (status) {
	if (kcmd_proto == KCMD_NEW_PROTOCOL && encrypt_flag)
	    /* Don't fall back to something less secure.  */
	    exit (1);
#ifdef KRB5_KRB4_COMPAT
	fprintf(stderr, "Trying krb4 rlogin...\n");
    try_v4:
	status = k4cmd(&sock, &host, port,
		       null_local_username ? "" : pwd->pw_name,
		       name ? name : pwd->pw_name, term,
		       0, &v4_ticket, "rcmd", krb_realm,
		       &v4_cred, v4_schedule, &v4_msg_data, &local, &foreign,
		       (encrypt_flag) ? KOPT_DO_MUTUAL : 0L, 0);
	if (status)
	    try_normal(orig_argv);
	rcmd_stream_init_krb4(v4_cred.session, encrypt_flag, 1, 1);
#else
	try_normal(orig_argv);
#endif
    } else {
	krb5_keyblock *key = 0;

	if (kcmd_proto == KCMD_NEW_PROTOCOL) {
	    do_inband = 1;

	    status = krb5_auth_con_getsendsubkey (bsd_context, auth_context,
						  &key);
	    if ((status || !key) && encrypt_flag)
		try_normal(orig_argv);
	}
	if (key == 0)
	    key = &cred->keyblock;

	rcmd_stream_init_krb5(key, encrypt_flag, 1, 1, kcmd_proto);
    }
	
    rem = sock;
    
#else
    rem = rcmd(&host, port,
	       null_local_username ? "" : pwd->pw_name,
	       name ? name : pwd->pw_name, term, 0);
#endif /* KERBEROS */

    if (rem < 0)
      exit(1);
    
    if (options & SO_DEBUG &&
	setsockopt(rem, SOL_SOCKET, SO_DEBUG, (char*)&on, sizeof (on)) < 0)
      perror("rlogin: setsockopt (SO_DEBUG)");
    uid = getuid();
    if (setuid(uid) < 0) {
	perror("rlogin: setuid");
	exit(1);
    }
    flowcontrol = flow;  /* Set up really correct non-volatile variable */
    doit(oldmask);
    /*NOTREACHED*/
  usage:
#ifdef KERBEROS
    fprintf (stderr,
	     "usage: rlogin host [-option] [-option...] [-k realm ] [-t ttytype] [-l username]\n");
#ifdef KRB5_KRB4_COMPAT
    fprintf (stderr, "     where option is e, 7, 8, noflow, n, a, x, f, F, c, 4, PO, or PN\n");
#else
    fprintf (stderr, "     where option is e, 7, 8, noflow, n, a, x, f, F, c, PO, or PN\n");
#endif
#else /* !KERBEROS */
    fprintf (stderr,
	     "usage: rlogin host [-option] [-option...] [-t ttytype] [-l username]\n");
    fprintf (stderr, "     where option is e, 7, 8, noflow, n, a, or c\n");
#endif /* KERBEROS */
    exit(1);
}



static int confirm_death ()
{
    char hostname[33];
    char input;
    int answer;
    if (!confirm) return (1);	/* no confirm, just die */
    
    if (gethostname (hostname, sizeof(hostname)-1) != 0)
      strlcpy (hostname, "???", sizeof(hostname));
    else
      hostname[sizeof(hostname)-1] = '\0';
    
    fprintf (stderr, "\r\nKill session on %s from %s (y/n)?  ",
	     host, hostname);
    fflush (stderr);
    if (read(0, &input, 1) != 1)
      answer = EOF;	/* read from stdin */
    else
      answer = (int) input;
    fprintf (stderr, "%c\r\n", answer);
    fflush (stderr);
    return (answer == 'y' || answer == 'Y' || answer == EOF ||
	    answer == 4);	/* control-D */
}



#define CRLF "\r\n"

int	child;
krb5_sigtype	catchild (int);
krb5_sigtype	writeroob (int);

int	defflags, tabflag;
int	deflflags;
char	deferase, defkill;

#ifdef USE_TERMIO
char defvtim, defvmin;
#if defined(hpux) || defined(__hpux)
#include <sys/bsdtty.h>
#include <sys/ptyio.h>
#endif
struct tchars {
    char    t_intrc;        /* interrupt */
    char    t_quitc;        /* quit */
    char    t_startc;       /* start output */
    char    t_stopc;        /* stop output */
    char    t_eofc;         /* end-of-file */
    char    t_brkc;         /* input delimiter (like nl) */
};
#endif


#ifndef POSIX_TERMIOS
#ifdef TIOCGLTC
/*
 * POSIX 1003.1-1988 does not define a 'suspend' character.
 * POSIX 1003.1-1990 does define an optional VSUSP but not a VDSUSP character.
 * Some termio implementations (A/UX, Ultrix 4.2) include both.
 *
 * However, since this is all derived from the BSD ioctl() and ltchars
 * concept, all these implementations generally also allow for the BSD-style
 * ioctl().  So we'll simplify the problem by only testing for the ioctl().
 */
struct	ltchars defltc;
struct	ltchars noltc =	{ -1, -1, -1, -1, -1, -1 };
#endif
struct	tchars deftc;
struct	tchars notc =	{ -1, -1, -1, -1, -1, -1 };
#endif

static void doit(oldmask)
#ifdef POSIX_SIGNALS
    sigset_t *oldmask;
#else
    int oldmask;
#endif
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif

#ifdef POSIX_TERMIOS
    (void) tcgetattr(0, &deftty);
#ifdef VLNEXT
    /* there's a POSIX way of doing this, but do we need it general? */
    deftty.c_cc[VLNEXT] = 0;
#endif
#else
#ifdef USE_TERMIO
    struct termio sb;
#else
    struct sgttyb sb;
#endif
    
    (void) ioctl(0, TIOCGETP, (char *)&sb);
    defflags = sb.sg_flags;
#ifdef USE_TERMIO
    tabflag = sb.c_oflag & TABDLY;
    defflags |= ECHO;
    deferase = sb.c_cc[VERASE];
    defkill = sb.c_cc[VKILL];
    sb.c_cc[VMIN] = 1;
    sb.c_cc[VTIME] = 1;
    defvtim = sb.c_cc[VTIME];
    defvmin = sb.c_cc[VMIN];
    deftc.t_quitc = CQUIT;
    deftc.t_startc = CSTART;
    deftc.t_stopc = CSTOP ;
    deftc.t_eofc = CEOF;
    deftc.t_brkc =  '\n';
#else
    tabflag = defflags & TBDELAY;
    defflags &= ECHO | CRMOD;
    deferase = sb.sg_erase;
    defkill = sb.sg_kill;
    (void) ioctl(0, TIOCLGET, (char *)&deflflags);
    (void) ioctl(0, TIOCGETC, (char *)&deftc);
#endif

    notc.t_startc = deftc.t_startc;
    notc.t_stopc = deftc.t_stopc;
    (void) ioctl(0, TIOCGLTC, (char *)&defltc);
#endif
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGINT, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGINT, SIG_IGN);
#endif

    setsignal(SIGHUP, exit_handler);
    setsignal(SIGQUIT, exit_handler);

    child = fork();
    if (child == -1) {
	perror("rlogin: fork");
	done(1);
    }
    if (child == 0) {
	mode(1);
	if (reader(oldmask) == 0) {
	    prf("Connection closed.");
	    exit(0);
	}
	sleep(1);
	prf("\007Connection closed.");
	exit(3);
    }
    
#ifdef POSIX_SIGNALS
    /* "sa" has already been initialized above. */

    sa.sa_handler = writeroob;
    (void) sigaction(SIGUSR1, &sa, (struct sigaction *)0);
    
    sigprocmask(SIG_SETMASK, oldmask, (sigset_t*)0);

    sa.sa_handler = catchild;
    (void) sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGUSR1, writeroob);
#ifndef sgi
    (void) sigsetmask(oldmask);
#endif
    (void) signal(SIGCHLD, catchild);
#endif /* POSIX_SIGNALS */
    writer();
    prf("Closed connection.");
    done(0);
}



/*
 * Trap a signal, unless it is being ignored.
 */
void
setsignal(sig, act)
     int sig;
     krb5_sigtype (*act)();
{
#ifdef POSIX_SIGNALS
    sigset_t omask, igmask;
    struct sigaction sa;
    
    sigemptyset(&igmask);
    sigaddset(&igmask, sig);
    sigprocmask(SIG_BLOCK, &igmask, &omask);
#else
#ifdef sgi
    int omask = sigignore(sigmask(sig));
#else
    int omask = sigblock(sigmask(sig));
#endif
#endif /* POSIX_SIGNALS */
    
#ifdef POSIX_SIGNALS
    (void) sigaction(sig, (struct sigaction *)0, &sa);
    if (sa.sa_handler != SIG_IGN) {
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = act;
	(void) sigaction(sig, &sa, (struct sigaction *)0);
    }
    sigprocmask(SIG_SETMASK, &omask, (sigset_t*)0);
#else    
    if (signal(sig, act) == SIG_IGN)
	(void) signal(sig, SIG_IGN);
#ifndef sgi
    (void) sigsetmask(omask);
#endif
#endif
}



static void
done(status)
     int status;
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif
#ifndef HAVE_WAITPID
    pid_t w;
#endif
    
    mode(0);
    if (child > 0) {
	/* make sure catchild does not snap it up */
#ifdef POSIX_SIGNALS
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	(void) sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
	(void) signal(SIGCHLD, SIG_DFL);
#endif
	
	if (kill(child, SIGKILL) >= 0) {
#ifdef HAVE_WAITPID
	    (void) waitpid(child, 0, 0);
#else
	    while ((w = wait(0)) > 0 && w != child)
		/*void*/;
#endif
	}
    }
    exit(status);
}






/*
 * This is called when the reader process gets the out-of-band (urgent)
 * request to turn on the window-changing protocol.
 */
krb5_sigtype
  writeroob(signo)
int signo;
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif
    
    if (dosigwinch == 0) {
	sendwindow();
#ifdef POSIX_SIGNALS
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sigwinch;
	(void) sigaction(SIGWINCH, &sa, (struct sigaction *)0);
#else
	(void) signal(SIGWINCH, sigwinch);
#endif
    }
    dosigwinch = 1;
}



krb5_sigtype
  catchild(signo)
int signo;
{
#ifdef WAIT_USES_INT
    int status;
#else
    union wait status;
#endif
    int pid;
    
  again:
#ifdef HAVE_WAITPID
    pid = waitpid(-1, &status, WNOHANG|WUNTRACED);
#else
    pid = wait3(&status, WNOHANG|WUNTRACED, (struct rusage *)0);
#endif
    if (pid == 0)
      return;
    /*
     * if the child (reader) dies, just quit
     */
#ifdef WAIT_USES_INT
    if (pid < 0 || (pid == child && !WIFSTOPPED(status)))
      done(status);
#else
    if ((pid < 0) || ((pid == child) && (!WIFSTOPPED(status))))
	done((int)(status.w_termsig | status.w_retcode));
#endif
    goto again;
}



/*
 * writer: write to remote: 0 -> line.
 * ~.	terminate
 * ~^Z	suspend rlogin process.
 * ~^Y  suspend rlogin process, but leave reader alone.
 */
static void writer()
{
    int n_read;
    char buf[1024];
    int got_esc; /* set to true by read_wrapper if an escape char
		    was encountered */
    char c;

#ifdef ultrix             
    fd_set waitread;
    register n;
    
    /* we need to wait until the reader() has set up the terminal, else
       the read() below may block and not unblock when the terminal
       state is reset.
       */
    for (;;) {
	FD_ZERO(&waitread);
	FD_SET(0, &waitread);
	n = select(1, &waitread, 0, 0, 0, 0);
	if (n < 0 && errno == EINTR)
	  continue;
	if (n > 0)
	  break;
	else
	  if (n < 0) {
	      perror("select");
	      break;
	  }
    }
#endif /* ultrix */

    /* This loop works as follows.  Call read_wrapper to get data until
       we would block or until we read a cmdchar at the beginning of a line.
       If got_esc is false, we just send everything we got back.  If got_esc 
       is true, we send everything except the cmdchar at the end and look at 
       the next char.  If its a "." we break out of the loop and terminate.
       If its ^Z or ^Y we call stop with the value of the char and continue.
       If its none of those, we send the cmdchar and then send the char we 
       just read, unless that char is also the cmdchar (in which case we are
       only supposed to send one of them).  When this loop ends, so does the
       program.
    */

    for (;;) {

      /* read until we would block or we get a cmdchar */
      n_read = read_wrapper(0,buf,sizeof(buf),&got_esc);
  
      /* if read returns an error or 0 bytes, just quit */
      if (n_read <= 0) {
	break;
      }
      
      if (!got_esc) {
	if (rcmd_stream_write(rem, buf, (unsigned) n_read, 0) == 0) {
	  prf("line gone");
	  break;
	}
	continue;
      }
      else {
	/* This next test is necessary to avoid sending 0 bytes of data
	   in the event that we got just a cmdchar */
	if (n_read > 1) {
	  if (rcmd_stream_write(rem, buf, (unsigned) (n_read-1), 0) == 0) {
	    prf("line gone");
	    break;
	  }
	}
	if (read_wrapper(0,&c,1,&got_esc) <= 0) {
	  break;
	}

#ifdef POSIX_TERMIOS
	if (c == '.' || c == deftty.c_cc[VEOF]) 
#else
	  if (c == '.' || c == deftc.t_eofc) 
#endif
	    {
	      if (confirm_death()) {
		echo(c);
		break; 
	      }
	    }

#ifdef POSIX_TERMIOS
	if ( (
	      (c == deftty.c_cc[VSUSP]) 
#ifdef VDSUSP
	      || (c == deftty.c_cc[VDSUSP]) 
#endif
	      )
	     && !no_local_escape) {
	  echo(c);
	  stop(c);
	  continue;
	}
#else /*POSIX_TERMIOS*/
#ifdef TIOCGLTC
	if ((c == defltc.t_suspc || c == defltc.t_dsuspc)
	    && !no_local_escape) {
	  echo(c);
	  stop(c);
	  continue;
	}
#endif /*TIOCGLTC*/
#endif

      
	if (c != cmdchar) {
	  rcmd_stream_write(rem, &cmdchar, 1, 0);
	}

	if (rcmd_stream_write(rem,&c,1,0) == 0) {
	  prf("line gone");
	  break;
	}
      }
    }
}

/* This function reads up to size bytes from file desciptor fd into buf.
   It will copy as much data as it can without blocking, but will never
   copy more than size bytes.  In addition, if it encounters a cmdchar
   at the beginning of a line, it will copy everything up to and including
   the cmdchar, but nothing after that.  In this instance *esc_char is set
   to true and any remaining data is buffered and copied on a subsequent 
   call.  Otherwise, *esc_char will be set to false and the minimum of size,
   1024, and the number of bytes that can be read without blocking will
   be copied.  In all cases, a non-negative return value indicates the number 
   of bytes actually copied and a return value of -1 indicates that there
   was a read error (other than EINTR) and errno is set appropriately. 
*/

static int read_wrapper(fd,buf,size,got_esc) 
     int fd;
     char *buf;
     int size;
     int *got_esc;
{
  static char tbuf[1024];
  static char *data_start = tbuf;
  static char *data_end = tbuf;
  static int bol = 1;
  unsigned int return_length = 0;
  char c;

  /* if we have no data buffered, get more */
  if (data_start == data_end) {
    int n_read;
    while ((n_read = read(fd, tbuf, sizeof(tbuf))) <= 0) {
      if (n_read < 0 && errno == EINTR)
	continue;
      return n_read;
    }
    data_start = tbuf;
    data_end = tbuf+n_read;
  }

  *got_esc = 0;

  /* We stop when we've fully checked the buffer or have checked size
     bytes.  We break out and set *got_esc if we encounter a cmdchar
     at the beginning of a line.
  */

  while (data_start+return_length < data_end && return_length < size) {
    
    c = *(data_start+return_length);
    return_length++;

    if (bol == 1 && c == cmdchar) {
      bol = 0;
      *got_esc = 1;
      break;
    }

#ifdef POSIX_TERMIOS
    bol = (c == deftty.c_cc[VKILL] ||
	   c == deftty.c_cc[VINTR] ||
	   c == '\r' || c == '\n');
	
#else /* !POSIX_TERMIOS */
    bol = c == defkill || c == deftc.t_eofc ||
      c == deftc.t_intrc || c == defltc.t_suspc ||
      c == '\r' || c == '\n';
#endif
  }
   
  memcpy(buf, data_start, return_length);
  data_start = data_start + return_length;
  return return_length;
}

static void echo(c)
     register char c;
{
    char buf[8];
    register char *p = buf;
    
    c &= 0177;
    *p++ = cmdchar;
    if (c < ' ') {
	*p++ = '^';
	*p++ = c + '@';
    } else if (c == 0177) {
	*p++ = '^';
	*p++ = '?';
    } else
      *p++ = c;
    *p++ = '\r';
    *p++ = '\n';
    (void) write(1, buf, (unsigned) (p - buf));
}



static void stop(cmdc)
     char cmdc;
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif
    
    mode(0);

#ifdef POSIX_SIGNALS
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGCHLD, SIG_IGN);
#endif
    
#ifdef POSIX_TERMIOS
    (void) kill(cmdc == deftty.c_cc[VSUSP] ? 0 : getpid(), SIGTSTP);
#else
#ifdef TIOCGLTC
    (void) kill(cmdc == defltc.t_suspc ? 0 : getpid(), SIGTSTP);
#endif
#endif
#ifdef POSIX_SIGNALS
    sa.sa_handler = catchild;
    (void) sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGCHLD, catchild);
#endif
    
    mode(1);
    sigwinch(SIGWINCH);		/* check for size changes */
}



krb5_sigtype
  sigwinch(signo)
int signo;
{
    struct winsize ws;
    
    if (dosigwinch && get_window_size(0, &ws) == 0 &&
	memcmp(&winsize, &ws, sizeof (ws))) {
	winsize = ws;
	sendwindow();
    }
}



/*
 * Send the window size to the server via the magic escape
 */
static void sendwindow()
{
    char obuf[4 + sizeof (struct winsize)];
    struct winsize *wp = (struct winsize *)(void *)(obuf+4);
    
    obuf[0] = 0377;
    obuf[1] = 0377;
    obuf[2] = 's';
    obuf[3] = 's';
    wp->ws_row = htons(winsize.ws_row);
    wp->ws_col = htons(winsize.ws_col);
    wp->ws_xpixel = htons(winsize.ws_xpixel);
    wp->ws_ypixel = htons(winsize.ws_ypixel);
    (void) rcmd_stream_write(rem, obuf, sizeof(obuf), 0);
}



/*
 * reader: read from remote: line -> 1
 */
#define	READING	1
#define	WRITING	2

char	rcvbuf[8 * 1024];
int	rcvcnt;
int	rcvstate;
int	ppid;

/* returns 1 if flush, 0 otherwise */

int server_message(mark)
     int mark;
{
#ifndef POSIX_TERMIOS
    int out = FWRITE;
#endif
#ifdef POSIX_TERMIOS
    struct termios tty;
#else
#ifdef USE_TERMIO
    struct termio sb;
#else
    struct sgttyb sb;
#endif
#endif

    if (mark & TIOCPKT_WINDOW) {
	/*
	 * Let server know about window size changes
	 */
	(void) kill(ppid, SIGUSR1);
    }
#ifdef POSIX_TERMIOS
    if (!eight && (mark & TIOCPKT_NOSTOP)) {
      (void) tcgetattr(0, &tty);
      tty.c_iflag &= ~IXON;
      (void) tcsetattr(0, TCSADRAIN, &tty);
    }
    if (!eight && (mark & TIOCPKT_DOSTOP)) {
      (void) tcgetattr(0, &tty);
      tty.c_iflag |= IXON;
      (void) tcsetattr(0, TCSADRAIN, &tty);
    }
#else
    if (!eight && (mark & TIOCPKT_NOSTOP)) {
	(void) ioctl(0, TIOCGETP, (char *)&sb);
#ifdef USE_TERMIO
	sb.c_iflag |= IXOFF;
	sb.sg_flags &= ~ICANON;
#else
	sb.sg_flags &= ~CBREAK;
	sb.sg_flags |= RAW;
	notc.t_stopc = -1;
	notc.t_startc = -1;
	(void) ioctl(0, TIOCSETC, (char *)&notc);
#endif
	(void) ioctl(0, TIOCSETN, (char *)&sb);
    }
    if (!eight && (mark & TIOCPKT_DOSTOP)) {
	(void) ioctl(0, TIOCGETP, (char *)&sb);
#ifdef USE_TERMIO
	sb.sg_flags  |= ICANON;
	sb.c_iflag |= IXON;
#else
	sb.sg_flags &= ~RAW;
	sb.sg_flags |= CBREAK;
	notc.t_stopc = deftc.t_stopc;
	notc.t_startc = deftc.t_startc;
	(void) ioctl(0, TIOCSETC, (char *)&notc);
#endif
	(void) ioctl(0, TIOCSETN, (char *)&sb);
    }
#endif
    if (mark & TIOCPKT_FLUSHWRITE) {
#ifdef POSIX_TERMIOS
        (void) tcflush(1, TCOFLUSH);
#else
#ifdef  TIOCFLUSH
	(void) ioctl(1, TIOCFLUSH, (char *)&out);
#else
	(void) ioctl(1, TCFLSH, 1);
#endif
#endif
	return(1);
    }

    return(0);
}

void oob()
{
    char mark;
    static char waste[RLOGIN_BUFSIZ];
    int atmark, n;

    mark = 0;
    
    recv(rem, &mark, 1, MSG_OOB);

    if (server_message(mark)) {
	for (;;) {
	    if (ioctl(rem, SIOCATMARK, &atmark) < 0) {
		perror("ioctl");
		return;
	    }
	    if (atmark)
		break;
	    n = read(rem, waste, sizeof (waste));
	    if (n <= 0)
		break;
	}
    }
}

/* two control messages are defined:

   a double flag byte of 'o' indicates a one-byte message which is
   identical to what was once carried out of band.  

   a double flag byte of 'q' indicates a zero-byte message.  This
   message is interpreted as two \377 data bytes.  This is just a
   quote rule so that binary data from the server does not confuse the
   client.  */

static int control(cp, n)
     char *cp;
     unsigned int n;
{
    if ((n >= 5) && (cp[2] == 'o') && (cp[3] == 'o')) {
	if (server_message(cp[4]))
	    return(-5);
	return(5);
    } else if ((n >= 4) && (cp[2] == 'q') && (cp[3] == 'q')) {
	/* this is somewhat of a hack */
	cp[2] = '\377';
	cp[3] = '\377';
	return(2);
    }

    return(0);
}

/*
 * reader: read from remote: line -> 1 
 */
static int 
reader(oldmask)
#ifdef POSIX_SIGNALS
    sigset_t *oldmask;
#else
     int oldmask;
#endif
{
    fd_set readset, excset, writeset;
    int n, remaining;
    unsigned int left;
    char *bufp = rcvbuf;
    char *cp;

#ifdef POSIX_SIGNALS
    struct sigaction sa;

    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGTTOU, &sa, (struct sigaction *)0);

#else    
    (void) signal(SIGTTOU, SIG_IGN);
#endif
    
    ppid = getppid();
    FD_ZERO(&readset);
    FD_ZERO(&excset);
    FD_ZERO(&writeset);
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, oldmask, (sigset_t*)0);
#else
#ifndef sgi
    (void) sigsetmask(oldmask);
#endif
#endif /* POSIX_SIGNALS */

    for (;;) {
	if ((remaining = rcvcnt - (bufp - rcvbuf)) > 0) {
	    FD_SET(1,&writeset);
	    rcvstate = WRITING;
	    FD_CLR(rem, &readset);
	} else {
	    bufp = rcvbuf;
	    rcvcnt = 0;
	    rcvstate = READING;
	    FD_SET(rem,&readset);
	    FD_CLR(1,&writeset);
	}
	if (!do_inband)
	    FD_SET(rem,&excset);
	if (select(rem+1, &readset, &writeset, &excset, 0) > 0 ) {
	    if (!do_inband)
		if (FD_ISSET(rem, &excset))
		    oob();
	    if (FD_ISSET(1,&writeset)) {
		n = write(1, bufp, remaining);
		if (n < 0) {
		    if (errno != EINTR)
			return (-1);
		    continue;
		}
		bufp += n;
	    }
	    if (FD_ISSET(rem, &readset)) {
	  	rcvcnt = rcmd_stream_read(rem, rcvbuf, sizeof (rcvbuf), 0);
		if (rcvcnt == 0)
		    return (0);
		if (rcvcnt < 0)
		    goto error;

		if (do_inband) {
		    for (cp = rcvbuf; cp < rcvbuf+rcvcnt-1; cp++) {
			if (cp[0] == '\377' &&
			    cp[1] == '\377') {
			    left = (rcvbuf+rcvcnt) - cp;
			    n = control(cp, left);
			    /* |n| <= left */
			    if (n < 0) {
				left -= (-n);
				rcvcnt = 0;
				/* flush before, and (-n) bytes */
				if (left > 0)
				    memmove(rcvbuf, cp+(-n), left);
				cp = rcvbuf-1;
			    } else if (n) {
				left -= n;
				rcvcnt -= n;
				if (left > 0)
				    memmove(cp, cp+n, left);
				cp--;
			    }
			}
		    }
		}
	    }
	} else
error:
	{
	    if (errno == EINTR)
	      continue;
	    perror("read");
	    return (-1);
	}
    }
}



static void mode(f)
int f;
{
#ifdef POSIX_TERMIOS
    struct termios newtty;
#ifndef IEXTEN
#define IEXTEN 0 /* No effect*/
#endif
#ifndef _POSIX_VDISABLE
#define _POSIX_VDISABLE 0 /*A good guess at the disable-this-character character*/
#endif

    switch(f) {
    case 0:
	(void) tcsetattr(0, TCSADRAIN, &deftty);
	break;
    case 1:
	(void) tcgetattr(0, &newtty);
	/* was __svr4__ */
#ifdef VLNEXT
	/* there's a POSIX way of doing this, but do we need it general? */
	newtty.c_cc[VLNEXT] = _POSIX_VDISABLE;
#endif
		
	newtty.c_lflag &= ~(ICANON|ISIG|ECHO|IEXTEN);
	newtty.c_iflag &= ~(ISTRIP|INLCR|ICRNL);

	if (!flow) {
	    newtty.c_iflag &= ~(BRKINT|IXON|IXANY);
	    newtty.c_oflag &= ~(OPOST);
	} else {
	    /* XXX - should we set ixon ? */
	    newtty.c_iflag &= ~(IXON|IXANY);
	    newtty.c_iflag |=  (BRKINT);
	    newtty.c_oflag &= ~(ONLCR|ONOCR);
	    newtty.c_oflag |=  (OPOST);
	}
#ifdef TABDLY
	/* preserve tab delays, but turn off XTABS */
	if ((newtty.c_oflag & TABDLY) == TAB3)
	    newtty.c_oflag &= ~TABDLY;
#endif
	if (!eight)
	    newtty.c_iflag |= ISTRIP;
	if (litout)
	    newtty.c_oflag &= ~OPOST;

	newtty.c_cc[VMIN] = 1;
	newtty.c_cc[VTIME] = 0;
	(void) tcsetattr(0, TCSADRAIN, &newtty);
	break;
    default:
	return;
	/* NOTREACHED */
    }
#else
    struct ltchars *ltc;
#ifdef USE_TERMIO
    struct termio sb;
#else
    struct tchars *tc;
    struct sgttyb sb;
    int	lflags;
    (void) ioctl(0, TIOCLGET, (char *)&lflags);
#endif
    
    (void) ioctl(0, TIOCGETP, (char *)&sb);
    switch (f) {
	
    case 0:
#ifdef USE_TERMIO
	/*
	**      remember whether IXON was set, so it can be restored
	**      when mode(1) is next done
	*/
	(void) ioctl(fileno(stdin), TIOCGETP, &ixon_state);
	/*
	**      copy the initial modes we saved into sb; this is
	**      for restoring to the initial state
	*/
	(void)memcpy(&sb, &defmodes, sizeof(defmodes));
	
#else
	sb.sg_flags &= ~(CBREAK|RAW|TBDELAY);
	sb.sg_flags |= defflags|tabflag;
	sb.sg_kill = defkill;
	sb.sg_erase = deferase;
	lflags = deflflags;
	tc = &deftc;
#endif
	ltc = &defltc;
	break;
	
    case 1:
#ifdef USE_TERMIO
	/*
	**      turn off output mappings
	*/
	sb.c_oflag &= ~(ONLCR|OCRNL);
	/*
	**      turn off canonical processing and character echo;
	**      also turn off signal checking -- ICANON might be
	**      enough to do this, but we're being careful
	*/
	sb.c_lflag &= ~(ECHO|ICANON|ISIG);
	sb.c_cc[VTIME] = 1;
	sb.c_cc[VMIN] = 1;
	if (eight)
	    sb.c_iflag &= ~(ISTRIP);
#ifdef TABDLY
	/* preserve tab delays, but turn off tab-to-space expansion */
	if ((sb.c_oflag & TABDLY) == TAB3)
	    sb.c_oflag &= ~TAB3;
#endif
	/*
	**  restore current flow control state
	*/
	if ((ixon_state.c_iflag & IXON) && flow ) {
	    sb.c_iflag |= IXON;
	} else {
	    sb.c_iflag &= ~IXON;
	}
#else /* ! USE_TERMIO */
	sb.sg_flags &= ~(CBREAK|RAW);
	sb.sg_flags |= (!flow ? RAW : CBREAK);
	/* preserve tab delays, but turn off XTABS */
	if ((sb.sg_flags & TBDELAY) == XTABS)
	    sb.sg_flags &= ~TBDELAY;
	sb.sg_kill = sb.sg_erase = -1;
#ifdef LLITOUT
	if (litout)
	    lflags |= LLITOUT;
#endif
#ifdef LPASS8
	if (eight)
	    lflags |= LPASS8;
#endif /* LPASS8 */
	tc = &notc;
	sb.sg_flags &= ~defflags;
#endif /* USE_TERMIO */
	
	ltc = &noltc;
	break;
	
    default:
	return;
    }
    (void) ioctl(0, TIOCSLTC, (char *)ltc);
#ifndef USE_TERMIO
    (void) ioctl(0, TIOCSETC, (char *)tc);
    (void) ioctl(0, TIOCLSET, (char *)&lflags);
#endif
    (void) ioctl(0, TIOCSETN, (char *)&sb);
#endif /* !POSIX_TERMIOS */
}



static void
prf(f)
     char *f;
{
    fprintf(stderr, "%s", f);
    fprintf(stderr, CRLF);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    register char *nhost;
#ifdef POSIX_SIGNALS
    sigset_t mask;
#endif
    
#ifndef KRB5_ATHENA_COMPAT
    if (encrypt_flag)
      exit(1);
#endif
    fprintf(stderr,"trying normal rlogin (%s)\n",
	    UCB_RLOGIN);
    fflush(stderr);
    
    nhost = strrchr(argv[0], '/');
    if (nhost)
      nhost++;
    else
      nhost = argv[0];
    if (!strcmp(nhost, "rlogin") || !strcmp(nhost, "rsh"))
      argv[0] = UCB_RLOGIN;
    
#ifdef POSIX_SIGNALS
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);
#endif

    execv(UCB_RLOGIN, argv);
    perror("exec");
    exit(1);
}
#endif



krb5_sigtype lostpeer(signo)
    int signo;
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;

    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGPIPE, SIG_IGN);
#endif
    
    prf("\007Connection closed.");
    done(1);
}
