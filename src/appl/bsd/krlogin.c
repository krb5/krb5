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
     
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

/* how do we tell apart irix 5 and irix 4? */
#if defined(__sgi) && defined(__mips)
/* IRIX 5: TIOCGLTC doesn't actually work */
#undef TIOCGLTC
#endif

#ifndef TIOCPKT_NOSTOP
/* These values are over-the-wire protocol, *not* local values */
#define TIOCPKT_NOSTOP          0x10
#define TIOCPKT_DOSTOP          0x20
#define TIOCPKT_FLUSHWRITE      0x02
#endif

#ifdef __386BSD__
#include <sys/ioctl_compat.h>
#endif

#ifdef CRAY
#include <sys/ttold.h>
#endif


#ifndef roundup
#define roundup(x,y) ((((x)+(y)-1)/(y))*(y))
#endif

#ifdef KERBEROS
#include "krb5.h"
#include "com_err.h"
#include "defines.h"
     
#define RLOGIN_BUFSIZ 4096
     
char des_inbuf[2*RLOGIN_BUFSIZ];       /* needs to be > largest read size */
char des_outbuf[2*RLOGIN_BUFSIZ];      /* needs to be > largest write size */
krb5_data desinbuf,desoutbuf;
krb5_encrypt_block eblock;      /* eblock for encrypt/decrypt */

void try_normal();
char *krb_realm = (char *)0;
int encrypt_flag = 0;
int fflag = 0, Fflag = 0;
krb5_creds *cred;
struct sockaddr_in local, foreign;
krb5_context bsd_context;

#ifndef UCB_RLOGIN
#define UCB_RLOGIN      "/usr/ucb/rlogin"
#endif

#include "rpaths.h"
#else /* !KERBEROS */
#define des_read read
#define des_write write
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
#ifdef hpux
char	*speeds[] =
{ "0", "50", "75", "110", "134", "150", "200", "300", "600",
    "900", "1200", "1800", "2400", "3600", "4800", "7200", "9600",
    "19200", "38400", "EXTA", "EXTB" };
#else
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

krb5_sigtype	sigwinch KRB5_PROTOTYPE((int)), oob KRB5_PROTOTYPE((int));
krb5_sigtype	lostpeer KRB5_PROTOTYPE((int));
#if __STDC__
int setsignal(int sig, krb5_sigtype (*act)());
#endif

/* to allow exits from signal handlers, without conflicting declarations */
krb5_sigtype exit_handler() {
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
    int debug_port = 0;
#endif
   
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
	debug_port = atoi(*argv);
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
	if(!(krb_realm = (char *)malloc(strlen(*argv) + 1))){
	    fprintf(stderr, "rlogin: Cannot malloc.\n");
	    exit(1);
	}
	strcpy(krb_realm, *argv);
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
#endif /* KERBEROS */
    if (host == 0)
      goto usage;
    if (argc > 0)
      goto usage;
    pwd = getpwuid(getuid());
    if (pwd == 0) {
	fprintf(stderr, "Who are you?\n");
	exit(1);
    }
#ifdef KERBEROS
    krb5_init_context(&bsd_context);
    krb5_init_ets(bsd_context);
    desinbuf.data = des_inbuf;
    desoutbuf.data = des_outbuf;	/* Set up des buffers */
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
	fprintf(stderr, "rlogin: %s/tcp: unknown service\n",
		encrypt_flag ? "eklogin" : "klogin");
	
	try_normal(orig_argv);
    }
#else
    sp = getservbyname("login", "tcp");
    if (sp == 0) {
	fprintf(stderr, "rlogin: login/tcp: unknown service\n");
	exit(2);
    }
#endif /* KERBEROS */
    if (cp == (char *) NULL) cp = getenv("TERM");
    if (cp)
      (void) strcpy(term, cp);
#ifdef POSIX_TERMIOS
	if (tcgetattr(0, &ttyb) == 0) {
		int ospeed = cfgetospeed (&ttyb);

		(void) strcat(term, "/");
		if (ospeed >= 50)
			/* On some systems, ospeed is the baud rate itself,
			   not a table index.  */
			sprintf (term + strlen (term), "%d", ospeed);
		else {
			(void) strcat(term, speeds[ospeed]);
#if 0
			/* XXX - Not used, since the above code was
			 * not ifdef'd and it relied on cfget... */

			/* some "posix" systems don't have cfget...
			 * so used CBAUD if it's there */
			(void) strcat(term, speeds[ttyb.c_cflag & CBAUD]);
#endif
		}
	}
#else
    if (ioctl(0, TIOCGETP, &ttyb) == 0) {
	(void) strcat(term, "/");
	(void) strcat(term, speeds[ttyb.sg_ospeed]);
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
    (void) sigaddset(&urgmask, SIGURG);
    (void) sigaddset(&urgmask, SIGUSR1);
    oldmask = &omask;
    (void) sigprocmask(SIG_BLOCK, &urgmask, oldmask);
#else
    (void) signal(SIGPIPE, lostpeer);
#ifdef sgi
    oldmask = sigignore(sigmask(SIGURG) | sigmask(SIGUSR1));
#else
    oldmask = sigblock(sigmask(SIGURG) | sigmask(SIGUSR1));
#endif
#endif /* POSIX_SIGNALS */
    
    if (debug_port)
      sp->s_port = htons(debug_port);

#ifdef KERBEROS
    authopts = AP_OPTS_MUTUAL_REQUIRED;

    /* Piggy-back forwarding flags on top of authopts; */
    /* they will be reset in kcmd */
    if (fflag || Fflag)
      authopts |= OPTS_FORWARD_CREDS;
    if (Fflag)
      authopts |= OPTS_FORWARDABLE_CREDS;

    status = kcmd(&sock, &host, sp->s_port,
		  null_local_username ? NULL : pwd->pw_name,
		  name ? name : pwd->pw_name, term,
		  0, "host", krb_realm,
		  &cred,
		  0,		/* No need for sequence number */
		  0,		/* No need for server seq # */
		  &local, &foreign,
		  authopts,
		  0);		/* Not any port # */
    if (status) {
	/* should check for KDC_PR_UNKNOWN, NO_TKT_FILE here -- XXX */
	fprintf(stderr,
		"%s: kcmd to host %s failed - %s\n",orig_argv[0], host,
		error_message(status));
	try_normal(orig_argv);
    }
    rem = sock;
    
    /* setup eblock for des_read and write */
    krb5_use_keytype(bsd_context, &eblock,cred->keyblock.keytype);
    if ( status = krb5_process_key(bsd_context, &eblock,&cred->keyblock)) {
	fprintf(stderr,
		"%s: Cannot process session key : %s.\n",
		orig_argv[0], error_message(status));
	exit(1);
    }
#else
    rem = rcmd(&host, sp->s_port,
	       null_local_username ? NULL : pwd->pw_name,
	       name ? name : pwd->pw_name, term, 0);
#endif /* KERBEROS */
    
    if (rem < 0)
      exit(1);
    
    /* we need to do the SETOWN here so that we get the SIGURG
       registered if the URG data come in early, before the reader() gets
       to do this for real (otherwise, the signal is never generated
       by the kernel).  We block it above, so when it gets unblocked
       it will get processed by the reader().
       There is a possibility that the signal will get delivered to both
       writer and reader, but that is harmless, since the writer reflects
       it to the reader, and the oob() processing code in the reader will
       work properly even if it is called when no oob() data is present.
       */
#ifdef hpux
	/* hpux invention */
	{
	  int pid = getpid();
	  ioctl(rem, FIOSSAIOSTAT, &pid); /* trick: pid is non-zero */
	  ioctl(rem, FIOSSAIOOWN, &pid);
	}
#else
#ifdef HAVE_SETOWN
    (void) fcntl(rem, F_SETOWN, getpid());
#endif
#endif
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
    fprintf (stderr, "     where option is e, 7, 8, noflow, n, a, x, f, F, or c\n");
#else /* !KERBEROS */
    fprintf (stderr,
	     "usage: rlogin host [-option] [-option...] [-t ttytype] [-l username]\n");
    fprintf (stderr, "     where option is e, 7, 8, noflow, n, a, or c\n");
#endif /* KERBEROS */
    exit(1);
}



int confirm_death ()
{
    char hostname[33];
    char input;
    int answer;
    if (!confirm) return (1);	/* no confirm, just die */
    
    if (gethostname (hostname, sizeof(hostname)-1) != 0)
      strcpy (hostname, "???");
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
krb5_sigtype	catchild KRB5_PROTOTYPE((int));
krb5_sigtype	copytochild KRB5_PROTOTYPE((int)),
		writeroob KRB5_PROTOTYPE((int));

int	defflags, tabflag;
int	deflflags;
char	deferase, defkill;

#ifdef USE_TERMIO
char defvtim, defvmin;
#ifdef hpux
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

#ifndef POSIX_TERMIOS
struct	tchars deftc;
struct	tchars notc =	{ -1, -1, -1, -1, -1, -1 };
#ifndef TIOCGLTC
struct	ltchars defltc;
struct	ltchars noltc =	{ -1, -1, -1, -1, -1, -1 };
#endif
#endif

doit(oldmask)
#ifdef POSIX_SIGNALS
    sigset_t *oldmask;
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
#ifdef TIOCGLTC
    (void) ioctl(0, TIOCGLTC, (char *)&defltc);
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
    
    /*
     * We may still own the socket, and may have a pending SIGURG
     * (or might receive one soon) that we really want to send to
     * the reader.  Set a trap that simply copies such signals to
     * the child.
     */
#ifdef POSIX_SIGNALS
    /* "sa" has already been initialized above. */
    sa.sa_handler = copytochild;
    (void) sigaction(SIGURG, &sa, (struct sigaction *)0);

    sa.sa_handler = writeroob;
    (void) sigaction(SIGUSR1, &sa, (struct sigaction *)0);
    
    sigprocmask(SIG_SETMASK, oldmask, (sigset_t*)0);

    sa.sa_handler = catchild;
    (void) sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGURG, copytochild);
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
 * Copy SIGURGs to the child process.
 */
krb5_sigtype
  copytochild(signo)
int signo;
{
    (void) kill(child, SIGURG);
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
#if defined(hpux)
    /* I think this one is wrong: XXX -- [eichin:19940727.1853EST] */
    if ((pid < 0) || ((pid == child) && (!WIFSTOPPED(status.w_stopval))))
#else
    if ((pid < 0) || ((pid == child) && (!WIFSTOPPED(status))))
#endif
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
writer()
{
    char c;
    register n;
    register bol = 1;               /* beginning of line */
    register local = 0;
    
#ifdef ultrix             
    fd_set waitread;
    
    /* we need to wait until the reader() has set up the terminal, else
       the read() below may block and not unblock when the terminal
       state is reset.
       */
    for (;;) {
	FD_ZERO(&waitread);
	FD_SET(0, &waitread);
	n = select(8*sizeof(waitread), &waitread, 0, 0, 0, 0);
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
    for (;;) {
	n = read(0, &c, 1);
	if (n <= 0) {
	    if (n < 0 && errno == EINTR)
	      continue;
	    break;
	}
	/*
	 * If we're at the beginning of the line
	 * and recognize a command character, then
	 * we echo locally.  Otherwise, characters
	 * are echo'd remotely.  If the command
	 * character is doubled, this acts as a 
	 * force and local echo is suppressed.
	 */
	if (bol) {
	    bol = 0;
	    if (c == cmdchar) {
		bol = 0;
		local = 1;
		continue;
	    }
	} else if (local) {
	    local = 0;
#ifdef POSIX_TERMIOS
	    if (c == '.' || c == deftty.c_cc[VEOF]) {
#else
	    if (c == '.' || c == deftc.t_eofc) {
#endif
		if (confirm_death()) {
		    echo(c);
		    break;
		}
	    }
#ifdef TIOCGLTC
	    if ((c == defltc.t_suspc || c == defltc.t_dsuspc)
		&& !no_local_escape) {
		bol = 1;
		echo(c);
		stop(c);
		continue;
	    }
#else
#ifdef POSIX_TERMIOS
	    if ( (
		  (c == deftty.c_cc[VSUSP]) 
#ifdef VDSUSP
		  || (c == deftty.c_cc[VDSUSP]) 
#endif
		  )
		&& !no_local_escape) {
	      bol = 1;
	      echo(c);
	      stop(c);
	      continue;
	    }
#endif
#endif

	    if (c != cmdchar)
	      (void) des_write(rem, &cmdchar, 1);
	}
	if (des_write(rem, &c, 1) == 0) {
	    prf("line gone");
	    break;
	}
#ifdef POSIX_TERMIOS
	bol = (c == deftty.c_cc[VKILL] ||
	       c == deftty.c_cc[VINTR] ||
	       c == '\r' || c == '\n');
#ifdef TIOCGLTC
	if (!bol)
	  bol = (c == defltc.t_suspc);
#endif
#else /* !POSIX_TERMIOS */
	bol = c == defkill || c == deftc.t_eofc ||
	  c == deftc.t_intrc || c == defltc.t_suspc ||
	    c == '\r' || c == '\n';
#endif
    }
}



echo(c)
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
    (void) write(1, buf, p - buf);
}



stop(cmdc)
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
    
#ifdef TIOCGLTC
    (void) kill(cmdc == defltc.t_suspc ? 0 : getpid(), SIGTSTP);
#else
#ifdef POSIX_TERMIOS
    (void) kill(cmdc == deftty.c_cc[VSUSP] ? 0 : getpid(), SIGTSTP);
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
sendwindow()
{
    char obuf[4 + sizeof (struct winsize)];
    struct winsize *wp = (struct winsize *)(obuf+4);
    
    obuf[0] = 0377;
    obuf[1] = 0377;
    obuf[2] = 's';
    obuf[3] = 's';
    wp->ws_row = htons(winsize.ws_row);
    wp->ws_col = htons(winsize.ws_col);
    wp->ws_xpixel = htons(winsize.ws_xpixel);
    wp->ws_ypixel = htons(winsize.ws_ypixel);
    (void) des_write(rem, obuf, sizeof(obuf));
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

#ifdef POSIX_SETJMP
sigjmp_buf rcvtop;
#else
jmp_buf rcvtop;
#endif

krb5_sigtype
  oob(signo)
int signo;
{
#ifndef POSIX_TERMIOS
    int out = FWRITE;
#endif
    int atmark, n;
    int rcvd = 0;
    char waste[RLOGIN_BUFSIZ], mark;
#ifdef POSIX_TERMIOS
    struct termios tty;
#else
#ifdef USE_TERMIO
    struct termio sb;
#else
    struct sgttyb sb;
#endif
#endif
    
    while (recv(rem, &mark, 1, MSG_OOB) < 0)
      switch (errno) {
	  
	case EWOULDBLOCK:
	  /*
	   * Urgent data not here yet.
	   * It may not be possible to send it yet
	   * if we are blocked for output
	   * and our input buffer is full.
	   */
	  if (rcvcnt < sizeof(rcvbuf)) {
	      n = read(rem, rcvbuf + rcvcnt,
		       sizeof(rcvbuf) - rcvcnt);
	      if (n <= 0)
		return;
	      rcvd += n;
	  } else {
	      n = read(rem, waste, sizeof(waste));
	      if (n <= 0)
		return;
	  }
	  continue;
	  
	default:
	  return;
      }
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
	for (;;) {
	    if (ioctl(rem, SIOCATMARK, &atmark) < 0) {
		perror("ioctl");
		break;
	    }
	    if (atmark)
	      break;
	    n = read(rem, waste, sizeof (waste));
	    if (n <= 0)
	      break;
	}
	/*
	 * Don't want any pending data to be output,
	 * so clear the recv buffer.
	 * If we were hanging on a write when interrupted,
	 * don't want it to restart.  If we were reading,
	 * restart anyway.
	 */
	rcvcnt = 0;
#ifdef POSIX_SETJMP
	siglongjmp(rcvtop, 1);
#else
	longjmp(rcvtop, 1);
#endif
    }
    
    /*
     * oob does not do FLUSHREAD (alas!)
     */
    
    /*
     * If we filled the receive buffer while a read was pending,
     * longjmp to the top to restart appropriately.  Don't abort
     * a pending write, however, or we won't know how much was written.
     */
#ifdef POSIX_SETJMP
    if (rcvd && rcvstate == READING)
	siglongjmp(rcvtop, 1);
#else
    if (rcvd && rcvstate == READING)
	longjmp(rcvtop, 1);
#endif
}



/*
 * reader: read from remote: line -> 1
 */
reader(oldmask)
#ifdef POSIX_SIGNALS
     sigset_t *oldmask;
#else
     int oldmask;
#endif
{
#if (defined(BSD) && BSD+0 >= 43) || defined(ultrix)
    int pid = getpid();
#else
    int pid = -getpid();
#endif
    int n, remaining;
    char *bufp = rcvbuf;

#ifdef POSIX_SIGNALS
    struct sigaction sa;

    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGTTOU, &sa, (struct sigaction *)0);

#ifdef SA_RESTART
    /* Because SIGURG will be coming in during a read,
     * we want to restart the syscall afterwards. */
    sa.sa_flags |= SA_RESTART;
#endif
    sa.sa_handler = oob;
    (void) sigaction(SIGURG, &sa, (struct sigaction *)0);
#else    
    (void) signal(SIGTTOU, SIG_IGN);
    (void) signal(SIGURG, oob);
#endif
    
    ppid = getppid();
#ifdef HAVE_SETOWN
    (void) fcntl(rem, F_SETOWN, pid);
#endif
#ifdef POSIX_SETJMP
    (void) sigsetjmp(rcvtop, 1);
#else
    (void) setjmp(rcvtop);
#endif
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, oldmask, (sigset_t*)0);
#else
#ifndef sgi
    (void) sigsetmask(oldmask);
#endif
#endif /* POSIX_SIGNALS */
    for (;;) {
	while ((remaining = rcvcnt - (bufp - rcvbuf)) > 0) {
	    rcvstate = WRITING;
	    n = write(1, bufp, remaining);
	    if (n < 0) {
		if (errno != EINTR)
		  return (-1);
		continue;
	    }
	    bufp += n;
	}
	bufp = rcvbuf;
	rcvcnt = 0;
	rcvstate = READING;
	rcvcnt = des_read(rem, rcvbuf, sizeof (rcvbuf));
	if (rcvcnt == 0)
	  return (0);
	if (rcvcnt < 0) {
	    if (errno == EINTR)
	      continue;
	    perror("read");
	    return (-1);
	}
    }
}



mode(f)
{
#ifdef POSIX_TERMIOS
	struct termios newtty;

	switch(f) {
	case 0:
#ifdef TIOCGLTC
#ifndef solaris20
		(void) ioctl(0, TIOCSLTC, (char *)&defltc);
#endif
#endif
		(void) tcsetattr(0, TCSADRAIN, &deftty);
		break;
	case 1:
		(void) tcgetattr(0, &newtty);
/* was __svr4__ */
#ifdef VLNEXT
	/* there's a POSIX way of doing this, but do we need it general? */
		newtty.c_cc[VLNEXT] = 0;
#endif
		
		newtty.c_lflag &= ~(ICANON|ISIG|ECHO);
		if (!flow)
		{
			newtty.c_lflag &= ~(ICANON|ISIG|ECHO);
			newtty.c_iflag &= ~(BRKINT|INLCR|ICRNL|ISTRIP);
			/* newtty.c_iflag |=  (IXON|IXANY); */
			newtty.c_iflag &= ~(IXON|IXANY);
			newtty.c_oflag &= ~(OPOST);
		} else {
			newtty.c_lflag &= ~(ICANON|ISIG|ECHO);
			newtty.c_iflag &= ~(INLCR|ICRNL);
			/* newtty.c_iflag |=  (BRKINT|ISTRIP|IXON|IXANY); */
			newtty.c_iflag &= ~(IXON|IXANY);
			newtty.c_iflag |=  (BRKINT|ISTRIP);
			newtty.c_oflag &= ~(ONLCR|ONOCR);
			newtty.c_oflag |=  (OPOST);
		}
#ifdef TABDLY
		/* preserve tab delays, but turn off XTABS */
		if ((newtty.c_oflag & TABDLY) == TAB3)
			newtty.c_oflag &= ~TABDLY;
#endif

		if (litout)
			newtty.c_oflag &= ~OPOST;

		newtty.c_cc[VMIN] = 1;
		newtty.c_cc[VTIME] = 0;
		(void) tcsetattr(0, TCSADRAIN, &newtty);
#ifdef TIOCGLTC
		/* Do this after the tcsetattr() in case this version
		 * of termio supports the VSUSP or VDSUSP characters */
#ifndef solaris20
		/* this forces ICRNL under Solaris... */
		(void) ioctl(0, TIOCSLTC, (char *)&noltc);
#endif
#endif
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



/*VARARGS*/
prf(f, a1, a2, a3, a4, a5)
     char *f;
     char *a1, *a2, *a3, *a4, *a5;
{
    fprintf(stderr, f, a1, a2, a3, a4, a5);
    fprintf(stderr, CRLF);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    register char *host;
    
    if (encrypt_flag)
      exit(1);
    fprintf(stderr,"trying normal rlogin (%s)\n",
	    UCB_RLOGIN);
    fflush(stderr);
    
    host = strrchr(argv[0], '/');
    if (host)
      host++;
    else
      host = argv[0];
    if (!strcmp(host, "rlogin"))
      argv++;
    
    execv(UCB_RLOGIN, argv);
    perror("exec");
    exit(1);
}



char storage[2*RLOGIN_BUFSIZ];		/* storage for the decryption */
int nstored = 0;
char *store_ptr = storage;

#ifndef OLD_VERSION

int des_read(fd, buf, len)
     int fd;
     register char *buf;
     int len;
{
    int nreturned = 0;
    long net_len,rd_len;
    int cc;
    unsigned char len_buf[4];
    
    if (!encrypt_flag)
      return(read(fd, buf, len));
    
    if (nstored >= len) {
	memcpy(buf, store_ptr, len);
	store_ptr += len;
	nstored -= len;
	return(len);
    } else if (nstored) {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	buf += nstored;
	len -= nstored;
	nstored = 0;
    }
    
#if 0
    if ((cc = krb5_net_read(bsd_context, fd, (char *)&len_buf, 4)) != 4) {
	/* XXX can't read enough, pipe must have closed */
	return(0);
    }
    rd_len =
	((len_buf[0]<<24) | (len_buf[1]<<16) | (len_buf[2]<<8) | len_buf[3]);
#else
	{
	    unsigned char c;
	    int gotzero = 0;

	    /* See the comment in v4_des_read. */
	    do {
		cc = krb5_net_read(bsd_context, fd, &c, 1);
		/* we should check for non-blocking here, but we'd have
		   to make it save partial reads as well. */
		if (cc < 0) return 0; /* read error */
		if (cc == 1) {
		    if (c == 0) gotzero = 1;
		}
	    } while (!gotzero);

	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    rd_len = c;
	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    rd_len = (rd_len << 8) | c;
	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    rd_len = (rd_len << 8) | c;
	}

#endif
    net_len = krb5_encrypt_size(rd_len,eblock.crypto_entry);
    if ((net_len <= 0) || (net_len > sizeof(des_inbuf))) {
	/* preposterous length; assume out-of-sync; only
	   recourse is to close connection, so return 0 */
	fprintf(stderr,"Read size problem.\n");
	return(0);
    }
    if ((cc = krb5_net_read(bsd_context, fd, desinbuf.data, net_len)) != net_len) {
	/* pipe must have closed, return 0 */
	fprintf(stderr,
		"Read error: length received %d != expected %d.\n",
		cc,net_len);
	return(0);
    }
    /* decrypt info */
    if ((krb5_decrypt(bsd_context, desinbuf.data,
		      (krb5_pointer) storage,
		      net_len,
		      &eblock, 0))) {
	fprintf(stderr,"Cannot decrypt data from network.\n");
	return(0);
    }
    store_ptr = storage;
    nstored = rd_len;
    if (nstored > len) {
	memcpy(buf, store_ptr, len);
	nreturned += len;
	store_ptr += len;
	nstored -= len;
    } else {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	nstored = 0;
    }
    
    return(nreturned);
}



int des_write(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    unsigned char len_buf[4];
    
    if (!encrypt_flag)
      return(write(fd, buf, len));
    
    desoutbuf.length = krb5_encrypt_size(len,eblock.crypto_entry);
    if (desoutbuf.length > sizeof(des_outbuf)){
	fprintf(stderr,"Write size problem.\n");
	return(-1);
    }
    if (( krb5_encrypt(bsd_context, (krb5_pointer)buf,
		       desoutbuf.data,
		       len,
		       &eblock,
		       0))){
	fprintf(stderr,"Write encrypt problem.\n");
	return(-1);
    }
    
    len_buf[0] = (len & 0xff000000) >> 24;
    len_buf[1] = (len & 0xff0000) >> 16;
    len_buf[2] = (len & 0xff00) >> 8;
    len_buf[3] = (len & 0xff);
    (void) write(fd, len_buf, 4);
    if (write(fd, desoutbuf.data,desoutbuf.length) != desoutbuf.length){
	fprintf(stderr,"Could not write out all data.\n");
	return(-1);
    }
    else return(len); 
}



#else /* Original version  placed here so that testing could be done
	 to determine why rlogin with encryption on is slower with
	 version 5 as compared to version 4. */

#define ENCRYPT 1
#define DECRYPT 0



int des_read(fd, buf, len)
     int fd;
     register char *buf;
     int len;
{
    int nreturned = 0;
    long net_len, rd_len;
    int cc;
    unsigned char len_buf[4];
    
    if (!encrypt_flag)
      return(read(fd, buf, len));
    
    if (nstored >= len) {
	memcpy(buf, store_ptr, len);
	store_ptr += len;
	nstored -= len;
	return(len);
    } else if (nstored) {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	buf += nstored;
	len -= nstored;
	nstored = 0;
    }
#if 0
    if ((cc = krb5_net_read(bsd_context, fd, len_buf, 4)) != 4) {
	/* XXX can't read enough, pipe must have closed */
	return(0);
    }
    net_len =
	((len_buf[0]<<24) | (len_buf[1]<<16) | (len_buf[2]<<8) | len_buf[3]);
#else
	{
	    unsigned char c;
	    int gotzero = 0;

	    /* See the comment in v4_des_read. */
	    do {
		cc = krb5_net_read(bsd_context, fd, &c, 1);
		/* we should check for non-blocking here, but we'd have
		   to make it save partial reads as well. */
		if (cc < 0) return 0; /* read error */
		if (cc == 1) {
		    if (c == 0) gotzero = 1;
		}
	    } while (!gotzero);

	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    net_len = c;
	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    net_len = (net_len << 8) | c;
	    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
	    net_len = (net_len << 8) | c;
	}
#endif
    if (net_len < 0 || net_len > sizeof(des_inbuf)) {
	/* XXX preposterous length, probably out of sync.
	   act as if pipe closed */
	return(0);
    }
    /* the writer tells us how much real data we are getting, but
       we need to read the pad bytes (8-byte boundary) */
#ifdef NOROUNDUP
    rd_len = ((((net_len)+((8)-1))/(8))*(8));
#else
    rd_len = roundup(net_len, 8);
#endif
    if ((cc = krb5_net_read(bsd_context, fd, des_inbuf, rd_len)) != rd_len) {
	/* pipe must have closed, return 0 */
	return(0);
    }
    (void) mit_des_cbc_encrypt(
			       des_inbuf,
			       storage,
			       (net_len < 8) ? 8 : net_len,
			       eblock.priv,
			       eblock.key->contents,
			       DECRYPT);
    /*
     * when the cleartext block is < 8 bytes, it is "right-justified"
     * in the block, so we need to adjust the pointer to the data
     */
    if (net_len < 8)
      store_ptr = storage + 8 - net_len;
    else
      store_ptr = storage;
    nstored = net_len;
    if (nstored > len) {
	memcpy(buf, store_ptr, len);
	nreturned += len;
	store_ptr += len;
	nstored -= len;
    } else {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	nstored = 0;
    }
    return(nreturned);
}



int des_write(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    static char garbage_buf[8];
    unsigned char len_buf[4];
    
    if (!encrypt_flag)
      return(write(fd, buf, len));
    
#define min(a,b) ((a < b) ? a : b)
    
    if (len < 8) {
	krb5_random_confounder(bsd_context, 8 - len, &garbage_buf);
	/* this "right-justifies" the data in the buffer */
	(void) memcpy(garbage_buf + 8 - len, buf, len);
    }
    
    (void) mit_des_cbc_encrypt((len < 8) ? garbage_buf : buf,
			       des_outbuf,
			       (len < 8) ? 8 : len,
			       eblock.priv,
			       eblock.key->contents,
			       ENCRYPT);
    
    /* tell the other end the real amount, but send an 8-byte padded
       packet */
    len_buf[0] = (len & 0xff000000) >> 24;
    len_buf[1] = (len & 0xff0000) >> 16;
    len_buf[2] = (len & 0xff00) >> 8;
    len_buf[3] = (len & 0xff);
    (void) write(fd, len_buf, 4);
#ifdef NOROUNDUP
    (void) write(fd, des_outbuf, ((((len)+((8)-1))/(8))*(8)));
#else
    (void) write(fd, des_outbuf, roundup(len,8));
#endif
    return(len);
}

#endif /* OLD_VERSION */
#endif /* KERBEROS */



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
