/*
 *    $Source$!  *    $Author$
 *    $Header$
 */
#ifndef lint
static char rcsid_rlogin_c[] = "$Header$";
#endif /* lint */

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

#ifndef lint
static char sccsid[] = "@(#)rlogin.c	5.12 (Berkeley) 9/19/88";
#endif /* not lint */

     
     /*
      * rlogin - remote login
      */
     
#include <sys/param.h>
#include <sys/errno.h>
#ifndef _TYPES
#include <sys/types.h>
#define _TYPES_
#endif
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
     
#include <netinet/in.h>
     
#include <stdio.h>
     
#ifdef SYSV
#ifndef USE_TERMIO
#define USE_TERMIO
#endif
#endif
     
#ifdef USE_TERMIO
#ifdef CRAY
#include <sys/ttold.h>
#endif
#include <sys/termio.h>
#define sg_flags c_lflag
#define sg_ospeed c_cflag&CBAUD
     
#ifndef TIOCGETP
#define TIOCGETP TCGETA
#endif
#ifndef TIOCSETP
#define TIOCSETP TCSETA
#endif
#ifndef TIOCSETN
#define TIOCSETN TCSETAW
#endif
#else /* !USE_TERMIO */
#include <sgtty.h>
#endif /* USE_TERMIO */
     
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>
#include <string.h>
     
#ifdef KERBEROS
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/mit-des.h>
#include <krb5/los-proto.h>
#include <com_err.h>
#include "defines.h"
     
#ifdef BUFSIZ
#undef BUFSIZ
#endif
#define BUFSIZ 4096
     
char des_inbuf[2*BUFSIZ];       /* needs to be > largest read size */
char des_outbuf[2*BUFSIZ];      /* needs to be > largest write size */
krb5_data desinbuf,desoutbuf;
krb5_encrypt_block eblock;      /* eblock for encrypt/decrypt */

void try_normal();
char *krb_realm = (char *)0;
int encrypt = 0;
int fflag = 0, Fflag = 0;
krb5_creds *cred;
struct sockaddr_in local, foreign;

#define      UCB_RLOGIN      "/usr/ucb/rlogin"

#ifdef CRAY
#ifndef BITS64
#define BITS64
#endif
#endif

#else /* !KERBEROS */
#define des_read read
#define des_write write
#endif /* KERBEROS */


# ifndef TIOCPKT_WINDOW
# define TIOCPKT_WINDOW 0x80
# endif /* TIOCPKT_WINDOW */

/* concession to sun */
# ifndef SIGUSR1
# define SIGUSR1 30
# endif /* SIGUSR1 */

char	*getenv();
#ifndef convex
struct	passwd *getpwuid();
#endif
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
char    *speeds[] =
{ "0", "50", "75", "110", "134", "150", "200", "300", "600",
    "900", "1200", "1800", "2400", "3600", "4800", "7200", "9600",
    "19200", "38400", "EXTA", "EXTB" };
#else
char    *speeds[] =
{ "0", "50", "75", "110", "134", "150", "200", "300",
    "600", "1200", "1800", "2400", "4800", "9600", "19200", "38400" };
#endif
char	term[256] = "network";
extern	int errno;
krb5_sigtype	lostpeer();
int	dosigwinch = 0;
#ifndef sigmask
#define sigmask(m)	(1 << ((m)-1))
#endif
#ifdef NO_WINSIZE
struct winsize {
    unsigned short ws_row, ws_col;
    unsigned short ws_xpixel, ws_ypixel;
};
#endif /* NO_WINSIZE */
struct	winsize winsize;
krb5_sigtype	sigwinch(), oob();
char	*host=0;			/* external, so it can be
					   reached from confirm_death() */



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


#ifdef USE_TERMIO
/* Globals for terminal modes and flow control */
struct  termio defmodes;
struct  termio ixon_state;
#endif



main(argc, argv)
     int argc;
     char **argv;
{
    char *cp = (char *) NULL;
#ifdef USE_TERMIO
    struct termio ttyb;
#else
    struct sgttyb ttyb;
#endif
    struct passwd *pwd;
    struct servent *sp;
    int uid, options = 0, oldmask;
    int on = 1;
#ifdef KERBEROS
    char **orig_argv = argv;
    int sock;
    krb5_flags authopts;
    krb5_error_code status;
    int debug_port = 0;
#endif /* KERBEROS */
   
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
	encrypt++;
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
    krb5_init_ets();
    desinbuf.data = des_inbuf;
    desoutbuf.data = des_outbuf;	/* Set up des buffers */
    /*
     * if there is an entry in /etc/services for Kerberos login,
     * attempt to login with Kerberos. 
     * If we fail at any step,  use the standard rlogin
     */
    if (encrypt)
      sp = getservbyname("eklogin","tcp");
    else 
      sp = getservbyname("klogin","tcp");
    if (sp == 0) {
	fprintf(stderr, "rlogin: %s/tcp: unknown service\n",
		encrypt ? "eklogin" : "klogin");
	
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
    if (ioctl(0, TIOCGETP, &ttyb) == 0) {
	(void) strcat(term, "/");
	(void) strcat(term, speeds[ttyb.sg_ospeed]);
    }
    (void) get_window_size(0, &winsize);
    
#ifdef USE_TERMIO
    /**** moved before rcmd call so that if get a SIGPIPE in rcmd **/
    /**** we will have the defmodes set already. ***/
    (void)ioctl(fileno(stdin), TIOCGETP, &defmodes);
    (void)ioctl(fileno(stdin), TIOCGETP,&ixon_state);
#endif
    (void) signal(SIGPIPE, lostpeer);
    
    /* will use SIGUSR1 for window size hack, so hold it off */
#ifdef sgi
    oldmask = sigignore(sigmask(SIGURG) | sigmask(SIGUSR1));
#else
    oldmask = sigblock(sigmask(SIGURG) | sigmask(SIGUSR1));
#endif
    
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
		  authopts);
    if (status) {
	fprintf(stderr,
		"%s: kcmd to host %s failed - %s\n",orig_argv[0], host,
		error_message(status));
	try_normal(orig_argv);
    }
    rem = sock;
    
    /* setup eblock for des_read and write */
    krb5_use_keytype(&eblock,cred->keyblock.keytype);
    if ( status = krb5_process_key(&eblock,&cred->keyblock)) {
	fprintf(stderr,
		"%s: Cannot process session key : %s.\n",
		orig_argv, error_message(status));
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
#ifdef HAVE_SETOWN
    (void) fcntl(rem, F_SETOWN, getpid());
#endif
    if (options & SO_DEBUG &&
	setsockopt(rem, SOL_SOCKET, SO_DEBUG, &on, sizeof (on)) < 0)
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
krb5_sigtype	catchild();
krb5_sigtype	copytochild(), writeroob();

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

struct	tchars deftc;
struct	tchars notc =	{ -1, -1, -1, -1, -1, -1 };
struct	ltchars defltc;
struct	ltchars noltc =	{ -1, -1, -1, -1, -1, -1 };


doit(oldmask)
{
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
    (void) signal(SIGINT, SIG_IGN);
    setsignal(SIGHUP, exit);
    setsignal(SIGQUIT,exit);
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
    (void) signal(SIGURG, copytochild);
    (void) signal(SIGUSR1, writeroob);
#ifndef sgi
    (void) sigsetmask(oldmask);
#endif
    (void) signal(SIGCHLD, catchild);
    writer();
    prf("Closed connection.");
    done(0);
}



/*
 * Trap a signal, unless it is being ignored.
 */
setsignal(sig, act)
     int sig, (*act)();
{
#ifdef sgi
    int omask = sigignore(sigmask(sig));
#else
    int omask = sigblock(sigmask(sig));
#endif
    
    if (signal(sig, act) == SIG_IGN)
      (void) signal(sig, SIG_IGN);
#ifndef sgi
    (void) sigsetmask(omask);
#endif
}



done(status)
     int status;
{
    int w;
    
    mode(0);
    if (child > 0) {
	/* make sure catchild does not snap it up */
	(void) signal(SIGCHLD, SIG_DFL);
	if (kill(child, SIGKILL) >= 0)
	  while ((w = wait((union wait *)0)) > 0 && w != child)
	    /*void*/;
    }
    exit(status);
}



/*
 * Copy SIGURGs to the child process.
 */
krb5_sigtype
  copytochild()
{
    
    (void) kill(child, SIGURG);
}



/*
 * This is called when the reader process gets the out-of-band (urgent)
 * request to turn on the window-changing protocol.
 */
krb5_sigtype
  writeroob()
{
    
    if (dosigwinch == 0) {
	sendwindow();
	(void) signal(SIGWINCH, sigwinch);
    }
    dosigwinch = 1;
}



krb5_sigtype
  catchild()
{
    union wait status;
    int pid;
    
  again:
    pid = wait3(&status, WNOHANG|WUNTRACED, (struct rusage *)0);
    if (pid == 0)
      return;
    /*
     * if the child (reader) dies, just quit
     */
#if defined(hpux)
    if ((pid < 0) || ((pid == child) && (!WIFSTOPPED(status.w_stopval))))
#else
      if ((pid < 0) || ((pid == child) && (!WIFSTOPPED( status))))
#endif
	done((int)(status.w_termsig | status.w_retcode));
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
	    if (c == '.' || c == deftc.t_eofc) {
		if (confirm_death()) {
		    echo(c);
		    break;
		}
	    }
	    if ((c == defltc.t_suspc || c == defltc.t_dsuspc)
		&& !no_local_escape) {
		bol = 1;
		echo(c);
		stop(c);
		continue;
	    }
	    if (c != cmdchar)
	      (void) des_write(rem, &cmdchar, 1);
	}
	if (des_write(rem, &c, 1) == 0) {
	    prf("line gone");
	    break;
	}
	bol = c == defkill || c == deftc.t_eofc ||
	  c == deftc.t_intrc || c == defltc.t_suspc ||
	    c == '\r' || c == '\n';
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
    mode(0);
    (void) signal(SIGCHLD, SIG_IGN);
    (void) kill(cmdc == defltc.t_suspc ? 0 : getpid(), SIGTSTP);
    (void) signal(SIGCHLD, catchild);
    mode(1);
    sigwinch();			/* check for size changes */
}



krb5_sigtype
  sigwinch()
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
jmp_buf	rcvtop;

krb5_sigtype
  oob()
{
    int out = FWRITE, atmark, n;
    int rcvd = 0;
    char waste[BUFSIZ], mark;
#ifdef USE_TERMIO
    struct termio sb;
#else
    struct sgttyb sb;
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
    if (mark & TIOCPKT_FLUSHWRITE) {
#ifdef  TIOCFLUSH
	(void) ioctl(1, TIOCFLUSH, (char *)&out);
#else
	(void) ioctl(1, TCFLSH, 1);
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
	longjmp(rcvtop, 1);
    }
    
    /*
     * oob does not do FLUSHREAD (alas!)
     */
    
    /*
     * If we filled the receive buffer while a read was pending,
     * longjmp to the top to restart appropriately.  Don't abort
     * a pending write, however, or we won't know how much was written.
     */
    if (rcvd && rcvstate == READING)
      longjmp(rcvtop, 1);
}



/*
 * reader: read from remote: line -> 1
 */
reader(oldmask)
     int oldmask;
{
#if (defined(BSD) && BSD >= 43) || defined(ultrix)
    int pid = getpid();
#else
    int pid = -getpid();
#endif
    int n, remaining;
    char *bufp = rcvbuf;
    
    (void) signal(SIGTTOU, SIG_IGN);
    (void) signal(SIGURG, oob);
    ppid = getppid();
#ifdef HAVE_SETOWN
    (void) fcntl(rem, F_SETOWN, pid);
#endif
    (void) setjmp(rcvtop);
#ifndef sgi
    (void) sigsetmask(oldmask);
#endif
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
	/* preserve tab delays, but turn off tab-to-space expansion */
	if ((sb.c_oflag & TABDLY) == TAB3)
	  sb.c_oflag &= ~TAB3;
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
}



/*VARARGS*/
prf(f, a1, a2, a3, a4, a5)
     char *f;
{
    fprintf(stderr, f, a1, a2, a3, a4, a5);
    fprintf(stderr, CRLF);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    register char *host;
    
    if (encrypt)
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



char storage[2*BUFSIZ];			/* storage for the decryption */
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
    
    if (!encrypt)
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
    
#ifdef BITS64
    /*
     * XXX Ick.  This assumes big endian byte order.
     */
    rd_len = 0;
    if ((cc = krb5_net_read(fd, (char *)&rd_len + 4, 4)) != 4) {
#else
    if ((cc = krb5_net_read(fd, (char *)&rd_len, sizeof(rd_len))) !=
	    sizeof(rd_len)) {
#endif
		/* XXX can't read enough, pipe
		   must have closed */
	return(0);
    }
    rd_len = ntohl(rd_len);
    net_len = krb5_encrypt_size(rd_len,eblock.crypto_entry);
    if (net_len <= 0 || net_len > sizeof(des_inbuf)) {
	/* preposterous length; assume out-of-sync; only
	   recourse is to close connection, so return 0 */
	fprintf(stderr,"Read size problem.\n");
	return(0);
    }
    if ((cc = krb5_net_read(fd, desinbuf.data, net_len)) != net_len) {
	/* pipe must have closed, return 0 */
	fprintf(stderr,
		"Read error: length received %d != expected %d.\n",
		cc,net_len);
	return(0);
    }
    /* decrypt info */
    if ((krb5_decrypt(desinbuf.data,
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
    long net_len;
    
    if (!encrypt)
      return(write(fd, buf, len));
    
    desoutbuf.length = krb5_encrypt_size(len,eblock.crypto_entry);
    if (desoutbuf.length > sizeof(des_outbuf)){
	fprintf(stderr,"Write size problem.\n");
	return(-1);
    }
    if (( krb5_encrypt((krb5_pointer)buf,
		       desoutbuf.data,
		       len,
		       &eblock,
		       0))){
	fprintf(stderr,"Write encrypt problem.\n");
	return(-1);
    }
    
    net_len = htonl(len);
#ifdef BITS64
    (void) write(fd,(char *)&net_len + 4, 4);
#else
    (void) write(fd, &net_len, sizeof(net_len));
#endif
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
    
    if (!encrypt)
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
#ifdef BITS64
    net_len = 0;
    if ((cc = krb5_net_read(fd, (char *)&net_len + 4, 4)) != 4) {
#else
    if ((cc = krb5_net_read(fd, &net_len, sizeof(net_len))) !=
	sizeof(net_len)) {
#endif
	/* XXX can't read enough, pipe
	   must have closed */
	return(0);
    }
    net_len = ntohl(net_len);
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
    if ((cc = krb5_net_read(fd, des_inbuf, rd_len)) != rd_len) {
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
    long net_len;
    static int seeded = 0;
    static char garbage_buf[8];
    long garbage;
    
    if (!encrypt)
      return(write(fd, buf, len));
    
#define min(a,b) ((a < b) ? a : b)
    
    if (len < 8) {
	if (!seeded) {
	    seeded = 1;
	    srandom((int) time((long *)0));
	}
	garbage = random();
	/* insert random garbage */
	(void) memcpy(garbage_buf, &garbage, min(sizeof(long),8));
	
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
    net_len = htonl(len);
#ifdef BITS64
    (void) write(fd,(char *)&net_len + 4, 4);
#else
    (void) write(fd, &net_len, sizeof(net_len));
#endif
#ifdef NOROUNDUP
    (void) write(fd, des_outbuf, ((((len)+((8)-1))/(8))*(8)));
#else
    (void) write(fd, des_outbuf, roundup(len,8));
#endif
    return(len);
}

#endif /* OLD_VERSION */
#endif /* KERBEROS */



krb5_sigtype lostpeer()
{
    
    (void) signal(SIGPIPE, SIG_IGN);
    prf("\007Connection closed.");
    done(1);
}
