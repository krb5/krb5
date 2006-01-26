/*
 *	appl/bsd/krsh.c
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

/* based on @(#)rsh.c	5.7 (Berkeley) 9/20/88 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/time.h>

#include <netinet/in.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_FILIO_H
/* get FIONBIO from sys/filio.h, so what if it is a compatibility feature */
#include <sys/filio.h>
#endif

#ifdef KERBEROS
#include <krb5.h>
#include <com_err.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif
#include "defines.h"
#endif /* KERBEROS */

#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
Key_schedule v4_schedule;
#endif

/*
 * rsh - remote shell
 */
#define SECURE_MESSAGE "This rsh session is encrypting input/output data transmissions.\r\n"

int	error();
     
int	options;
int	rfd2;
int	nflag;
krb5_sigtype  sendsig(int);

#ifdef KERBEROS

#ifndef UCB_RSH
#define UCB_RSH "/usr/ucb/rsh"
#endif

krb5_context bsd_context;
krb5_creds *cred;

#ifdef KRB5_KRB4_COMPAT
Key_schedule v4_schedule;
CREDENTIALS v4_cred;
#endif

int	encrypt_flag = 0;
char	*krb_realm = (char *)0;
void	try_normal(char **);

#endif /* KERBEROS */

#ifndef RLOGIN_PROGRAM
#ifdef KERBEROS
#define RLOGIN_PROGRAM KRB5_PATH_RLOGIN
#else /* KERBEROS */
#ifndef UCB_RLOGIN
#define UCB_RLOGIN "/usr/ucb/rlogin"
#endif
#define RLOGIN_PROGRAM UCB_RLOGIN
#endif  /* KERBEROS */
#endif /* !RLOGIN_PROGRAM */
     
#ifndef POSIX_SIGNALS
#define	mask(s)	(1 << ((s) - 1))
#endif /* POSIX_SIGNALS */
     
int
main(argc, argv0)
     int argc;
     char **argv0;
{
    int rem, pid = 0;
    char *host=0, *cp, **ap, buf[RCMD_BUFSIZ], *args, **argv = argv0, *user = 0;
    register int cc;
    struct passwd *pwd;
    fd_set readfrom, ready;
    int one = 1;
    struct servent *sp;
    struct servent defaultservent;
    struct sockaddr_in local, foreign;
    int suppress = 0;

#ifdef POSIX_SIGNALS
    sigset_t omask, igmask;
    struct sigaction sa, osa;
#else
    int omask;
#endif
#ifdef KERBEROS
    krb5_flags authopts;
    krb5_error_code status;
    krb5_auth_context auth_context;
    int fflag = 0, Fflag = 0;
#ifdef KRB5_KRB4_COMPAT
    KTEXT_ST v4_ticket;
    MSG_DAT v4_msg_data;
#endif
#endif  /* KERBEROS */
    int debug_port = 0;
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
	debug_port = htons(atoi(*argv));
	argv++; argc--;
	goto another;
    }

    if (argc > 0 && !strcmp(*argv, "-l")) {
	argv++, argc--;
	if (argc > 0)
	  user = *argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-n")) {
	argv++, argc--;
	nflag++;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-d")) {
	argv++, argc--;
	options |= SO_DEBUG;
	goto another;
    }
#ifdef KERBEROS
    if (argc > 0 && !strcmp(*argv, "-k")) {
	argv++, argc--;
	if (argc == 0) {
	    fprintf(stderr, "rsh(kerberos): -k flag must have a realm after it.\n");
	    exit (1);
	}
	if(!(krb_realm = (char *)malloc(strlen(*argv) + 1))){
	    fprintf(stderr, "rsh(kerberos): Cannot malloc.\n");
	    exit(1);
	}
	strcpy(krb_realm, *argv);
	argv++, argc--;
	goto another;
    }
    /*
     * Ignore -x from kerberos rlogin
     */
    if (argc > 0 && !strncmp(*argv, "-x", 2)) {
	argv++, argc--;
	encrypt_flag++;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-f", 2)) {
	if (Fflag) {
	    fprintf(stderr, "rsh: Only one of -f and -F allowed\n");
	    goto usage;
	}
	fflag++;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-F", 2)) {
	if (fflag) {
	    fprintf(stderr, "rsh: Only one of -f and -F allowed\n");
	    goto usage;
	}
	Fflag++;
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-A", 2)) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-PO")) {
	argv++, argc--;
	kcmd_proto = KCMD_OLD_PROTOCOL;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-PN")) {
	argv++, argc--;
	kcmd_proto = KCMD_NEW_PROTOCOL;
	goto another;
    }
#endif  /* KERBEROS */
    /*
     * Ignore the -L, -w, -e and -8 flags to allow aliases with rlogin
     * to work
     *
     * There must be a better way to do this! -jmb
     */
    if (argc > 0 && !strncmp(*argv, "-L", 2)) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-w", 2)) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-e", 2)) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strncmp(*argv, "-8", 2)) {
	argv++, argc--;
	goto another;
    }
#ifdef ATHENA
    /* additional Athena flags to be ignored */
    if (argc > 0 && !strcmp(*argv, "-noflow")) {	/* No local flow control option for rlogin */
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-7")) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-c")) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-a")) {
	argv++, argc--;
	goto another;
    }
    if (argc > 0 && !strcmp(*argv, "-n")) {
	argv++, argc--;
	goto another;
    }
    /*
     ** Also ignore -t ttytype
     */
    if (argc > 0 && !strcmp(*argv, "-t")) {
	argv++; argv++; argc--; argc--;
	goto another;
    }
#endif /* ATHENA */
    if (host == 0)
      goto usage;
    if (argv[0] == 0) {
	execv(RLOGIN_PROGRAM, argv0);
	perror(RLOGIN_PROGRAM);
	exit(1);
    }

    pwd = getpwuid(getuid());
    if (pwd == 0) {
	fprintf(stderr, "who are you?\n");
	exit(1);
    }
    cc = 0;
    for (ap = argv; *ap; ap++)
      cc += strlen(*ap) + 1;
    if (encrypt_flag)
      cc += 3;
    cp = args = (char *) malloc((unsigned) cc);
    if (encrypt_flag) {
      strcpy(args, "-x ");
      cp += 3;
    }
    for (ap = argv; *ap; ap++) {
	(void) strcpy(cp, *ap);
	while (*cp)
	  cp++;
	if (ap[1])
	  *cp++ = ' ';
    }

    if(debug_port == 0) {
#ifdef KERBEROS
      sp = getservbyname("kshell", "tcp");
#else 
      sp = getservbyname("shell", "tcp");
#endif  /* KERBEROS */
      if (sp == 0) {
#ifdef KERBEROS
	sp = &defaultservent;
	sp->s_port = htons(544);
#else 
	fprintf(stderr, "rsh: shell/tcp: unknown service\n");
	exit(1);
#endif /* KERBEROS */
      }

      debug_port = sp->s_port;
    }

#ifdef KERBEROS
    status = krb5_init_context(&bsd_context);
    if (status) {
	    com_err(argv[0], status, "while initializing krb5");
	    exit(1);
    }
    authopts = AP_OPTS_MUTUAL_REQUIRED;

    /* Piggy-back forwarding flags on top of authopts; */
    /* they will be reset in kcmd */
    if (fflag || Fflag)
      authopts |= OPTS_FORWARD_CREDS;
    if (Fflag)
      authopts |= OPTS_FORWARDABLE_CREDS;    
#ifdef HAVE_ISATTY
    suppress = !isatty(fileno(stderr));
#endif
    status = kcmd(&rem, &host, debug_port,
		  pwd->pw_name,
		  user ? user : pwd->pw_name,
		  args, &rfd2, "host", krb_realm,
		  &cred,
		  0,           /* No need for sequence number */
		  0,           /* No need for server seq # */
		  &local, &foreign,
		  &auth_context, authopts,
		  1,	/* Always set anyport, there is no need not to. --proven */
		  suppress,
		  &kcmd_proto);
    if (status) {
	/* If new protocol requested, don't fall back to less secure
	   ones.  */
	if (kcmd_proto == KCMD_NEW_PROTOCOL)
	    exit (1);
#ifdef KRB5_KRB4_COMPAT
	/* No encrypted Kerberos 4 rsh. */
	if (encrypt_flag)
	    exit(1);
#ifdef HAVE_ISATTY
	if (isatty(fileno(stderr)))
	    fprintf(stderr, "Trying krb4 rsh...\n");
#endif
	status = k4cmd(&rem, &host, debug_port,
		       pwd->pw_name,
		       user ? user : pwd->pw_name, args,
		       &rfd2, &v4_ticket, "rcmd", krb_realm,
		       &v4_cred, v4_schedule, &v4_msg_data,
		       &local, &foreign, 0L, 0);
	if (status)
	    try_normal(argv0);
	rcmd_stream_init_krb4(v4_cred.session, encrypt_flag, 0, 1);
#else
	try_normal(argv0);
#endif
    } else {
	krb5_keyblock *key = &cred->keyblock;

	if (kcmd_proto == KCMD_NEW_PROTOCOL) {
	    status = krb5_auth_con_getsendsubkey (bsd_context, auth_context,
						  &key);
	    if (status) {
		com_err (argv[0], status, "determining subkey for session");
		exit (1);
	    }
	    if (!key) {
		com_err (argv[0], 0, "no subkey negotiated for connection");
		exit (1);
	    }
	}

	rcmd_stream_init_krb5(key, encrypt_flag, 0, 1, kcmd_proto);
    }

#ifdef HAVE_ISATTY
    if(encrypt_flag&&isatty(2)) {
	write(2,SECURE_MESSAGE, strlen(SECURE_MESSAGE));
    }
#endif
    
#else /* !KERBEROS */
    rem = rcmd(&host, debug_port, pwd->pw_name,
	       user ? user : pwd->pw_name, args, &rfd2);
    if (rem < 0)
      exit(1);
#endif /* KERBEROS */
    if (rfd2 < 0) {
	fprintf(stderr, "rsh: can't establish stderr\n");
	exit(2);
    }
    if (options & SO_DEBUG) {
	if (setsockopt(rem, SOL_SOCKET, SO_DEBUG,
		       (const char *) &one, sizeof (one)) < 0)
	  perror("setsockopt (stdin)");
	if (setsockopt(rfd2, SOL_SOCKET, SO_DEBUG,
		       (const char *) &one, sizeof (one)) < 0)
	  perror("setsockopt (stderr)");
    }
    (void) setuid(getuid());
#ifdef POSIX_SIGNALS
    sigemptyset(&igmask);
    sigaddset(&igmask, SIGINT);
    sigaddset(&igmask, SIGQUIT);
    sigaddset(&igmask, SIGTERM);
    sigprocmask(SIG_BLOCK, &igmask, &omask);

    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sendsig;

    (void)sigaction(SIGINT, (struct sigaction *)0, &osa);
    if (osa.sa_handler != SIG_IGN)
	(void)sigaction(SIGINT, &sa, (struct sigaction *)0);

    (void)sigaction(SIGQUIT, (struct sigaction *)0, &osa);
    if (osa.sa_handler != SIG_IGN)
	(void)sigaction(SIGQUIT, &sa, (struct sigaction *)0);

    (void)sigaction(SIGTERM, (struct sigaction *)0, &osa);
    if (osa.sa_handler != SIG_IGN)
	(void)sigaction(SIGTERM, &sa, (struct sigaction *)0);
#else
#ifdef sgi
    omask = sigignore(mask(SIGINT)|mask(SIGQUIT)|mask(SIGTERM));
#else
    omask = sigblock(mask(SIGINT)|mask(SIGQUIT)|mask(SIGTERM));
#endif
    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
      signal(SIGINT, sendsig);
    if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
      signal(SIGQUIT, sendsig);
    if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
      signal(SIGTERM, sendsig);
#endif /* POSIX_SIGNALS */
    if (nflag == 0) {
	pid = fork();
	if (pid < 0) {
	    perror("fork");
	    exit(1);
	}
    }
    if (!encrypt_flag) {
	ioctl(rfd2, FIONBIO, &one);
	ioctl(rem, FIONBIO, &one);
    }
    if (nflag == 0 && pid == 0) {
	char *bp;
	int wc;
	fd_set rembits;
	
	(void) close(rfd2);
      reread:
	errno = 0;
	cc = read(0, buf, sizeof buf);
	if (cc <= 0)
	  goto done;
	bp = buf;
      rewrite:
	FD_ZERO(&rembits);
	FD_SET(rem, &rembits);
	if (select(8*sizeof(rembits), 0, &rembits, 0, 0) < 0) {
	    if (errno != EINTR) {
		perror("select");
		exit(1);
	    }
	    goto rewrite;
	}
	if (FD_ISSET(rem, &rembits) == 0)
	  goto rewrite;
	wc = rcmd_stream_write(rem, bp, cc, 0);
	if (wc < 0) {
	    if ((errno == EWOULDBLOCK) || (errno == EAGAIN))
	      goto rewrite;
	    goto done;
	}
	cc -= wc; bp += wc;
	if (cc == 0)
	  goto reread;
	goto rewrite;
      done:
	(void) shutdown(rem, 1);
#ifdef KERBEROS 
	krb5_free_context(bsd_context);
#endif
	exit(0);
    }
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &omask, (sigset_t*)0);
#else
#ifndef sgi
    sigsetmask(omask);
#endif
#endif /* POSIX_SIGNALS */
    FD_ZERO(&readfrom);
    FD_SET(rfd2, &readfrom);
    FD_SET(rem, &readfrom);
    do {
	ready = readfrom;
	if (select(8*sizeof(ready), &ready, 0, 0, 0) < 0) {
	    if (errno != EINTR) {
		perror("select");
		exit(1);
	    }
	    continue;
	}
	if (FD_ISSET(rfd2, &ready)) {
	    errno = 0;
	    cc = rcmd_stream_read(rfd2, buf, sizeof buf, 1);
	    if (cc <= 0) {
		if ((errno != EWOULDBLOCK) && (errno != EAGAIN))
		    FD_CLR(rfd2, &readfrom);
	    } else
	      (void) write(2, buf, (unsigned) cc);
	}
	if (FD_ISSET(rem, &ready)) {
	    errno = 0;
	    cc = rcmd_stream_read(rem, buf, sizeof buf, 0);
	    if (cc <= 0) {
		if ((errno != EWOULDBLOCK) && (errno != EAGAIN))
		    FD_CLR(rem, &readfrom);
	    } else
	      (void) write(1, buf, (unsigned) cc);
	}
    } while (FD_ISSET(rem, &readfrom) || FD_ISSET(rfd2, &readfrom));
    if (nflag == 0)
      (void) kill(pid, SIGKILL);
#ifdef KERBEROS 
    krb5_free_context(bsd_context);
#endif
    exit(0);
  usage:
    fprintf(stderr,
	    "usage: \trsh host [ -PN / -PO ] [ -l login ] [ -n ] [ -x ] [ -f / -F] command\n");
    fprintf(stderr,
	    "OR \trsh [ -PN / -PO ] [ -l login ] [-n ] [ -x ] [ -f / -F ] host command\n");
    exit(1);
}



krb5_sigtype sendsig(signo)
     char signo;
{
    (void) rcmd_stream_write(rfd2, &signo, 1, 1);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    char *host;
    
#ifndef KRB5_ATHENA_COMPAT
    if (encrypt_flag)
	exit(1);
#endif
    /*
     * if we were invoked as 'rsh host mumble', strip off the rsh
     * from arglist.
     *
     * We always want to call the Berkeley rsh as 'host mumble'
     */
    host = strrchr(argv[0], '/');
    if (host)
      host++;
    else
      host = argv[0];
    
    if (!strcmp(host, "rsh"))
      argv++;
    
    fprintf(stderr,"trying normal rsh (%s)\n",
	    UCB_RSH);
    fflush(stderr);
    execv(UCB_RSH, argv);
    perror("exec");
    exit(1);
}
#endif /* KERBEROS */
