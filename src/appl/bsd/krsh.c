/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_rsh_c = 
  "$Header$";
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
static char sccsid[] = "@(#)rsh.c	5.7 (Berkeley) 9/20/88";
#endif /* not lint */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
     
#include <netinet/in.h>
     
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>
     
#ifdef HAVE_SYS_FILIO_H
/* get FIONBIO from sys/filio.h, so what if it is a compatibility feature */
#include <sys/filio.h>
#endif

#ifdef KERBEROS
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/mit-des.h>
#include <krb5/osconf.h>
#include "defines.h"
#endif /* KERBEROS */
     
     /*
      * rsh - remote shell
      */

int	error();
     
#ifndef convex
struct	passwd *getpwuid();
#endif

int	options;
int	rfd2;
int	nflag;
krb5_sigtype  sendsig();

#ifdef KERBEROS
char	*krb_realm = (char *)0;
void	try_normal();
#define UCB_RSH "/usr/ucb/rsh"
#endif

#ifndef RLOGIN_PROGRAM
#ifdef KERBEROS
#define RLOGIN_PROGRAM KRB5_PATH_RLOGIN
#else /* KERBEROS */
#define RLOGIN_PROGRAM "/usr/ucb/rlogin"
#endif  /* KERBEROS */
#endif /* !RLOGIN_PROGRAM */
     
#define	mask(s)	(1 << ((s) - 1))
     
     main(argc, argv0)
     int argc;
     char **argv0;
{
    int rem, pid;
    char *host=0, *cp, **ap, buf[BUFSIZ], *args, **argv = argv0, *user = 0;
    register int cc;
    int asrsh = 0;
    struct passwd *pwd;
    int readfrom, ready;
    int one = 1;
    struct servent *sp;
    int omask;
#ifdef KERBEROS
    krb5_flags authopts;
    krb5_error_code status;
    int fflag = 0, Fflag = 0;
    int debug_port = 0;
#endif  /* KERBEROS */
   
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
    cp = args = (char *) malloc(cc);
    for (ap = argv; *ap; ap++) {
	(void) strcpy(cp, *ap);
	while (*cp)
	  cp++;
	if (ap[1])
	  *cp++ = ' ';
    }
#ifdef KERBEROS
    sp = getservbyname("kshell", "tcp");
#else 
    sp = getservbyname("shell", "tcp");
#endif  /* KERBEROS */
    if (sp == 0) {
#ifdef KERBEROS
	fprintf(stderr, "rsh: kshell/tcp: unknown service\n");
	try_normal(argv0);
#else 
	fprintf(stderr, "rsh: shell/tcp: unknown service\n");
#endif /* KERBEROS */
	exit(1);
    }

    if (debug_port)
      sp->s_port = debug_port;
    
#ifdef KERBEROS
    krb5_init_ets();
    authopts = AP_OPTS_MUTUAL_REQUIRED;

    /* Piggy-back forwarding flags on top of authopts; */
    /* they will be reset in kcmd */
    if (fflag || Fflag)
      authopts |= OPTS_FORWARD_CREDS;
    if (Fflag)
      authopts |= OPTS_FORWARDABLE_CREDS;    

    status = kcmd(&rem, &host, sp->s_port,
		  pwd->pw_name,
		  user ? user : pwd->pw_name,
		  args, &rfd2, "host", krb_realm,
		  0,		/* No need for returned credentials */
		  0,           /* No need for sequence number */
		  0,           /* No need for server seq # */
		  (struct sockaddr_in *) 0,
		  (struct sockaddr_in *) 0,
		  authopts);
    if (status) {
	fprintf(stderr,
		"%s: kcmd to host %s failed - %s\n",argv0[0], host,
		error_message(status));
	try_normal(argv0);
    }
#else /* !KERBEROS */
    rem = rcmd(&host, sp->s_port, pwd->pw_name,
	       user ? user : pwd->pw_name, args, &rfd2);
    if (rem < 0)
      exit(1);
#endif /* KERBEROS */
    if (rfd2 < 0) {
	fprintf(stderr, "rsh: can't establish stderr\n");
	exit(2);
    }
    if (options & SO_DEBUG) {
	if (setsockopt(rem, SOL_SOCKET, SO_DEBUG, &one, sizeof (one)) < 0)
	  perror("setsockopt (stdin)");
	if (setsockopt(rfd2, SOL_SOCKET, SO_DEBUG, &one, sizeof (one)) < 0)
	  perror("setsockopt (stderr)");
    }
    (void) setuid(getuid());
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
    if (nflag == 0) {
	pid = fork();
	if (pid < 0) {
	    perror("fork");
	    exit(1);
	}
    }
    ioctl(rfd2, FIONBIO, &one);
    ioctl(rem, FIONBIO, &one);
    if (nflag == 0 && pid == 0) {
	char *bp; int rembits, wc;
	(void) close(rfd2);
      reread:
	errno = 0;
	cc = read(0, buf, sizeof buf);
	if (cc <= 0)
	  goto done;
	bp = buf;
      rewrite:
	rembits = 1<<rem;
	if (select(16, 0, &rembits, 0, 0) < 0) {
	    if (errno != EINTR) {
		perror("select");
		exit(1);
	    }
	    goto rewrite;
	}
	if ((rembits & (1<<rem)) == 0)
	  goto rewrite;
	wc = write(rem, bp, cc);
	if (wc < 0) {
	    if (errno == EWOULDBLOCK)
	      goto rewrite;
	    goto done;
	}
	cc -= wc; bp += wc;
	if (cc == 0)
	  goto reread;
	goto rewrite;
      done:
	(void) shutdown(rem, 1);
	exit(0);
    }
#ifndef sgi
    sigsetmask(omask);
#endif
    readfrom = (1<<rfd2) | (1<<rem);
    do {
	ready = readfrom;
	if (select(16, &ready, 0, 0, 0) < 0) {
	    if (errno != EINTR) {
		perror("select");
		exit(1);
	    }
	    continue;
	}
	if (ready & (1<<rfd2)) {
	    errno = 0;
	    cc = read(rfd2, buf, sizeof buf);
	    if (cc <= 0) {
		if (errno != EWOULDBLOCK)
		  readfrom &= ~(1<<rfd2);
	    } else
	      (void) write(2, buf, cc);
	}
	if (ready & (1<<rem)) {
	    errno = 0;
	    cc = read(rem, buf, sizeof buf);
	    if (cc <= 0) {
		if (errno != EWOULDBLOCK)
		  readfrom &= ~(1<<rem);
	    } else
	      (void) write(1, buf, cc);
	}
    } while (readfrom);
    if (nflag == 0)
      (void) kill(pid, SIGKILL);
    exit(0);
  usage:
    fprintf(stderr,
	    "usage: \trsh host [ -l login ] [ -n ] [ -f / -F] command\n");
    fprintf(stderr,
	    "OR \trsh [ -l login ] [-n ] [ -f / -F ] host command\n");
    exit(1);
}



krb5_sigtype sendsig(signo)
     char signo;
{
    
    (void) write(rfd2, &signo, 1);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    char *host;
    
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
