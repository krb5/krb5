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
#include "krb5.h"
#include "com_err.h"
#include "defines.h"
#endif /* KERBEROS */
     
/*
 * rsh - remote shell
 */
#define SECURE_MESSAGE "This rsh session is using DES encryption for all data transmissions.\r\n"

int	error();
     
int	options;
int	rfd2;
int	nflag;
krb5_sigtype  sendsig();

#ifdef KERBEROS

#ifndef UCB_RSH
#define UCB_RSH "/usr/ucb/rsh"
#endif

#define RSH_BUFSIZ 4096

char des_inbuf[2*RSH_BUFSIZ];       /* needs to be > largest read size */
char des_outbuf[2*RSH_BUFSIZ];      /* needs to be > largest write size */
krb5_data desinbuf,desoutbuf;
krb5_encrypt_block eblock;      /* eblock for encrypt/decrypt */
krb5_context bsd_context;
krb5_creds *cred;

int	encrypt_flag = 0;
char	*krb_realm = (char *)0;
void	try_normal();

#else /* KERBEROS */

#define des_read read
#define des_write write

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
     
main(argc, argv0)
     int argc;
     char **argv0;
{
    int rem, pid;
    char *host=0, *cp, **ap, buf[RSH_BUFSIZ], *args, **argv = argv0, *user = 0;
    register int cc;
    struct passwd *pwd;
    fd_set readfrom, ready;
    int one = 1;
    struct servent *sp;
    struct servent defaultservent;

#ifdef POSIX_SIGNALS
    sigset_t omask, igmask;
    struct sigaction sa, osa;
#else
    int omask;
#endif
#ifdef KERBEROS
    krb5_flags authopts;
    krb5_error_code status;
    int fflag = 0, Fflag = 0, Aflag = 0;
#endif  /* KERBEROS */
    int debug_port = 0;

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
        Aflag++;
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
    if (encrypt_flag)
      cc += 3;
    cp = args = (char *) malloc(cc);
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
#endif /* KERBEROS */
	exit(1);
      }

      debug_port = sp->s_port;
    }

#ifdef KERBEROS
    krb5_init_context(&bsd_context);
    krb5_init_ets(bsd_context);
    authopts = AP_OPTS_MUTUAL_REQUIRED;

    /* Piggy-back forwarding flags on top of authopts; */
    /* they will be reset in kcmd */
    if (fflag || Fflag)
      authopts |= OPTS_FORWARD_CREDS;
    if (Fflag)
      authopts |= OPTS_FORWARDABLE_CREDS;    

    status = kcmd(&rem, &host, debug_port,
		  pwd->pw_name,
		  user ? user : pwd->pw_name,
		  args, &rfd2, "host", krb_realm,
		  &cred,
		  0,           /* No need for sequence number */
		  0,           /* No need for server seq # */
		  (struct sockaddr_in *) 0,
		  (struct sockaddr_in *) 0,
		  authopts,
		  Aflag);	/* Any port #? */
    if (status) {
        /* check NO_TKT_FILE or equivalent... */
	fprintf(stderr,
		"%s: kcmd to host %s failed - %s\n",argv0[0], host,
		error_message(status));
	try_normal(argv0);
    }

    /* Setup for des_read and write */
    desinbuf.data = des_inbuf;
    desoutbuf.data = des_outbuf;
    krb5_use_enctype(bsd_context, &eblock,cred->keyblock.enctype);
    if (status = krb5_process_key(bsd_context, &eblock,&cred->keyblock)) {
        fprintf(stderr, "%s: Cannot process session key : %s.\n",
                argv0, error_message(status));
        exit(1);
    }
#ifdef HAVE_ISATTY
    if(isatty(2)) {
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
	wc = des_write(rem, bp, cc);
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
	    cc = des_read(rfd2, buf, sizeof buf);
	    if (cc <= 0) {
		if ((errno != EWOULDBLOCK) && (errno != EAGAIN))
		    FD_CLR(rfd2, &readfrom);
	    } else
	      (void) write(2, buf, cc);
	}
	if (FD_ISSET(rem, &ready)) {
	    errno = 0;
	    cc = des_read(rem, buf, sizeof buf);
	    if (cc <= 0) {
		if ((errno != EWOULDBLOCK) && (errno != EAGAIN))
		    FD_CLR(rem, &readfrom);
	    } else
	      (void) write(1, buf, cc);
	}
    } while (FD_ISSET(rem, &readfrom) || FD_ISSET(rfd2, &readfrom));
    if (nflag == 0)
      (void) kill(pid, SIGKILL);
    exit(0);
  usage:
    fprintf(stderr,
	    "usage: \trsh host [ -l login ] [ -n ] [ -x ] [ -f / -F] command\n");
    fprintf(stderr,
	    "OR \trsh [ -l login ] [-n ] [ -x ] [ -f / -F ] host command\n");
    exit(1);
}



krb5_sigtype sendsig(signo)
     char signo;
{
    (void) des_write(rfd2, &signo, 1);
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    char *host;
    
    if (encrypt_flag)
	exit(1);

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


char storage[2*RSH_BUFSIZ];
int nstored = 0;
char *store_ptr = storage;

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
    
    if ((cc = krb5_net_read(bsd_context, fd, len_buf, 4)) != 4) {
	/* XXX can't read enough, pipe must have closed */
	return(0);
    }
    rd_len =
	((len_buf[0]<<24) | (len_buf[1]<<16) | (len_buf[2]<<8) | len_buf[3]);
    net_len = krb5_encrypt_size(rd_len,eblock.crypto_entry);
    if ((net_len <= 0) || (net_len > sizeof(des_inbuf))) {
	/* preposterous length; assume out-of-sync; only
	   recourse is to close connection, so return 0 */
	fprintf(stderr,"Read size problem.\n");
	return(0);
    }
    if ((cc = krb5_net_read(bsd_context, fd, desinbuf.data, net_len)) != net_len) {
	/* pipe must have closed, return 0 */
	fprintf(stderr, "Read error: length received %d != expected %d.\n",
		cc, net_len);
	return(0);
    }
    /* decrypt info */
    if (cc = krb5_decrypt(bsd_context, desinbuf.data, (krb5_pointer) storage,
			  net_len, &eblock, 0)) {
	fprintf(stderr,"Cannot decrypt data from network\n");
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
    
    desoutbuf.length = krb5_encrypt_size(len, eblock.crypto_entry);
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
#endif /* KERBEROS */
