/*
 *	appl/bsd/krcp.c
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

/* based on @(#)rcp.c	5.10 (Berkeley) 9/20/88 */

     /*
      * rcp
      */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/param.h>
#ifndef _TYPES_
#include <sys/types.h>
#define _TYPES_
#endif
#include <sys/file.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
     
#include <netinet/in.h>
     
#include <stdio.h>
#include <signal.h>
#include <pwd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_VFORK_H
#include <vfork.h>
#endif
#include <stdarg.h>
#include <sys/wait.h>

#ifdef KERBEROS
#include "k5-int.h"
#include <k5-util.h>
#include <com_err.h>

#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif

#include "defines.h"

#define RCP_BUFSIZ 4096
     
int sock;
struct sockaddr_in local, foreign; /* set up by kcmd used by v4_send_auth */
char *krb_realm = NULL;
char *krb_cache = NULL;
char *krb_config = NULL;
krb5_encrypt_block eblock;         /* eblock for encrypt/decrypt */
krb5_context bsd_context;

#ifdef KRB5_KRB4_COMPAT
Key_schedule v4_schedule;
CREDENTIALS v4_cred;
KTEXT_ST v4_ticket;
MSG_DAT v4_msg_data;
#endif

void	v4_send_auth(char *, char *), try_normal(char **);
char	**save_argv(int, char **);
#ifndef HAVE_STRSAVE
char	*strsave();
#endif
int	rcmd_stream_write(), rcmd_stream_read();
void 	usage(void), sink(int, char **),
    source(int, char **), rsource(char *, struct stat *), verifydir(char *), 
    answer_auth(char *, char *);
int	response(void), hosteq(char *, char *), okname(char *), 
    susystem(char *);
int	encryptflag = 0;

#ifndef UCB_RCP
#define	UCB_RCP	"/bin/rcp"
#endif

#endif /* KERBEROS */

int	rem;
char	*colon(char *);
int	errs;
krb5_sigtype	lostconn(int);
int	iamremote, targetshouldbedirectory;
int	iamrecursive;
int	pflag;
int	forcenet;
struct	passwd *pwd;
int	userid;
int	port = 0;

struct buffer {
    unsigned int cnt;
    char	*buf;
};

struct buffer *allocbuf(struct buffer *, int, int);

#define	NULLBUF	(struct buffer *) 0
  
void 	error (char *fmt, ...)
#if !defined (__cplusplus) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7))
       __attribute__ ((__format__ (__printf__, 1, 2)))
#endif
     ;

#define	ga()	 	(void) rcmd_stream_write(rem, "", 1, 0)

int main(argc, argv)
     int argc;
     char **argv;
{
    char *targ, *host, *src;
    char *suser, *tuser, *thost;
    int i;
    unsigned int cmdsiz = 30;
    char buf[RCP_BUFSIZ], cmdbuf[30];
    char *cmd = cmdbuf;
    struct servent *sp;
    static char curhost[256];
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif
#ifdef KERBEROS
    krb5_flags authopts;
    krb5_error_code status;	
    int euid;
    char **orig_argv = save_argv(argc, argv);
    krb5_auth_context auth_context;
    enum kcmd_proto kcmd_proto = KCMD_PROTOCOL_COMPAT_HACK;

    status = krb5_init_context(&bsd_context);
    if (status) {
	    com_err(argv[0], status, "while initializing krb5");
	    exit(1);
    }
#endif

    pwd = getpwuid(userid = getuid());
    if (pwd == 0) {
	fprintf(stderr, "who are you?\n");
	exit(1);
    }
    
    for (argc--, argv++; argc > 0 && **argv == '-'; argc--, argv++) {
	(*argv)++;
	while (**argv) switch (*(*argv)++) {
	    
	  case 'r':
	    iamrecursive++;
	    break;
	    
	  case 'p':		/* preserve mtimes and atimes */
	    pflag++;
	    break;
	    
	  case 'D':
	    argc--, argv++;
	    if (argc == 0)
	      usage();
	    port = htons(atoi(*argv));
	    goto next_arg;

	  case 'N':
	    forcenet++;
	    break;

#ifdef KERBEROS
	  case 'x':
	    encryptflag++;
	    break;
	  case 'k':		/* Change kerberos realm */
	    argc--, argv++;
	    if (argc == 0) 
	      usage();
	    if(!(krb_realm = strdup(*argv))){
		fprintf(stderr, "rcp: Cannot malloc.\n");
		exit(1);
	    }
	    goto next_arg;
	  case 'c':		/* Change default ccache file */
	    argc--, argv++;
	    if (argc == 0) 
	      usage();
	    if(!(krb_cache = strdup(*argv))){
		fprintf(stderr, "rcp: Cannot malloc.\n");
		exit(1);
	    }
	    goto next_arg;
	  case 'C':		/* Change default config file */
	    argc--, argv++;
	    if (argc == 0) 
	      usage();
	    if(!(krb_config = strdup(*argv))){
		fprintf(stderr, "rcp: Cannot malloc.\n");
		exit(1);
	    }
	    goto next_arg;
	  case 'P':
	    if (!strcmp (*argv, "O"))
		kcmd_proto = KCMD_OLD_PROTOCOL;
	    else if (!strcmp (*argv, "N"))
		kcmd_proto = KCMD_NEW_PROTOCOL;
	    else
		usage ();
	    goto next_arg;
#endif /* KERBEROS */
	    /* The rest of these are not for users. */
	  case 'd':
	    targetshouldbedirectory = 1;
	    break;
	    
	  case 'f':		/* "from" */
	    iamremote = 1;
	    rcmd_stream_init_normal();
#if defined(KERBEROS)
	    if (encryptflag)
	      answer_auth(krb_config, krb_cache);
#endif /* KERBEROS */

	    (void) response();
	    source(--argc, ++argv);
	    exit(errs);
	    
	  case 't':		/* "to" */
	    iamremote = 1;
	    rcmd_stream_init_normal();
#if defined(KERBEROS)
	    if (encryptflag)
	      answer_auth(krb_config, krb_cache);
#endif /* KERBEROS */

	    sink(--argc, ++argv);
	    exit(errs);
	    
	  default:
	    usage();
	}
      next_arg: ;
    }
    
    if (argc < 2)
      usage();
    if (argc > 2)
      targetshouldbedirectory = 1;
    rem = -1;


    if (port == 0) {
#ifdef KERBEROS
      sp = getservbyname("kshell", "tcp");
#else
      sp = getservbyname("shell", "tcp");
#endif /* KERBEROS */
    
      if (sp == NULL) {
#ifdef KERBEROS
	fprintf(stderr, "rcp: kshell/tcp: unknown service\n");
	try_normal(orig_argv);
#else
	fprintf(stderr, "rcp: shell/tcp: unknown service\n");
	exit(1);
#endif /* KERBEROS */
      }
      port = sp->s_port;
    }

#ifdef KERBEROS
    if (krb_realm != NULL)
	cmdsiz += strlen(krb_realm);
    if (krb_cache != NULL)
	cmdsiz += strlen(krb_cache);
    if (krb_config != NULL)
	cmdsiz += strlen(krb_config);

    if ((cmd = (char *)malloc(cmdsiz)) == NULL) {
	fprintf(stderr, "rcp: Cannot malloc.\n");
	exit(1);
    }
    (void) sprintf(cmd, "%srcp %s%s%s%s%s%s%s%s%s",
		   encryptflag ? "-x " : "",

		   iamrecursive ? " -r" : "", pflag ? " -p" : "", 
		   targetshouldbedirectory ? " -d" : "",
		   krb_realm != NULL ? " -k " : "",
		   krb_realm != NULL ? krb_realm : "",
		   krb_cache != NULL ? " -c " : "",
		   krb_cache != NULL ? krb_cache : "",
		   krb_config != NULL ? " -C " : "",
		   krb_config != NULL ? krb_config : "");

#else /* !KERBEROS */
    (void) sprintf(cmd, "rcp%s%s%s",
		   iamrecursive ? " -r" : "", pflag ? " -p" : "", 
		   targetshouldbedirectory ? " -d" : "");
#endif /* KERBEROS */
    
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = lostconn;
    (void) sigaction(SIGPIPE, &sa, (struct sigaction *)0);
#else
    (void) signal(SIGPIPE, lostconn);
#endif
    targ = colon(argv[argc - 1]);
    
    /* Check if target machine is the current machine. */
    
    gethostname(curhost, sizeof(curhost));
    if (targ) {				/* ... to remote */
	*targ++ = 0;
	if (hosteq(argv[argc - 1], curhost)) {
	    
	    /* If so, pretend there wasn't even one given
	     * check for an argument of just "host:", it
	     * should become "."
	     */
	    
	    if (*targ == 0) {
		targ = ".";
		argv[argc - 1] = targ;
	    }
	    else
	      argv[argc - 1] = targ;
	    targ = 0;
	}
    }
    if (targ) {
	/* Target machine is some remote machine */
	if (*targ == 0)
	  targ = ".";
	thost = strchr(argv[argc - 1], '@');
	if (thost) {
	    *thost++ = 0;
	    tuser = argv[argc - 1];
	    if (*tuser == '\0')
	      tuser = NULL;
	    else if (!okname(tuser))
	      exit(1);
	} else {
	    thost = argv[argc - 1];
	    tuser = NULL;
	}
	for (i = 0; i < argc - 1; i++) {
	    src = colon(argv[i]);
	    if (src) {		/* remote to remote */
		*src++ = 0;
		if (*src == 0)
		  src = ".";
		host = strchr(argv[i], '@');
		if (host) {
		    *host++ = 0;
		    suser = argv[i];
		    if (*suser == '\0')
		      suser = pwd->pw_name;
		    else if (!okname(suser))
		      continue;
		    (void) sprintf(buf,
#if defined(hpux) || defined(__hpux)
				   "remsh %s -l %s -n %s %s '%s%s%s:%s'",
#else
				   "rsh %s -l %s -n %s %s '%s%s%s:%s'",
#endif
				   host, suser, cmd, src,
				   tuser ? tuser : "",
				   tuser ? "@" : "",
				   thost, targ);
	       } else
		   (void) sprintf(buf,
#if defined(hpux) || defined(__hpux)
				  "remsh %s -n %s %s '%s%s%s:%s'",
#else
				  "rsh %s -n %s %s '%s%s%s:%s'",
#endif
				   argv[i], cmd, src,
				   tuser ? tuser : "",
				   tuser ? "@" : "",
				   thost, targ);
		(void) susystem(buf);
	    } else {		/* local to remote */
		krb5_creds *cred;
		if (rem == -1) {
		    (void) sprintf(buf, "%s -t %s",
				   cmd, targ);
		    host = thost;
#ifdef KERBEROS
		    authopts = AP_OPTS_MUTUAL_REQUIRED;
		    status = kcmd(&sock, &host,
				  port,
				  pwd->pw_name,
				  tuser ? tuser :
				  pwd->pw_name,
				  buf,
				  0,
				  "host",
				  krb_realm,
				  &cred,  
				  0,  /* No seq # */
				  0,  /* No server seq # */
				  &local,
				  &foreign,
				  &auth_context, authopts,
				  0, /* Not any port # */
				  0,
				  &kcmd_proto);
		    if (status) {
			if (kcmd_proto == KCMD_NEW_PROTOCOL)
			    /* Don't fall back to less safe methods.  */
			    exit (1);
#ifdef KRB5_KRB4_COMPAT
			fprintf(stderr, "Trying krb4 rcp...\n");
			if (strncmp(buf, "-x rcp", 6) == 0)
			    memcpy(buf, "rcp -x", 6);
			status = k4cmd(&sock, &host, port,
				       pwd->pw_name,
				       tuser ? tuser : pwd->pw_name, buf,
				       0, &v4_ticket, "rcmd", krb_realm,
				       NULL, NULL, NULL,
				       &local, &foreign, 0L, 0);
			if (status)
			    try_normal(orig_argv);
			if (encryptflag)
			    v4_send_auth(host, krb_realm);
			rcmd_stream_init_krb4(v4_cred.session, encryptflag, 0,
					      0);
#else
			try_normal(orig_argv);
#endif
		    }
		    else {
			krb5_boolean similar;
			krb5_keyblock *key = &cred->keyblock;

			status = krb5_c_enctype_compare(bsd_context,
							ENCTYPE_DES_CBC_CRC,
							cred->keyblock.enctype,
							&similar);
			if (status)
			    try_normal(orig_argv); /* doesn't return */

			if (!similar) {
			    status = krb5_auth_con_getsendsubkey (bsd_context,
								  auth_context,
								  &key);
			    if ((status || !key) && encryptflag)
				try_normal(orig_argv);
			}
			if (key == 0)
			    key = &cred->keyblock;

			rcmd_stream_init_krb5(key, encryptflag, 0, 1,
					      kcmd_proto);
		    }
		    rem = sock;
#else
		    rem = rcmd(&host, port, pwd->pw_name,
			       tuser ? tuser : pwd->pw_name,
			       buf, 0);
		    if (rem < 0)
		      exit(1);
#endif /* KERBEROS */
		    if (response() < 0)
		      exit(1);
		}
		source(1, argv+i);
	    }
	}
    } else {				/* ... to local */
	if (targetshouldbedirectory)
	  verifydir(argv[argc - 1]);
	for (i = 0; i < argc - 1; i++) {
	    src = colon(argv[i]);
	    /* Check if source machine is current machine */
	    if (src) {
		*src++ = 0;
		if (hosteq(argv[i], curhost)) {
		    
		    /* If so, pretend src machine never given */
		    
		    if (*src == 0) {
			error("rcp: no path given in arg: %s:\n",
			      argv[i]);
			errs++;
			continue;
		    }
		    argv[i] = src;
		    src = 0;
		} else {
		    /* not equiv, return colon */
		    *(--src) = ':';
		}
	    }
	    if (src == 0) {		/* local to local */
		(void) sprintf(buf, "/bin/cp%s%s %s %s",
			       iamrecursive ? " -r" : "",
			       pflag ? " -p" : "",
			       argv[i], argv[argc - 1]);
		(void) susystem(buf);
	    } else {		/* remote to local */
		krb5_creds *cred;
		*src++ = 0;
		if (*src == 0)
		  src = ".";
		host = strchr(argv[i], '@');
		if (host) {
		    *host++ = 0;
		    suser = argv[i];
		    if (*suser == '\0')
		      suser = pwd->pw_name;
		    else if (!okname(suser))
		      continue;
		} else {
		    host = argv[i];
		    suser = pwd->pw_name;
		}
		(void) sprintf(buf, "%s -f %s", cmd, src);
#ifdef KERBEROS
		authopts = AP_OPTS_MUTUAL_REQUIRED;
		status = kcmd(&sock, &host,
			      port,
			      pwd->pw_name,  suser,
			      buf,
			      0,
			      "host",
			      krb_realm,
			      &cred,  
			      0,  /* No seq # */
			      0,  /* No server seq # */
			      (struct sockaddr_in *) 0,
			      &foreign,
			      &auth_context, authopts,
			      0, /* Not any port # */
			      0,
			      &kcmd_proto);
		if (status) {
			if (kcmd_proto == KCMD_NEW_PROTOCOL)
			    /* Don't fall back to less safe methods.  */
			    exit (1);
#ifdef KRB5_KRB4_COMPAT
			fprintf(stderr, "Trying krb4 rcp...\n");
			if (strncmp(buf, "-x rcp", 6) == 0)
			    memcpy(buf, "rcp -x", 6);
			status = k4cmd(&sock, &host, port,
				       pwd->pw_name, suser, buf,
				       0, &v4_ticket, "rcmd", krb_realm,
				       NULL, NULL, NULL,
				       &local, &foreign, 0L, 0);
			if (status)
			    try_normal(orig_argv);
			if (encryptflag)
			    v4_send_auth(host, krb_realm);
			rcmd_stream_init_krb4(v4_cred.session, encryptflag, 0,
					      0);
#else
			try_normal(orig_argv);
#endif
		} else {
		    krb5_keyblock *key = &cred->keyblock;

		    if (kcmd_proto == KCMD_NEW_PROTOCOL) {
			status = krb5_auth_con_getsendsubkey (bsd_context,
							      auth_context,
							      &key);
			if (status) {
			    com_err (argv[0], status,
				     "determining subkey for session");
			    exit (1);
			}
			if (!key) {
			    com_err (argv[0], 0,
				     "no subkey negotiated for connection");
			    exit (1);
			}
		    }

		    rcmd_stream_init_krb5(key, encryptflag, 0, 1, kcmd_proto);
		}
		rem = sock; 
				   
		euid = geteuid();
		if (euid == 0) {
		    if (setuid(0)) {
			perror("rcp setuid 0"); errs++; exit(errs);
		    }
		    if(krb5_seteuid(userid)) {
			perror("rcp seteuid user"); errs++; exit(errs);
		    }
		}
		sink(1, argv+argc-1);
		if (euid == 0) {
		    if(krb5_seteuid(0)) {
			perror("rcp seteuid 0"); errs++; exit(errs);
		    }
		}
#else
		rem = rcmd(&host, port, pwd->pw_name, suser,
			   buf, 0);
		if (rem < 0)
		  continue;
		rcmd_stream_init_normal();
#ifdef HAVE_SETREUID
		if (setreuid(0, userid)) {
		    perror("rcp setreuid 0,user"); errs++; exit(errs);
		}
		sink(1, argv+argc-1);
		if (setreuid(userid, 0)) {
		    perror("rcp setreuid user,0"); errs++; exit(errs);
		}
#else
		if (setuid(0)) {
		  perror("rcp setuid 0"); errs++; exit(errs);
		}
		if(seteuid(userid)) {
		  perror("rcp seteuid user"); errs++; exit(errs);
		}
		sink(1, argv+argc-1);
		if(seteuid(0)) {
		  perror("rcp seteuid 0"); errs++; exit(errs);
		}
#endif
#endif /* KERBEROS */
		(void) close(rem);
		rem = -1;
	    }
	}
    }
    exit(errs);
}



void verifydir(cp)
     char *cp;
{
    struct stat stb;
    
    if (stat(cp, &stb) >= 0) {
	if ((stb.st_mode & S_IFMT) == S_IFDIR)
	  return;
	errno = ENOTDIR;
    }
    error("rcp: %s: %s.\n", cp, error_message(errno));
    exit(1);
}



char *colon(cp)
     char *cp;
{
    
    while (*cp) {
	if (*cp == ':')
	  return (cp);
	if (*cp == '/')
	  return (0);
	cp++;
    }
    return (0);
}



int okname(cp0)
     char *cp0;
{
    register char *cp = cp0;
    register int c;
    
    do {
	c = *cp;
	if (c & 0200)
	  goto bad;
	if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-')
	  goto bad;
	cp++;
    } while (*cp);
    return (1);
  bad:
    fprintf(stderr, "rcp: invalid user name %s\n", cp0);
    return (0);
}



int susystem(s)
     char *s;
{
    int status;
    pid_t pid, w;
#ifdef POSIX_SIGNALS
    struct sigaction sa, isa, qsa;
#else
    register krb5_sigtype (bsd_context, *istat)(), (*qstat)();
#endif
    
    if ((pid = vfork()) == 0) {
	execl("/bin/sh", "sh", "-c", s, (char *)0);
	_exit(127);
    }

#ifdef POSIX_SIGNALS
    (void) sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGINT, &sa, &isa);
    (void) sigaction(SIGQUIT, &sa, &qsa);
#else
    istat = signal(SIGINT, SIG_IGN);
    qstat = signal(SIGQUIT, SIG_IGN);
#endif
    
#ifdef HAVE_WAITPID
    w = waitpid(pid, &status, 0);
#else
    while ((w = wait(&status)) != pid && w != -1) /*void*/ ;
#endif
    if (w == (pid_t)-1)
      status = -1;

#ifdef POSIX_SIGNALS
    (void) sigaction(SIGINT, &isa, (struct sigaction *)0);
    (void) sigaction(SIGQUIT, &qsa, (struct sigaction *)0);
#else    
    (void) signal(SIGINT, istat);
    (void) signal(SIGQUIT, qstat);
#endif
    
    return (status);
}

void source(argc, argv)
     int argc;
     char **argv;
{
    char *last, *name;
    struct stat stb;
    static struct buffer buffer;
    struct buffer *bp;
    int x, readerr, f;
    unsigned int amt;
    off_t i;
    char buf[RCP_BUFSIZ];
    
    for (x = 0; x < argc; x++) {
	name = argv[x];
	if ((f = open(name, 0)) < 0) {
	    error("rcp: %s: %s\n", name, error_message(errno));
	    continue;
	}
	if (fstat(f, &stb) < 0)
	  goto notreg;
	switch (stb.st_mode&S_IFMT) {
	    
	  case S_IFREG:
	    break;
	    
	  case S_IFDIR:
	    if (iamrecursive) {
		(void) close(f);
		rsource(name, &stb);
		continue;
	    }
	    /* fall into ... */
	  default:
	  notreg:
	    (void) close(f);
	    error("rcp: %s: not a plain file\n", name);
	    continue;
	}
	last = strrchr(name, '/');
	if (last == 0)
	  last = name;
	else
	  last++;
	if (pflag) {
	    /*
	     * Make it compatible with possible future
	     * versions expecting microseconds.
	     */
	    (void) sprintf(buf, "T%ld 0 %ld 0\n",
			   stb.st_mtime, stb.st_atime);
	    (void) rcmd_stream_write(rem, buf, strlen(buf), 0);
	    if (response() < 0) {
		(void) close(f);
		continue;
	    }
	}
	(void) sprintf(buf, "C%04o %ld %s\n",
		       (int) stb.st_mode&07777, (long ) stb.st_size, last);
	(void) rcmd_stream_write(rem, buf, strlen(buf), 0);
	if (response() < 0) {
	    (void) close(f);
	    continue;
	}
	if ((bp = allocbuf(&buffer, f, RCP_BUFSIZ)) == NULLBUF) {
	    (void) close(f);
	    continue;
	}
	readerr = 0;
	for (i = 0; i < stb.st_size; i += bp->cnt) {
	    amt = bp->cnt;
	    if (i + amt > stb.st_size)
	      amt = stb.st_size - i;
	    if (readerr == 0 && read(f, bp->buf, amt) != amt)
	      readerr = errno;
	    (void) rcmd_stream_write(rem, bp->buf, amt, 0);
	}
	(void) close(f);
	if (readerr == 0)
	  ga();
	else
	  error("rcp: %s: %s\n", name, error_message(readerr));
	(void) response();
    }
}



#ifndef USE_DIRENT_H
#include <sys/dir.h>
#else
#include <dirent.h>
#endif

void rsource(name, statp)
     char *name;
     struct stat *statp;
{
    DIR *d = opendir(name);
    char *last;
#ifdef USE_DIRENT_H
    struct dirent *dp;
#else
    struct direct *dp;
#endif
    char buf[RCP_BUFSIZ];
    char *bufv[1];
    
    if (d == 0) {
	error("rcp: %s: %s\n", name, error_message(errno));
	return;
    }
    last = strrchr(name, '/');
    if (last == 0)
      last = name;
    else
      last++;
    if (pflag) {
	(void) sprintf(buf, "T%ld 0 %ld 0\n",
		       statp->st_mtime, statp->st_atime);
	(void) rcmd_stream_write(rem, buf, strlen(buf), 0);
	if (response() < 0) {
	    closedir(d);
	    return;
	}
    }
    (void) sprintf(buf, "D%04lo %d %s\n", (long) statp->st_mode&07777, 0, 
		   last);
    (void) rcmd_stream_write(rem, buf, strlen(buf), 0);
    if (response() < 0) {
	closedir(d);
	return;
    }
    while ((dp = readdir(d)) != NULL) {
	if (dp->d_ino == 0)
	  continue;
	if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
	  continue;
	if (strlen(name) + 1 + strlen(dp->d_name) >= RCP_BUFSIZ - 1) {
	    error("%s/%s: Name too long.\n", name, dp->d_name);
	    continue;
	}
	(void) sprintf(buf, "%s/%s", name, dp->d_name);
	bufv[0] = buf;
	source(1, bufv);
    }
    closedir(d);
    (void) rcmd_stream_write(rem, "E\n", 2, 0);
    (void) response();
}



int response()
{
    char resp, c, rbuf[RCP_BUFSIZ], *cp = rbuf;
    if (rcmd_stream_read(rem, &resp, 1, 0) != 1)
      lostconn(0);
    switch (resp) {
	
      case 0:				/* ok */
	return (0);
	
      default:
	*cp++ = resp;
	/* fall into... */
      case 1:				/* error, followed by err msg */
      case 2:				/* fatal error, "" */
	do {
	    if (rcmd_stream_read(rem, &c, 1, 0) != 1)
	      lostconn(0);
	    *cp++ = c;
	} while (cp < &rbuf[RCP_BUFSIZ] && c != '\n');
	if (iamremote == 0)
	  (void) write(2, rbuf, (unsigned) (cp - rbuf));
	errs++;
	if (resp == 1)
	  return (-1);
	exit(1);
    }
    /*NOTREACHED*/
}



krb5_sigtype
  lostconn(signumber)
    int signumber;
{
    if (iamremote == 0)
      fprintf(stderr, "rcp: lost connection\n");
    exit(1);
}


#if !defined(HAVE_UTIMES)
#include <utime.h>
#include <sys/time.h>

/*
 * We emulate utimes() instead of utime() as necessary because
 * utimes() is more powerful than utime(), and rcp actually tries to
 * set the microsecond values; we don't want to take away
 * functionality unnecessarily.
 */
int utimes(file, tvp)
const char *file;
struct timeval *tvp;
{
	struct utimbuf times;

	times.actime = tvp[0].tv_sec;
	times.modtime = tvp[1].tv_sec;
	return(utime(file, &times));
}
#endif


void sink(argc, argv)
     int argc;
     char **argv;
{
    mode_t mode;
    mode_t mask = umask(0);
    off_t i, j;
    char *targ, *whopp, *cp;
    int of, wrerr, exists, first;
    off_t size;
    unsigned int amt, count;
    struct buffer *bp;
    static struct buffer buffer;
    struct stat stb;
    int targisdir = 0;
    char *myargv[1];
    char cmdbuf[RCP_BUFSIZ], nambuf[RCP_BUFSIZ];
    int setimes = 0;
    struct timeval tv[2];
#define atime	tv[0]
#define mtime	tv[1]
#define	SCREWUP(str)	{ whopp = str; goto screwup; }
    
    if (!pflag)
      (void) umask(mask);
    if (argc != 1) {
	error("rcp: ambiguous target\n");
	exit(1);
    }
    targ = *argv;
    if (targetshouldbedirectory)
      verifydir(targ);
    ga();
    if (stat(targ, &stb) == 0 && (stb.st_mode & S_IFMT) == S_IFDIR)
      targisdir = 1;
    for (first = 1; ; first = 0) {
	cp = cmdbuf;
	if (rcmd_stream_read(rem, cp, 1, 0) <= 0)
	  return;
	if (*cp++ == '\n')
	  SCREWUP("unexpected '\\n'");
	do {
	    if (rcmd_stream_read(rem, cp, 1, 0) != 1)
	      SCREWUP("lost connection");
	} while (*cp++ != '\n');
	*cp = 0;
	if (cmdbuf[0] == '\01' || cmdbuf[0] == '\02') {
	    if (iamremote == 0)
	      (void) write(2, cmdbuf+1, strlen(cmdbuf+1));
	    if (cmdbuf[0] == '\02')
	      exit(1);
	    errs++;
	    continue;
	}
	*--cp = 0;
	cp = cmdbuf;
	if (*cp == 'E') {
	    ga();
	    return;
	}
	
#define getnum(t) (t) = 0; while (isdigit((int) *cp)) (t) = (t) * 10 + (*cp++ - '0');
	if (*cp == 'T') {
	    setimes++;
	    cp++;
	    getnum(mtime.tv_sec);
	    if (*cp++ != ' ')
	      SCREWUP("mtime.sec not delimited");
	    getnum(mtime.tv_usec);
	    if (*cp++ != ' ')
	      SCREWUP("mtime.usec not delimited");
	    getnum(atime.tv_sec);
	    if (*cp++ != ' ')
	      SCREWUP("atime.sec not delimited");
	    getnum(atime.tv_usec);
	    if (*cp++ != '\0')
	      SCREWUP("atime.usec not delimited");
	    ga();
	    continue;
	}
	if (*cp != 'C' && *cp != 'D') {
	    /*
	     * Check for the case "rcp remote:foo\* local:bar".
	     * In this case, the line "No match." can be returned
	     * by the shell before the rcp command on the remote is
	     * executed so the ^Aerror_message convention isn't
	     * followed.
	     */
	    if (first) {
		error("%s\n", cp);
		exit(1);
	    }
	    SCREWUP("expected control record");
	}
	cp++;
	mode = 0;
	for (; cp < cmdbuf+5; cp++) {
	    if (*cp < '0' || *cp > '7')
	      SCREWUP("bad mode");
	    mode = (mode << 3) | (*cp - '0');
	}
	if (*cp++ != ' ')
	  SCREWUP("mode not delimited");
	size = 0;
	while (isdigit((int) *cp))
	  size = size * 10 + (*cp++ - '0');
	if (*cp++ != ' ')
	  SCREWUP("size not delimited");
	if (targisdir) {
          if(strlen(targ) + strlen(cp) + 2 >= sizeof(nambuf))
	    SCREWUP("target name too long");
	  (void) sprintf(nambuf, "%s%s%s", targ,
			 *targ ? "/" : "", cp);
	} else {
	  if (strlen(targ) + 1 >= sizeof (nambuf))
	    SCREWUP("target name too long");
	  (void) strncpy(nambuf, targ, sizeof(nambuf) - 1);
	}
	nambuf[sizeof(nambuf) - 1] = '\0';
	exists = stat(nambuf, &stb) == 0;
	if (cmdbuf[0] == 'D') {
	    if (exists) {
		if ((stb.st_mode&S_IFMT) != S_IFDIR) {
		    errno = ENOTDIR;
		    goto bad;
		}
		if (pflag)
		  (void) chmod(nambuf, mode);
	    } else if (mkdir(nambuf, mode) < 0)
	      goto bad;
	    myargv[0] = nambuf;
	    sink(1, myargv);
	    if (setimes) {
		setimes = 0;
		if (utimes(nambuf, tv) < 0)
		  error("rcp: can't set times on %s: %s\n",
			nambuf, error_message(errno));
	    }
	    continue;
	}
	if ((of = open(nambuf, O_WRONLY|O_CREAT, mode)) < 0) {
	  bad:
	    error("rcp: %s: %s\n", nambuf, error_message(errno));
	    continue;
	}
	if (exists && pflag) {
#ifdef NOFCHMOD
	    (void) chmod(nambuf, mode);
#else
	    (void) fchmod(of, mode);
#endif
	}
	ga();
	if ((bp = allocbuf(&buffer, of, RCP_BUFSIZ)) == NULLBUF) {
	    (void) close(of);
	    continue;
	}
	cp = bp->buf;
	count = 0;
	wrerr = 0;
	for (i = 0; i < size; i += RCP_BUFSIZ) {
	    amt = RCP_BUFSIZ;
	    if (i + amt > size)
	      amt = size - i;
	    count += amt;
	    do {
		j = rcmd_stream_read(rem, cp, amt, 0);
		if (j <= 0) {
		    if (j == 0)
		      error("rcp: dropped connection");
		    else
		      error("rcp: %s\n", error_message(errno));
		    exit(1);
		}
		amt -= j;
		cp += j;
	    } while (amt > 0);
	    if (count == bp->cnt) {
		if (wrerr == 0 &&
		    write(of, bp->buf, count) != count)
		  wrerr++;
		count = 0;
		cp = bp->buf;
	    }
	}
	if (count != 0 && wrerr == 0 &&
	    write(of, bp->buf, count) != count)
	  wrerr++;
	if (ftruncate(of, size))
	  error("rcp: can't truncate %s: %s\n", nambuf, error_message(errno));
	(void) close(of);
	(void) response();
	if (setimes) {
	    setimes = 0;
	    if (utimes(nambuf, tv) < 0)
	      error("rcp: can't set times on %s: %s\n",
		    nambuf, error_message(errno));
	}				   
	if (wrerr)
	  error("rcp: %s: %s\n", nambuf, error_message(errno));
	else
	  ga();
    }
  screwup:
    error("rcp: protocol screwup: %s\n", whopp);
    exit(1);
}



struct buffer *allocbuf(bp, fd, blksize)
     struct buffer *bp;
     int fd, blksize;
{
    struct stat stb;
    int size;
    
    if (fstat(fd, &stb) < 0) {
	error("rcp: fstat: %s\n", error_message(errno));
	return (NULLBUF);
    }

    size = blksize;
    if (bp->cnt < size) {
	if (bp->buf != 0)
	  free(bp->buf);
	bp->buf = (char *)malloc((unsigned) size);
	if (bp->buf == 0) {
	    error("rcp: malloc: out of memory\n");
	    return (NULLBUF);
	}
    }
    bp->cnt = size;
    return (bp);
}

void
#ifdef HAVE_STDARG_H
error(char *fmt, ...)
#else
/*VARARGS1*/
error(fmt, va_alist)
     char *fmt;
     va_dcl
#endif
{
    va_list ap;
    char buf[RCP_BUFSIZ], *cp = buf;

#ifdef HAVE_STDARG_H
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    errs++;
    *cp++ = 1;
    (void) vsprintf(cp, fmt, ap);
    va_end(ap);

    if (iamremote)
      (void) rcmd_stream_write(rem, buf, strlen(buf), 0);
    else
      (void) write(2, buf+1, strlen(buf+1));
}



void usage()
{
#ifdef KERBEROS
    fprintf(stderr,
	    "Usage: \trcp [-PN | -PO] [-p] [-x] [-k realm] f1 f2; or:\n\trcp [-PN | -PO] [-r] [-p] [-x] [-k realm] f1 ... fn d2\n");
#else
    fputs("usage: rcp [-p] f1 f2; or: rcp [-rp] f1 ... fn d2\n", stderr);
#endif
    exit(1);
}



int hosteq(h1, h2)
     char *h1, *h2;
{
    struct hostent *h_ptr;
    char hname1[256];
    
    if (forcenet)
      return(0);

    /* get the official names for the two hosts */
    
    if ((h_ptr = gethostbyname(h1)) == NULL)
      return(0);
    strncpy(hname1, h_ptr->h_name, sizeof (hname1));
    hname1[sizeof (hname1) - 1] = '\0';
    if ((h_ptr = gethostbyname(h2)) == NULL)
      return(0);
    
    /*return if they are equal (strcmp returns 0 for equal - I return 1) */
    
    return(!strcmp(hname1, h_ptr->h_name));
}



#ifdef KERBEROS
void try_normal(argv)
     char **argv;
{
    register int i;
#ifndef     KRB5_ATHENA_COMPAT
    if (!encryptflag)
#endif
	{
	fprintf(stderr,"trying normal rcp (%s)\n", UCB_RCP);
	fflush(stderr);
	/* close all but stdin, stdout, stderr */
	for (i = getdtablesize(); i > 2; i--)
	  (void) close(i);
	execv(UCB_RCP, argv);
	perror("exec");
    }
    exit(1);
}



char **save_argv(argc, argv)
     int argc;
     char **argv;
{
    register int i;
    
    char **local_argv = (char **)calloc((unsigned) argc+1,
					(unsigned) sizeof(char *));
    /* allocate an extra pointer, so that it is initialized to NULL
       and execv() will work */
    for (i = 0; i < argc; i++)
      local_argv[i] = strsave(argv[i]);
    return(local_argv);
}



#ifdef unicos61
#define SIZEOF_INADDR  SIZEOF_in_addr
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif


/* This function is mostly vestigial, since under normal operation
 * the -x flag doesn't get set for the server process for encrypted
 * rcp.  It only gets called by beta clients attempting user-to-user
 * authentication. */
void
  answer_auth(config_file, ccache_file)
    char *config_file;
    char *ccache_file;
{
    krb5_data pname_data, msg;
    krb5_creds creds, *new_creds;
    krb5_ccache cc;
    krb5_error_code status;
    krb5_auth_context auth_context = NULL;
    
    if (config_file) {
    	const char * filenames[2];
    	filenames[1] = NULL;
    	filenames[0] = config_file;
    	if ((status = krb5_set_config_files(bsd_context, filenames)))
	    exit(1);
    }
    
    memset ((char*)&creds, 0, sizeof(creds));

    if ((status = krb5_read_message(bsd_context, (krb5_pointer)&rem,
				    &pname_data)))
	exit(1);
    
    if ((status = krb5_read_message(bsd_context, (krb5_pointer) &rem,
				    &creds.second_ticket)))
	exit(1);
    
    if (ccache_file == NULL) {
    	if ((status = krb5_cc_default(bsd_context, &cc)))
	    exit(1);
    } else {
	if ((status = krb5_cc_resolve(bsd_context, ccache_file, &cc)))
	    exit(1);
    }

    if ((status = krb5_cc_get_principal(bsd_context, cc, &creds.client)))
	exit(1);

    if ((status = krb5_parse_name(bsd_context, pname_data.data,
				  &creds.server)) )
	exit(1);

    krb5_free_data_contents(bsd_context, &pname_data);

    if ((status = krb5_get_credentials(bsd_context, KRB5_GC_USER_USER, cc, 
				       &creds, &new_creds)))
	exit(1);

    if ((status = krb5_mk_req_extended(bsd_context, &auth_context,
				       AP_OPTS_USE_SESSION_KEY,
				       NULL, new_creds, &msg)))
	exit(1);
    
    if ((status = krb5_write_message(bsd_context, (krb5_pointer) &rem,
				     &msg))) {
    	krb5_free_data_contents(bsd_context, &msg);
	exit(1);
    }
    
    rcmd_stream_init_krb5(&new_creds->keyblock, encryptflag, 0, 0,
			  KCMD_OLD_PROTOCOL);
    
    /* cleanup */
    krb5_free_cred_contents(bsd_context, &creds);
    krb5_free_creds(bsd_context, new_creds);
    krb5_free_data_contents(bsd_context, &msg);

    return;
}



char storage[2*RCP_BUFSIZ];		/* storage for the decryption */
int nstored = 0;
char *store_ptr = storage;

#ifdef KRB5_KRB4_COMPAT
void
v4_send_auth(host,realm)
char *host;
char *realm;
{
	long authopts;

	if ((realm == NULL) || (realm[0] == '\0'))
	     realm = krb_realmofhost(host);
	/* this needs to be sent again, because the
	   rcp process needs the key.  the rshd has
	   grabbed the first one. */
	authopts = KOPT_DO_MUTUAL;
	if ((rem = krb_sendauth(authopts, sock, &v4_ticket,
				"rcmd", host,
				realm, (unsigned long) getpid(),
				&v4_msg_data,
				&v4_cred, v4_schedule,
				&local,
				&foreign,
				"KCMDV0.1")) != KSUCCESS) {
		fprintf(stderr,
			"krb_sendauth mutual fail: %s\n",
			krb_get_err_text(rem));
		exit(1);
	}
}
#endif /* KRB5_KRB4_COMPAT */

#endif /* KERBEROS */
