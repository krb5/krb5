/*
 *	$Source$
 *	$Header$
 */

#ifndef lint
static char *rcsid_rcp_c = "$Header$";
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
static char sccsid[] = "@(#)rcp.c	5.10 (Berkeley) 9/20/88";
#endif /* not lint */

     /*
      * rcp
      */
#include <sys/param.h>
#ifndef _TYPES_
#include <sys/types.h>
#define _TYPES_
#endif
#include <sys/file.h>
#ifdef CRAY
#include <sys/fcntl.h>
#endif
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
     
#ifdef KERBEROS
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/mit-des.h>
#include <krb5/los-proto.h>

#include <com_err.h>
     
#ifdef BUFSIZ
#undef BUFSIZ
#endif
#define BUFSIZ 4096
     
int sock;
struct sockaddr_in foreign;	   /* set up by kcmd used by send_auth */
char *krb_realm = (char *)0;
char des_inbuf[2*BUFSIZ];          /* needs to be > largest read size */
char des_outbuf[2*BUFSIZ];         /* needs to be > largest write size */
krb5_data desinbuf,desoutbuf;
krb5_encrypt_block eblock;         /* eblock for encrypt/decrypt */
krb5_keyblock *session_key;	   /* static key for session */

void	try_normal();
char	**save_argv(), *strsave();
int	des_write(), des_read();
void	send_auth(), answer_auth();
int	encryptflag = 0;

#define	UCB_RCP	"/bin/rcp"

#ifdef CRAY
#ifndef BITS64
#define BITS64
#endif
#endif

#else /* !KERBEROS */
#define	des_read	read
#define	des_write	write
#endif /* KERBEROS */

int	rem;
char	*colon(), *index(), *rindex(), *strcpy();
int	errs;
krb5_sigtype	lostconn();
int	errno;
extern char	*sys_errlist[];
int	iamremote, targetshouldbedirectory;
int	iamrecursive;
int	pflag;
struct	passwd *pwd;
#ifndef convex
struct	passwd *getpwuid();
#endif
int	userid;
int	port;

struct buffer {
    int	cnt;
    char	*buf;
} *allocbuf();

#define	NULLBUF	(struct buffer *) 0
  
  /*VARARGS*/
  int	error();

#define	ga()	 	(void) des_write(rem, "", 1)


main(argc, argv)
     int argc;
     char **argv;
{
    char *targ, *host, *src;
    char *suser, *tuser, *thost;
    int i;
    char buf[BUFSIZ], cmd[16];
    struct servent *sp;
    static char curhost[256];
#ifdef KERBEROS
    krb5_flags authopts;
    krb5_error_code status;	
    char **orig_argv = save_argv(argc, argv);
    
    sp = getservbyname("kshell", "tcp");
    krb5_init_ets();
    desinbuf.data = des_inbuf;
    desoutbuf.data = des_outbuf;    /* Set up des buffers */
    
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
	    
#ifdef KERBEROS
	  case 'x':
	    encryptflag++;
	    break;
	  case 'k':		/* Change kerberos realm */
	    argc--, argv++;
	    if (argc == 0) 
	      usage();
	    if(!(krb_realm = (char *)malloc(strlen(*argv) + 1))){
		fprintf(stderr, "rcp: Cannot malloc.\n");
		exit(1);
	    }
	    strcpy(krb_realm, *argv);	
	    goto next_arg;
#endif /* KERBEROS */
	    /* The rest of these are not for users. */
	  case 'd':
	    targetshouldbedirectory = 1;
	    break;
	    
	  case 'f':		/* "from" */
	    iamremote = 1;
#if defined(KERBEROS)
	    if (encryptflag)
	      answer_auth();
#endif /* KERBEROS */
	    (void) response();
	    source(--argc, ++argv);
	    exit(errs);
	    
	  case 't':		/* "to" */
	    iamremote = 1;
#if defined(KERBEROS) 
	    if (encryptflag)
	      answer_auth();
#endif /* KERBEROS */
	    sink(--argc, ++argv);
	    exit(errs);
	    
	  default:
	    usage();
	}
#ifdef KERBEROS
      next_arg: ;
#endif /* KERBEROS */
    }
    
    if (argc < 2)
      usage();
    if (argc > 2)
      targetshouldbedirectory = 1;
    rem = -1;
#ifdef KERBEROS
    (void) sprintf(cmd, "rcp%s%s%s%s",
		   iamrecursive ? " -r" : "", pflag ? " -p" : "", 
		   encryptflag ? " -x" : "",
		   targetshouldbedirectory ? " -d" : "");
#else /* !KERBEROS */
    
    (void) sprintf(cmd, "rcp%s%s%s",
		   iamrecursive ? " -r" : "", pflag ? " -p" : "", 
		   targetshouldbedirectory ? " -d" : "");
#endif /* KERBEROS */
    
    (void) signal(SIGPIPE, lostconn);
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
	thost = index(argv[argc - 1], '@');
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
		host = index(argv[i], '@');
		if (host) {
		    *host++ = 0;
		    suser = argv[i];
		    if (*suser == '\0')
		      suser = pwd->pw_name;
		    else if (!okname(suser))
		      continue;
#ifdef hpux
		    (void) sprintf(buf, "remsh %s -l %s -n %s %s '%s%s%s:%s'",
#else
		    (void) sprintf(buf, "rsh %s -l %s -n %s %s '%s%s%s:%s'",
#endif
				   host, suser, cmd, src,
				   tuser ? tuser : "",
				   tuser ? "@" : "",
				   thost, targ);
	       } else
#ifdef hpux
		   (void) sprintf(buf, "remsh %s -n %s %s '%s%s%s:%s'",
#else
		    (void) sprintf(buf, "rsh %s -n %s %s '%s%s%s:%s'",
#endif
				   argv[i], cmd, src,
				   tuser ? tuser : "",
				   tuser ? "@" : "",
				   thost, targ);
		(void) susystem(buf);
	    } else {		/* local to remote */
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
				  0,  /* No return cred */
				  0,  /* No seq # */
				  0,  /* No server seq # */
				  (struct sockaddr_in *) 0,
				  &foreign,
				  authopts);
		    if (status) {
			fprintf(stderr,
				"%s: kcmd to host %s failed - %s\n",
				orig_argv[0], host,
				error_message(status));
			try_normal(orig_argv);
		    }
		    else {
			rem = sock; 
			if (encryptflag)
			  send_auth();
		    }
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
		*src++ = 0;
		if (*src == 0)
		  src = ".";
		host = index(argv[i], '@');
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
			      0,  /* No return cred */
			      0,  /* No seq # */
			      0,  /* No server seq # */
			      (struct sockaddr_in *) 0,
			      &foreign,
			      authopts);
		if (status) {
		    fprintf(stderr,
			    "%s: kcmd to host %s failed - %s\n",
			    orig_argv[0], host,
			    error_message(status));
		    try_normal(orig_argv);
		    
		} else {
		    rem = sock; 
		    if (encryptflag)
		      send_auth();
		}
		sink(1, argv+argc-1);
#else
		rem = rcmd(&host, port, pwd->pw_name, suser,
			   buf, 0);
		if (rem < 0)
		  continue;
		(void) setreuid(0, userid);
		sink(1, argv+argc-1);
		(void) setreuid(userid, 0);
#endif /* KERBEROS */
		(void) close(rem);
		rem = -1;
	    }
	}
    }
    exit(errs);
}



verifydir(cp)
     char *cp;
{
    struct stat stb;
    
    if (stat(cp, &stb) >= 0) {
	if ((stb.st_mode & S_IFMT) == S_IFDIR)
	  return;
	errno = ENOTDIR;
    }
    error("rcp: %s: %s.\n", cp, sys_errlist[errno]);
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



okname(cp0)
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



susystem(s)
     char *s;
{
    int status, pid, w;
    register krb5_sigtype (*istat)(), (*qstat)();
    
    if ((pid = vfork()) == 0) {
	execl("/bin/sh", "sh", "-c", s, (char *)0);
	_exit(127);
    }
    istat = signal(SIGINT, SIG_IGN);
    qstat = signal(SIGQUIT, SIG_IGN);
    while ((w = wait(&status)) != pid && w != -1)
      ;
    if (w == -1)
      status = -1;
    (void) signal(SIGINT, istat);
    (void) signal(SIGQUIT, qstat);
    return (status);
}



source(argc, argv)
     int argc;
     char **argv;
{
    char *last, *name;
    struct stat stb;
    static struct buffer buffer;
    struct buffer *bp;
    int x, readerr, f, amt;
    off_t i;
    char buf[BUFSIZ];
    
    for (x = 0; x < argc; x++) {
	name = argv[x];
	if ((f = open(name, 0)) < 0) {
	    error("rcp: %s: %s\n", name, sys_errlist[errno]);
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
	last = rindex(name, '/');
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
	    (void) des_write(rem, buf, strlen(buf));
	    if (response() < 0) {
		(void) close(f);
		continue;
	    }
	}
	(void) sprintf(buf, "C%04o %ld %s\n",
		       stb.st_mode&07777, stb.st_size, last);
	(void) des_write(rem, buf, strlen(buf));
	if (response() < 0) {
	    (void) close(f);
	    continue;
	}
	if ((bp = allocbuf(&buffer, f, BUFSIZ)) == NULLBUF) {
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
	    (void) des_write(rem, bp->buf, amt);
	}
	(void) close(f);
	if (readerr == 0)
	  ga();
	else
	  error("rcp: %s: %s\n", name, sys_errlist[readerr]);
	(void) response();
    }
}



#if defined(SYSV) && !defined(sysvimp)
#include <dirent.h>
#else
#ifdef sysvimp
#include <ufs/fsdir.h>
#else
#include <sys/dir.h>
#endif
#endif

rsource(name, statp)
     char *name;
     struct stat *statp;
{
    DIR *d = opendir(name);
    char *last;
#if defined(SYSV) && !defined(sysvimp)
    struct dirent *dp;
#else
    struct direct *dp;
#endif
    char buf[BUFSIZ];
    char *bufv[1];
    
    if (d == 0) {
	error("rcp: %s: %s\n", name, sys_errlist[errno]);
	return;
    }
    last = rindex(name, '/');
    if (last == 0)
      last = name;
    else
      last++;
    if (pflag) {
	(void) sprintf(buf, "T%ld 0 %ld 0\n",
		       statp->st_mtime, statp->st_atime);
	(void) des_write(rem, buf, strlen(buf));
	if (response() < 0) {
	    closedir(d);
	    return;
	}
    }
    (void) sprintf(buf, "D%04o %d %s\n", statp->st_mode&07777, 0, last);
    (void) des_write(rem, buf, strlen(buf));
    if (response() < 0) {
	closedir(d);
	return;
    }
    while (dp = readdir(d)) {
	if (dp->d_ino == 0)
	  continue;
	if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
	  continue;
	if (strlen(name) + 1 + strlen(dp->d_name) >= BUFSIZ - 1) {
	    error("%s/%s: Name too long.\n", name, dp->d_name);
	    continue;
	}
	(void) sprintf(buf, "%s/%s", name, dp->d_name);
	bufv[0] = buf;
	source(1, bufv);
    }
    closedir(d);
    (void) des_write(rem, "E\n", 2);
    (void) response();
}



response()
{
    char resp, c, rbuf[BUFSIZ], *cp = rbuf;
    if (des_read(rem, &resp, 1) != 1)
      lostconn();
    switch (resp) {
	
      case 0:				/* ok */
	return (0);
	
      default:
	*cp++ = resp;
	/* fall into... */
      case 1:				/* error, followed by err msg */
      case 2:				/* fatal error, "" */
	do {
	    if (des_read(rem, &c, 1) != 1)
	      lostconn();
	    *cp++ = c;
	} while (cp < &rbuf[BUFSIZ] && c != '\n');
	if (iamremote == 0)
	  (void) write(2, rbuf, cp - rbuf);
	errs++;
	if (resp == 1)
	  return (-1);
	exit(1);
    }
    /*NOTREACHED*/
}



krb5_sigtype
  lostconn()
{
    if (iamremote == 0)
      fprintf(stderr, "rcp: lost connection\n");
    exit(1);
}



sink(argc, argv)
     int argc;
     char **argv;
{
    off_t i, j;
    char *targ, *whopp, *cp;
    int of, mode, wrerr, exists, first, count, amt, size;
    struct buffer *bp;
    static struct buffer buffer;
    struct stat stb;
    int targisdir = 0;
    int mask = umask(0);
    char *myargv[1];
    char cmdbuf[BUFSIZ], nambuf[BUFSIZ];
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
	if (des_read(rem, cp, 1) <= 0)
	  return;
	if (*cp++ == '\n')
	  SCREWUP("unexpected '\\n'");
	do {
	    if (des_read(rem, cp, 1) != 1)
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
	
#define getnum(t) (t) = 0; while (isdigit(*cp)) (t) = (t) * 10 + (*cp++ - '0');
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
	while (isdigit(*cp))
	  size = size * 10 + (*cp++ - '0');
	if (*cp++ != ' ')
	  SCREWUP("size not delimited");
	if (targisdir)
	  (void) sprintf(nambuf, "%s%s%s", targ,
			 *targ ? "/" : "", cp);
	else
	  (void) strcpy(nambuf, targ);
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
			nambuf, sys_errlist[errno]);
	    }
	    continue;
	}
	if ((of = open(nambuf, O_WRONLY|O_CREAT, mode)) < 0) {
	  bad:
	    error("rcp: %s: %s\n", nambuf, sys_errlist[errno]);
	    continue;
	}
	if (exists && pflag)
#ifdef NOFCHMOD
	  (void) chmod(nambuf, mode);
#else
	(void) fchmod(of, mode);
#endif
	ga();
	if ((bp = allocbuf(&buffer, of, BUFSIZ)) == NULLBUF) {
	    (void) close(of);
	    continue;
	}
	cp = bp->buf;
	count = 0;
	wrerr = 0;
	for (i = 0; i < size; i += BUFSIZ) {
	    amt = BUFSIZ;
	    if (i + amt > size)
	      amt = size - i;
	    count += amt;
	    do {
		j = des_read(rem, cp, amt);
		if (j <= 0) {
		    if (j == 0)
		      error("rcp: dropped connection");
		    else
		      error("rcp: %s\n",
			    sys_errlist[errno]);
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
	  error("rcp: can't truncate %s: %s\n",
		nambuf, sys_errlist[errno]);
	(void) close(of);
	(void) response();
	if (setimes) {
	    setimes = 0;
	    if (utimes(nambuf, tv) < 0)
	      error("rcp: can't set times on %s: %s\n",
		    nambuf, sys_errlist[errno]);
	}				   
	if (wrerr)
	  error("rcp: %s: %s\n", nambuf, sys_errlist[errno]);
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
	error("rcp: fstat: %s\n", sys_errlist[errno]);
	return (NULLBUF);
    }
#ifdef NOROUNDUP
    size = 0;
#else
    size = roundup(stb.st_blksize, blksize);
#endif
    if (size == 0)
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



/*VARARGS1*/
error(fmt, a1, a2, a3, a4, a5)
     char *fmt;
     int a1, a2, a3, a4, a5;
{
    char buf[BUFSIZ], *cp = buf;
    
    errs++;
    *cp++ = 1;
    (void) sprintf(cp, fmt, a1, a2, a3, a4, a5);
    (void) des_write(rem, buf, strlen(buf));
    if (iamremote == 0)
      (void) write(2, buf+1, strlen(buf+1));
}



usage()
{
#ifdef KERBEROS
    fprintf(stderr,
	    "Usage: \trcp [-p] [-x] [-k realm] f1 f2; or:\n\trcp [-r] [-p] [-x] [-k realm] f1 ... fn d2\n");
#else /* !KERBEROS */
    fputs("usage: rcp [-p] f1 f2; or: rcp [-rp] f1 ... fn d2\n", stderr);
#endif
    exit(1);
}



hosteq(h1, h2)
     char *h1, *h2;
{
    struct hostent *h_ptr;
    char hname1[256];
    
    /* get the official names for the two hosts */
    
    if ((h_ptr = gethostbyname(h1)) == NULL)
      return(0);
    strcpy(hname1, h_ptr->h_name);
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
    
    if (!encryptflag) {
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

krb5_error_code tgt_keyproc(DECLARG(krb5_pointer, keyprocarg),
			    DECLARG(krb5_principal, principal),
			    DECLARG(krb5_kvno, vno),
			    DECLARG(krb5_keyblock **, key))
     OLDDECLARG(krb5_pointer, keyprocarg)
     OLDDECLARG(krb5_principal, principal)
     OLDDECLARG(krb5_kvno, vno)
     OLDDECLARG(krb5_keyblock **, key)
{
    krb5_creds *creds = (krb5_creds *)keyprocarg;
    
    return krb5_copy_keyblock(&creds->keyblock, key);
}



void send_auth()
{
    int sin_len;
    char *princ;          /* principal in credentials cache */
    krb5_ccache cc;
    krb5_creds creds;
    krb5_principal sprinc;                /* principal of server */
    krb5_data reply, msg, princ_data;
    krb5_tkt_authent *authdat;
    krb5_error_code status;
    krb5_address faddr;
    
    
    
    if (status = krb5_cc_default(&cc)){
	fprintf(stderr,"rcp: send_auth failed krb5_cc_default : %s\n",
		error_message(status));
	exit(1);
    }
    
    memset ((char*)&creds, 0, sizeof(creds));
    
    if (status = krb5_cc_get_principal(cc, &creds.client)){
	fprintf(stderr,
		"rcp: send_auth failed krb5_cc_get_principal : %s\n",
		error_message(status));
	krb5_cc_close(cc);
	exit(1);
    }
    
    if (status = krb5_unparse_name(creds.client, &princ)){
	fprintf(stderr,"rcp: send_auth failed krb5_parse_name : %s\n",
		error_message(status));
	krb5_cc_close(cc);
	exit(1);
    }
    if (status = krb5_build_principal_ext(&sprinc,
					  krb5_princ_realm(creds.client)->length,
					  krb5_princ_realm(creds.client)->data,
					  6, "krbtgt",
					  krb5_princ_realm(creds.client)->length,
					  krb5_princ_realm(creds.client)->data,
					  0)){
	fprintf(stderr,
		"rcp: send_auth failed krb5_build_principal_ext : %s\n",
		error_message(status));
	krb5_cc_close(cc);
	exit(1);
    }
    
    creds.server = sprinc;
    
    /* Get TGT from credentials cache */
    if (status = krb5_get_credentials(KRB5_GC_CACHED, cc, &creds)){
	fprintf(stderr,
                "rcp: send_auth failed krb5_get_credentials: %s\n",
		error_message(status));
	krb5_cc_close(cc);
	exit(1);
    }
    krb5_cc_close(cc);
    
    krb5_free_principal(sprinc);          /* creds.server is replaced
					     upon retrieval */
    
    
    princ_data.data = princ;
    princ_data.length = strlen(princ_data.data) + 1; /* include null 
							terminator for
							server's convenience */
    status = krb5_write_message((krb5_pointer) &rem, &princ_data);
    if (status){
	fprintf(stderr,
                "rcp: send_auth failed krb5_write_message: %s\n",
		error_message(status));
	exit(1);
    }
    krb5_xfree(princ);
    status = krb5_write_message((krb5_pointer) &rem, &creds.ticket);
    if (status){
	fprintf(stderr,
                "rcp: send_auth failed krb5_write_message: %s\n",
		error_message(status));
	exit(1);
    }
    
    status = krb5_read_message((krb5_pointer) &rem, &reply);
    if (status){
	fprintf(stderr,
                "rcp: send_auth failed krb5_read_message: %s\n",
		error_message(status));
	exit(1);
    }
    
    sin_len = SIZEOF_INADDR;
    faddr.addrtype = foreign.sin_family;
    faddr.length = SIZEOF_INADDR;
    faddr.contents = (krb5_octet *) &foreign.sin_addr;
    
    /* read the ap_req to get the session key */
    status = krb5_rd_req(&reply,
			 0,               /* don't know server's name... */
			 &faddr,
			 0,               /* no fetchfrom */
			 tgt_keyproc,
			 (krb5_pointer)&creds, /* credentials as arg to
						  keyproc */
			 0,               /* no rcache for the moment XXX */
			 &authdat);
    krb5_xfree(reply.data);
    if (status) {
	fprintf(stderr, "rcp: send_auth failed krb5_rd_req: %s\n",
		error_message(status));
	exit(1);
    }
    
    krb5_copy_keyblock(authdat->ticket->enc_part2->session,&session_key);
    krb5_free_tkt_authent(authdat);
    krb5_free_cred_contents(&creds);
    
    krb5_use_keytype(&eblock, session_key->keytype);
    if ( status = krb5_process_key(&eblock, 
				   session_key)){
	fprintf(stderr, "rcp: send_auth failed krb5_process_key: %s\n",
		error_message(status));
	exit(1);
    }
    
}



void
  answer_auth()
{
    krb5_data pname_data, msg;
    krb5_creds creds;
    krb5_ccache cc;
    krb5_error_code status;
    extern krb5_flags krb5_kdc_default_options;
    
    
    memset ((char*)&creds, 0, sizeof(creds));
    
    if (status = krb5_read_message((krb5_pointer) &rem, &pname_data)) {
	exit(1);
    }
    
    if (status = krb5_read_message((krb5_pointer) &rem,
				   &creds.second_ticket)) {
	exit(1);
    }
    
    if (status = krb5_cc_default(&cc)){
	exit(1);
    }
    
    if (status = krb5_cc_get_principal(cc, &creds.client)){
	krb5_cc_destroy(cc);
	krb5_cc_close(cc);
	exit(1);
    }
    
    if (status = krb5_parse_name(pname_data.data, &creds.server)){
	krb5_cc_destroy(cc);
	krb5_cc_close(cc);
	exit(1);
    }
    krb5_xfree(pname_data.data);
    
    if (status = krb5_get_credentials(KRB5_GC_USER_USER, cc, &creds)){
	krb5_cc_destroy(cc);
	krb5_cc_close(cc);
	exit(1);
    }
    
    if (status = krb5_mk_req_extended(AP_OPTS_USE_SESSION_KEY,
				      0,       /* no application checksum here */
				      krb5_kdc_default_options,
				      0,
				      0,       /* no need for subkey */
				      cc,
				      &creds,
				      0,       /* don't need authenticator copy */
				      &msg)) {
	krb5_cc_destroy(cc);
	krb5_cc_close(cc);
	exit(1);
    }
    krb5_cc_destroy(cc);
    krb5_cc_close(cc);
    status = krb5_write_message((krb5_pointer) &rem, &msg);
    krb5_xfree(msg.data);
    if (status){
	exit(1);
    }
    
    /* setup eblock for des_read and write */
    krb5_copy_keyblock(&creds.keyblock,&session_key);
    
    /* cleanup */
    krb5_free_cred_contents(&creds);
    
    /* OK process key */
    krb5_use_keytype(&eblock, session_key->keytype);
    if ( status = krb5_process_key(&eblock,session_key)) {
	exit(1);
    }
    
    return;
}



char storage[2*BUFSIZ];			/* storage for the decryption */
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
    krb5_error_code status;
    
    if (!encryptflag)
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
     * XXX Ick; this assumes a big-endian word order....  
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
	error( "rcp: Des_read size problem net_len %d rd_len %d %d.\n",
	      net_len,rd_len, len);
	errno = E2BIG;
	return(-1);
    }
    if ((cc = krb5_net_read(fd, desinbuf.data, net_len)) != net_len) {
	/* pipe must have closed, return 0 */
	error( "rcp: Des_read error: length received %d != expected %d.\n",
	      cc,net_len);
	return(0);
    }
    /* decrypt info */
    if ((status = krb5_decrypt(desinbuf.data,
			       (krb5_pointer) storage,
			       net_len,
			       &eblock, 0))) {
	error("rcp: Des_read cannot decrypt data from network %s.\n",
	      error_message(status));
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
    
    if (!encryptflag)
      return(write(fd, buf, len));
    
    desoutbuf.length = krb5_encrypt_size(len,eblock.crypto_entry);
    if (desoutbuf.length > sizeof(des_outbuf)){
	return(-1);
    }
    if (( krb5_encrypt((krb5_pointer)buf,
		       desoutbuf.data,
		       len,
		       &eblock,
		       0))){
	return(-1);
    }
    
    net_len = htonl(len);
#ifdef BITS64
    (void) write(fd,(char *)&net_len + 4, 4);
#else
    (void) write(fd, &net_len, sizeof(net_len));
#endif
    if (write(fd, desoutbuf.data,desoutbuf.length) != desoutbuf.length){
	return(-1);
    }
    else return(len);
}

#endif /* KERBEROS */
