/* Stripped down Kerberos V4 rcp, for server-side use only */
/* based on Cygnus CNS V4-96q1 src/appl/bsd/rcp.c. */

/*
 *	rcp.c
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

#ifndef lint
static char sccsid[] = "@(#)rcp.c	5.10 (Berkeley) 9/20/88";
#endif /* not lint */

/*
 * rcp
 */
#ifdef KERBEROS
#include <krb5.h>
#include <com_err.h>
#include <k5-util.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#ifndef KERBEROS
/* Ultrix doesn't protect it vs multiple inclusion, and krb.h includes it */
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#ifdef NEED_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#include <netinet/in.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <ctype.h>
#ifndef KERBEROS
/* Ultrix doesn't protect it vs multiple inclusion, and krb.h includes it */
#include <netdb.h>
#endif
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "port-sockets.h"

#ifdef KERBEROS
#include <krb.h>
#include <krbports.h>


void sink(int, char **), source(int, char **), 
    rsource(char *, struct stat *), usage(void);
/*VARARGS*/
void 	error (char *fmt, ...)
#if !defined (__cplusplus) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7))
       __attribute__ ((__format__ (__printf__, 1, 2)))
#endif
     ;
int	response(void);
#if !defined(HAVE_UTIMES)
int	utimes();
#endif


#if 0
#include <kstream.h>
#else
/* we don't have full kstream in v5, so fake it... */

typedef struct {
  int encrypting;
  int read_fd, write_fd;
  des_key_schedule *sched;
  des_cblock *ivec;
  /* used on the read side */
  char *inbuf;
  char *outbuf;
  int writelen;
  char* retbuf;
  int retbuflen;
  int retlen;
  int returned;
} *kstream;

static kstream kstream_create_rcp_from_fd(read_fd, write_fd, sched, ivec)
     int read_fd, write_fd;
     des_key_schedule *sched;
     des_cblock *ivec;
{
  kstream tmp = (kstream)malloc(sizeof(*tmp));
  tmp->encrypting = 1;
  tmp->read_fd = read_fd;
  tmp->write_fd = write_fd;
  /* they're static in this file, so just hang on to the pointers */
  tmp->sched = sched;
  tmp->ivec = ivec;
  tmp->inbuf = 0;
  tmp->outbuf = 0;
  tmp->writelen = 0;
  tmp->retbuf = 0;
  tmp->retbuflen = 0;
  tmp->returned = 0;
  tmp->retlen = 0;
  return tmp;
}

static kstream kstream_create_from_fd(read_fd, write_fd, sched, session)
     int read_fd, write_fd;
     Key_schedule *sched;
     des_cblock *session;
{
  /* just set it up... */
  kstream tmp = (kstream)malloc(sizeof(*tmp));
  tmp->encrypting = 0;
  tmp->read_fd = read_fd;
  tmp->write_fd = write_fd;
  return tmp;
}


/* always set to 0 here anyway */
#define kstream_set_buffer_mode(x,y)

static int kstream_read(krem, buf, len)
     kstream krem;
     char *buf;
     unsigned int len;
{
  if(krem->encrypting) {
    /* when we get a length, we have to read the whole block. However,
       we have to hand it to the user in the chunks they want, which 
       may be smaller if BUFSIZ doesn't match. [the caller can deal if
       the incoming blocks are smaller...] */
    if (krem->returned) {
      int remaining = krem->retlen - krem->returned;
      int returning;
      
      if (remaining <= len) {
	returning = remaining;
      } else {
	returning = len;
      }
      memcpy(buf, krem->retbuf+krem->returned, returning);
      krem->returned += returning;
      if (krem->returned == krem->retlen) krem->returned = 0;

      return returning;
    }

    /* we need 4 bytes to get a length, and once we have that we know how
       much to get to fill the buffer. Then we can hand back bits, or loop. */
    {
      int cc;
      unsigned char clen[4];
      unsigned int x = 0;
      unsigned int sz, off;

      cc = read(krem->read_fd, clen, 4);
      if (cc != 4) return cc;
      x <<= 8; x += clen[0] & 0xff;
      x <<= 8; x += clen[1] & 0xff;
      x <<= 8; x += clen[2] & 0xff;
      x <<= 8; x += clen[3] & 0xff;
      sz = (x + 7) & (~7U);

      if (krem->retbuflen < sz) {
	if (krem->retbuflen == 0) 
	  krem->retbuf = (char*)malloc(sz>(BUFSIZ)?sz:(BUFSIZ));
	else 
	  krem->retbuf = (char*)realloc(krem->retbuf, sz);
	if(!krem->retbuf) { errno = ENOMEM; return -1; }
	krem->retbuflen = sz>(BUFSIZ)?sz:(BUFSIZ);
      }

      /* get all of it */
      off = 0;
      do {
	cc = read(krem->read_fd, krem->retbuf+off, sz-off);
	if (cc <= 0) return cc;
	off += cc;
      } while (off < sz);
      
      /* decrypt it */
      des_pcbc_encrypt ((des_cblock *)krem->retbuf, 
			(des_cblock *)krem->retbuf, 
			(int) sz, *krem->sched, krem->ivec, 
			DECRYPT);

      /* now retbuf has sz bytes, return len or x of them to the user */
      if (x <= len) {
	memcpy(buf, krem->retbuf, x);
	return x;
      } else {
	memcpy(buf, krem->retbuf, len);
	/* defer the rest */
	krem->returned = len;
	krem->retlen = x;
	return len;
      }
    }
  } else {
    return read(krem->read_fd, buf, len);
  }
}

static int kstream_write(krem, buf, len)
     kstream krem;
     char *buf;
     unsigned int len;
{
  if (krem->encrypting) {
    unsigned long x;
    int st;
    unsigned int outlen = (len + 7) & (~7U);

    if (krem->writelen < outlen) {
      if (krem->writelen == 0) {
	krem->inbuf = (char*)malloc(outlen);
	krem->outbuf = (char*)malloc(outlen+8);
      } else {
	krem->inbuf = (char*)realloc(krem->inbuf, outlen);
	krem->outbuf = (char*)realloc(krem->outbuf, outlen+8);
      }
      if(!krem->inbuf || !krem->outbuf) { errno = ENOMEM; return -1; }
      krem->writelen = outlen;
    }

    outlen = (len + 7) & (~7U);

    memcpy(krem->inbuf, buf, len);
    krb5_random_confounder(outlen-len, krem->inbuf+len);
    buf = krem->inbuf;

    x = len;
    krem->outbuf[3+4] = x & 0xff; x >>= 8;
    krem->outbuf[2+4] = x & 0xff; x >>= 8;
    krem->outbuf[1+4] = x & 0xff; x >>= 8;
    krem->outbuf[0+4] = x & 0xff; x >>= 8;
    if (x)
      abort ();
    /* memset(outbuf+4+4, 0x42, BUFSIZ); */
    st = des_pcbc_encrypt ((des_cblock *)buf, (des_cblock *)(krem->outbuf+4+4),
			   (int) outlen,
			   *krem->sched, krem->ivec, ENCRYPT);

    if (st) abort();
    return write(krem->write_fd, krem->outbuf+4, 4+outlen);
  } else {
    return write(krem->write_fd, buf, len);
  }
}

/* 0 = stdin, read; 1 = stdout, write */
#define rem 0,1

#endif


#ifdef _AUX_SOURCE
#define vfork fork
#endif
#ifdef NOVFORK
#define vfork fork
#endif

#ifndef roundup
#define roundup(x,y) ((((x)+(y)-1)/(y))*(y))
#endif

int	sock;
CREDENTIALS cred;
MSG_DAT msg_data;
struct sockaddr_in foreign, local;
Key_schedule schedule;

KTEXT_ST ticket;
AUTH_DAT kdata;
static des_cblock crypt_session_key;
char	krb_realm[REALM_SZ];
char	**save_argv(int, char **), *krb_realmofhost();
#ifndef HAVE_STRSAVE
static char *strsave(char *);
#endif
#ifdef NOENCRYPTION
#define	des_read	read
#define	des_write	write
#else /* !NOENCRYPTION */
void	answer_auth(void);
int	encryptflag = 0;
#endif /* NOENCRYPTION */
#include "rpaths.h"
#else /* !KERBEROS */
#define	des_read	read
#define	des_write	write
#endif /* KERBEROS */

kstream krem;
int	errs;
krb5_sigtype lostconn(int);
int	iamremote, targetshouldbedirectory;
int	iamrecursive;
int	pflag;
int	force_net;
struct	passwd *pwd;
int	userid;
int	port;

char	*getenv();

struct buffer {
	int	cnt;
	char	*buf;
} *allocbuf(struct buffer *, int, int);

#define	NULLBUF	(struct buffer *) 0

#define	ga()		(void) kstream_write (krem, "", 1)

int main(argc, argv)
	int argc;
	char **argv;
{
	char portarg[20], rcpportarg[20];
#ifdef ATHENA
	static char curhost[256];
#endif /* ATHENA */
#ifdef KERBEROS
	char realmarg[REALM_SZ + 5];
#endif /* KERBEROS */

	portarg[0] = '\0';
	rcpportarg[0] = '\0';
	realmarg[0] = '\0';

	pwd = getpwuid(userid = getuid());
	if (pwd == 0) {
		fprintf(stderr, "who are you?\n");
		exit(1);
	}

#ifdef KERBEROS
	krb_realm[0] = '\0';		/* Initially no kerberos realm set */
#endif /* KERBEROS */
	for (argc--, argv++; argc > 0 && **argv == '-'; argc--, argv++) {
		(*argv)++;
		while (**argv) switch (*(*argv)++) {

		    case 'r':
			iamrecursive++;
			break;

		    case 'p':		/* preserve mtimes and atimes */
			pflag++;
			break;

		    case 'P':		/* Set port to use.  */
			port = atoi(*argv);
			sprintf(portarg, " -p%d", port);
			sprintf(rcpportarg, " -P%d", port);
			port = htons(port);
			goto next_arg;

		    case 'N':
			/* Force use of network even on local machine.  */
			force_net++;
			break;

#ifdef KERBEROS
#ifndef NOENCRYPTION
		    case 'x':
			encryptflag++;
			break;
#endif
		    case 'k':		/* Change kerberos realm */
			argc--, argv++;
			if (argc == 0) 
			  usage();
			strncpy(krb_realm,*argv,REALM_SZ);
			krb_realm[REALM_SZ-1] = 0;
			sprintf(realmarg, " -k %s", krb_realm);
			goto next_arg;
#endif /* KERBEROS */
		    /* The rest of these are not for users. */
		    case 'd':
			targetshouldbedirectory = 1;
			break;

		    case 'f':		/* "from" */
			iamremote = 1;
#if defined(KERBEROS) && !defined(NOENCRYPTION)
			if (encryptflag) {
				answer_auth();
				krem = kstream_create_rcp_from_fd (rem,
								   &schedule,
								   &crypt_session_key);
			} else
				krem = kstream_create_from_fd (rem, 0, 0);
			kstream_set_buffer_mode (krem, 0);
#endif /* KERBEROS && !NOENCRYPTION */
			(void) response();
			(void) setuid(userid);
			source(--argc, ++argv);
			exit(errs);

		    case 't':		/* "to" */
			iamremote = 1;
#if defined(KERBEROS) && !defined(NOENCRYPTION)
			if (encryptflag) {
				answer_auth();
				krem = kstream_create_rcp_from_fd (rem,
								   &schedule,
								   &crypt_session_key);
			} else
				krem = kstream_create_from_fd (rem, 0, 0);
			kstream_set_buffer_mode (krem, 0);
#endif /* KERBEROS && !NOENCRYPTION */
			(void) setuid(userid);
			sink(--argc, ++argv);
			exit(errs);

		    default:
			usage();
		}
#ifdef KERBEROS
	      next_arg: ;
#endif /* KERBEROS */
	}
	usage();
	return 1;
}

static void verifydir(cp)
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
	char buf[BUFSIZ];

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
			kstream_write (krem, buf, strlen (buf));
			if (response() < 0) {
				(void) close(f);
				continue;
			}
		}
		(void) sprintf(buf, "C%04o %ld %s\n",
		    (unsigned int) stb.st_mode&07777, (long) stb.st_size, last);
		kstream_write (krem, buf, strlen (buf));
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
			kstream_write (krem, bp->buf, amt);
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
	char buf[BUFSIZ];
	char *bufv[1];
#ifdef USE_DIRENT_H
	struct dirent *dp;
#else
	struct direct *dp;
#endif

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
		kstream_write (krem, buf, strlen (buf));
		if (response() < 0) {
			closedir(d);
			return;
		}
	}
	(void) sprintf(buf, "D%04o %d %s\n",
		       (unsigned int) statp->st_mode&07777, 0, last);
	kstream_write (krem, buf, strlen (buf));
	if (response() < 0) {
		closedir(d);
		return;
	}
	while ((dp = readdir(d))) {
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
	kstream_write (krem, "E\n", 2);
	(void) response();
}

int response()
{
	char resp, c, rbuf[BUFSIZ], *cp = rbuf;

	if (kstream_read (krem, &resp, 1) != 1)
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
			if (kstream_read (krem, &c, 1) != 1)
				lostconn(0);
			*cp++ = c;
		} while (cp < &rbuf[BUFSIZ] && c != '\n');
		if (iamremote == 0)
			(void) write(2, rbuf, (unsigned) (cp - rbuf));
		errs++;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/*NOTREACHED*/
	return -1;
}

krb5_sigtype lostconn(signum)
    int signum;
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
	off_t i, j;
	char *targ, *whopp, *cp;
	int of, wrerr, exists, first, amt;
	mode_t mode;
	unsigned int count;
	off_t size;
	struct buffer *bp;
	static struct buffer buffer;
	struct stat stb;
	int targisdir = 0;
	mode_t mask = umask(0);
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
		if (kstream_read (krem, cp, 1) <= 0)
			return;
		if (*cp++ == '\n')
			SCREWUP("unexpected '\\n'");
		do {
			if (kstream_read(krem, cp, 1) != 1)
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
			if (strlen(targ) + strlen(cp) + 1 < sizeof(nambuf)) {
				(void) sprintf(nambuf, "%s%s%s", targ,
				    *targ ? "/" : "", cp);
			} else {
				SCREWUP("target directory name too long");
			}
		} else {
		    if (strlen(targ) + 1 < sizeof(nambuf))
			(void) strncpy(nambuf, targ, sizeof(nambuf)-1);
		    else
			SCREWUP("target pathname too long");
		}
		nambuf[sizeof(nambuf)-1] = '\0';
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
		if ((of = open(nambuf, O_WRONLY|O_CREAT|O_TRUNC, mode)) < 0) {
	bad:
			error("rcp: %s: %s\n", nambuf, error_message(errno));
			continue;
		}
#ifdef NO_FCHMOD
		if (exists && pflag)
			(void) chmod(nambuf, mode);
#else
		if (exists && pflag)
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
				j = kstream_read(krem, cp, amt);
				if (j <= 0) {
					if (j == 0)
					    error("rcp: dropped connection");
					else
					    error("rcp: %s\n",
						error_message(errno));
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
#ifndef __SCO__
		if (ftruncate(of, size))
			error("rcp: can't truncate %s: %s\n",
			    nambuf, error_message(errno));
#endif
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

struct buffer *
allocbuf(bp, fd, blksize)
	struct buffer *bp;
	int fd, blksize;
{
	int size;
#ifndef NOSTBLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) < 0) {
		error("rcp: fstat: %s\n", error_message(errno));
		return (NULLBUF);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
#endif
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
    char buf[BUFSIZ], *cp = buf;
    
#ifdef HAVE_STDARG_H
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    errs++;
    *cp++ = 1;
    (void) vsprintf(cp, fmt, ap);
    va_end(ap);

    if (krem)
	(void) kstream_write(krem, buf, strlen(buf));
    if (iamremote == 0)
	(void) write(2, buf+1, strlen(buf+1));
}

void usage()
{
  fprintf(stderr,
"v4rcp: this program only acts as a server, and is not for user function.\n");
  exit(1);
}

#ifdef KERBEROS

char **
save_argv(argc, argv)
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

#ifndef HAVE_STRSAVE
static char *
strsave(sp)
char *sp;
{
	register char *ret;
	
	if((ret = (char *)malloc((unsigned) strlen(sp)+1)) == NULL) {
		fprintf(stderr, "rcp: no memory for saving args\n");
		exit(1);
	}
	(void) strcpy(ret,sp);
	return(ret);
}
#endif

#ifndef NOENCRYPTION
#undef rem
#define rem 0

void
answer_auth()
{
	int status;
	long authopts = KOPT_DO_MUTUAL;
	char instance[INST_SZ];
	char version[9];
	char *srvtab;
	char *envaddr;

#if 0
	int sin_len;
	
	sin_len = sizeof (struct sockaddr_in);
	if (getpeername(rem, &foreign, &sin_len) < 0) {
		perror("getpeername");
		exit(1);
	}

	sin_len = sizeof (struct sockaddr_in);
	if (getsockname(rem, &local, &sin_len) < 0) {
		perror("getsockname");
		exit(1);
	}
#else
	if ((envaddr = getenv("KRB5LOCALADDR"))) {
#ifdef HAVE_INET_ATON
	  inet_aton(envaddr,  &local.sin_addr);
#else
	  local.sin_addr.s_addr = inet_addr(envaddr);
#endif
	  local.sin_family = AF_INET;
	  envaddr = getenv("KRB5LOCALPORT");
	  if (envaddr)
	    local.sin_port = htons(atoi(envaddr));
	  else
	    local.sin_port = 0;
	} else {
	  fprintf(stderr, "v4rcp: couldn't get local address (KRB5LOCALADDR)\n");
	  exit(1);
	}
	if ((envaddr = getenv("KRB5REMOTEADDR"))) {
#ifdef HAVE_INET_ATON
	  inet_aton(envaddr,  &foreign.sin_addr);
#else
	  foreign.sin_addr.s_addr = inet_addr(envaddr);
#endif
	  foreign.sin_family = AF_INET;
	  envaddr = getenv("KRB5REMOTEPORT");
	  if (envaddr)
	    foreign.sin_port = htons(atoi(envaddr));
	  else
	    foreign.sin_port = 0;
	} else {
	  fprintf(stderr, "v4rcp: couldn't get remote address (KRB5REMOTEADDR)\n");
	  exit(1);
	}

#endif
	strcpy(instance, "*");

	/* If rshd was invoked with the -s argument, it will set the
           environment variable KRB_SRVTAB.  We use that to get the
           srvtab file to use.  If we do use the environment variable,
           we reset to our real user ID (which will already have been
           set up by rsh).  Since rcp is setuid root, we would
           otherwise have a security hole.  If we are using the normal
           srvtab (KEYFILE in krb.h, normally set to /etc/krb-srvtab),
           we must keep our effective uid of root, because that file
           can only be read by root.  */
	srvtab = (char *) getenv("KRB_SRVTAB");
	if (srvtab == NULL)
		srvtab = "";
	if (*srvtab != '\0')
		(void) setuid (userid);

	if ((status = krb_recvauth(authopts, rem, &ticket, "rcmd", instance,
				   &foreign,
				   &local,
				   &kdata,
				   srvtab,
				   schedule,
				   version)) != KSUCCESS) {
		fprintf(stderr, "krb_recvauth mutual fail: %s\n",
			krb_get_err_text(status));
		exit(1);
	}
	memcpy(&crypt_session_key, &kdata.session, sizeof (crypt_session_key));
	return;
}
#endif /* !NOENCRYPTION */

#endif /* KERBEROS */
