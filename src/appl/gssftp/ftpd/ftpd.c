/*
 * Copyright (c) 1985, 1988, 1990 Regents of the University of California.
 * All rights reserved.
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

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1985, 1988, 1990 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)ftpd.c	5.40 (Berkeley) 7/2/91";
#endif /* not lint */

/*
 * FTP server.
 */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#define	FTP_NAMES
#include <arpa/ftp.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#ifdef HAVE_SHADOW
#include <shadow.h>
#endif
#include <setjmp.h>
#ifndef POSIX_SETJMP
#undef sigjmp_buf
#undef sigsetjmp
#undef siglongjmp
#define sigjmp_buf	jmp_buf
#define sigsetjmp(j,s)	setjmp(j)
#define siglongjmp	longjmp
#endif
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#ifndef STDARG
#if (defined(__STDC__) && ! defined(VARARGS)) || defined(HAVE_STDARG_H)
#define STDARG
#endif
#endif
#ifdef STDARG
#include <stdarg.h>
#endif
#include "pathnames.h"

#ifndef L_SET
#define L_SET 0
#endif
#ifndef L_INCR
#define L_INCR 1
#endif

#define strerror(error)	(sys_errlist[error])
#ifdef NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif

extern char *mktemp ();

#ifndef HAVE_SETEUID
#ifdef HAVE_SETRESUID
#define seteuid(e) setresuid(-1,e,-1)
#define setegid(e) setresgid(-1,e,-1)
#endif
#endif

#ifdef STDARG
extern reply(int, char *, ...);
extern lreply(int, char *, ...);
#endif

#ifdef KERBEROS
#include <krb.h>

AUTH_DAT kdata;
KTEXT_ST ticket;
MSG_DAT msg_data;
Key_schedule schedule;
int kerb_ok;	/* Kerberos authentication and authorization succeeded */
char *keyfile = KEYFILE;
#endif /* KERBEROS */

#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
gss_ctx_id_t gcontext;
gss_buffer_desc client_name;
int gss_ok;	/* GSSAPI authentication and userok authorization succeeded */
char* gss_services[] = { "ftp", "host", 0 };
#endif /* GSSAPI */

char *auth_type;	/* Authentication succeeded?  If so, what type? */
static char *temp_auth_type;

/*
 * File containing login names
 * NOT to be used on this machine.
 * Commonly used to disallow uucp.
 */
extern	int errno;
extern	char *crypt();
extern	char version[];
extern	char *home;		/* pointer to home directory for glob */
extern	FILE *ftpd_popen(), *fopen(), *freopen();
extern	int  ftpd_pclose(), fclose();
extern	char *getline();
extern	char cbuf[];
extern	off_t restart_point;

struct	sockaddr_in ctrl_addr;
struct	sockaddr_in data_source;
struct	sockaddr_in data_dest;
struct	sockaddr_in his_addr;
struct	sockaddr_in pasv_addr;

int	data;
jmp_buf	errcatch;
sigjmp_buf urgcatch;
int	logged_in;
struct	passwd *pw;
int	debug;
int	timeout = 900;    /* timeout after 15 minutes of inactivity */
int	maxtimeout = 7200;/* don't allow idle time to be set beyond 2 hours */
int	logging;
int	authenticate;
int	guest;
int	type;
int	level;
int	form;
int	stru;			/* avoid C keyword */
int	mode;
int	usedefault = 1;		/* for data transfers */
int	pdata = -1;		/* for passive mode */
int	transflag;
off_t	file_size;
off_t	byte_count;
#if !defined(CMASK) || CMASK == 0
#undef CMASK
#define CMASK 027
#endif
int	defumask = CMASK;		/* default umask value */
char	tmpline[FTP_BUFSIZ];
char	hostname[MAXHOSTNAMELEN];
char	remotehost[MAXHOSTNAMELEN];

/*
 * Timeout intervals for retrying connections
 * to hosts that don't accept PORT cmds.  This
 * is a kludge, but given the problems with TCP...
 */
#define	SWAITMAX	90	/* wait at most 90 seconds */
#define	SWAITINT	5	/* interval between retries */

int	swaitmax = SWAITMAX;
int	swaitint = SWAITINT;

void	lostconn(), myoob();
FILE	*getdatasock(), *dataconn();

#ifdef SETPROCTITLE
char	**Argv = NULL;		/* pointer to argument vector */
char	*LastArgv = NULL;	/* end of argv */
char	proctitle[FTP_BUFSIZ];	/* initial part of title */
#endif /* SETPROCTITLE */

#ifdef __SCO__
/* sco has getgroups and setgroups but no initgroups */
int initgroups(char* name, gid_t basegid) {
  gid_t others[NGROUPS_MAX+1];
  int ngrps;

  others[0] = basegid;
  ngrps = getgroups(NGROUPS_MAX, others+1);
  return setgroups(ngrps+1, others);
}
#endif

main(argc, argv, envp)
	int argc;
	char *argv[];
	char **envp;
{
	int addrlen, on = 1, tos, port = -1;
	char *cp;

	debug = 0;
#ifdef SETPROCTITLE
	/*
	 *  Save start and extent of argv for setproctitle.
	 */
	Argv = argv;
	while (*envp)
		envp++;
	LastArgv = envp[-1] + strlen(envp[-1]);
#endif /* SETPROCTITLE */

	argc--, argv++;
	while (argc > 0 && *argv[0] == '-') {
		for (cp = &argv[0][1]; *cp; cp++) switch (*cp) {

		case 'v':
			debug = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'l':
			logging = 1;
			break;

		case 'a':
			authenticate = 1;
			break;

		case 'p':
			if (*++cp != '\0')
				port = atoi(cp);
			else if (argc > 1) {
				argc--, argv++;
				port = atoi(*argv);
			}
			else
				fprintf(stderr, "ftpd: -p expects argument\n");
			goto nextopt;

		case 'r':
			if (*++cp != '\0')
				setenv("KRB_CONF", cp, 1);
			else if (argc > 1) {
				argc--, argv++;
				setenv("KRB_CONF", *argv, 1);
			}
			else
				fprintf(stderr, "ftpd: -r expects argument\n");
			goto nextopt;

#ifdef KERBEROS
		case 's':
			if (*++cp != '\0')
				keyfile = cp;
			else if (argc > 1) {
				argc--, argv++;
				keyfile = *argv;
			}
			else
				fprintf(stderr, "ftpd: -s expects argument\n");
			goto nextopt;

#endif /* KERBEROS */
		case 't':
			timeout = atoi(++cp);
			if (maxtimeout < timeout)
				maxtimeout = timeout;
			goto nextopt;

		case 'T':
			maxtimeout = atoi(++cp);
			if (timeout > maxtimeout)
				timeout = maxtimeout;
			goto nextopt;

		case 'u':
		    {
			int val = 0;

			while (*++cp && *cp >= '0' && *cp <= '9')
				val = val*8 + *cp - '0';
			if (*cp)
				fprintf(stderr, "ftpd: Bad value for -u\n");
			else
				defumask = val;
			goto nextopt;
		    }

		default:
			fprintf(stderr, "ftpd: Unknown flag -%c ignored.\n",
			     *cp);
			break;
		}
nextopt:
		argc--, argv++;
	}

	if (port != -1) {
		struct sockaddr_in sin;
		int s, ns, sz;

		/* Accept an incoming connection on port.  */
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(port);
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) {
			perror("socket");
			exit(1);
		}
		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&on, sizeof(on));
		if (bind(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
			perror("bind");
			exit(1);
		}
		if (listen(s, 1) < 0) {
			perror("listen");
			exit(1);
		}
		sz = sizeof sin;
		ns = accept(s, (struct sockaddr *)&sin, &sz);
		if (ns < 0) {
			perror("accept");
			exit(1);
		}
		(void) close(s);
		(void) dup2(ns, 0);
		(void) dup2(ns, 1);
		(void) dup2(ns, 2);
		if (ns > 2)
		  (void) close(ns);
	}

	/*
	 * LOG_NDELAY sets up the logging connection immediately,
	 * necessary for anonymous ftp's that chroot and can't do it later.
	 */
#ifndef LOG_NDELAY
/* Ultrix syslog does not support NDELAY.  */
#define LOG_NDELAY 0
#endif
#ifndef LOG_DAEMON
#define LOG_DAEMON 0
#endif
	openlog("ftpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	addrlen = sizeof (his_addr);
	if (getpeername(0, (struct sockaddr *)&his_addr, &addrlen) < 0) {
		syslog(LOG_ERR, "getpeername (%s): %m",argv[0]);
		exit(1);
	}
	addrlen = sizeof (ctrl_addr);
	if (getsockname(0, (struct sockaddr *)&ctrl_addr, &addrlen) < 0) {
		syslog(LOG_ERR, "getsockname (%s): %m",argv[0]);
		exit(1);
	}
#ifdef IP_TOS
#ifdef IPTOS_LOWDELAY
	tos = IPTOS_LOWDELAY;
	if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
#endif
	port = ntohs(ctrl_addr.sin_port);
	data_source.sin_port = htons(port - 1);

	(void) freopen("/dev/null", "w", stderr);
	(void) signal(SIGPIPE, lostconn);
	(void) signal(SIGCHLD, SIG_IGN);
#ifdef SIGURG
#ifdef POSIX_SIGNALS
	{
		struct sigaction sa;

		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = myoob;
		if (sigaction(SIGURG, &sa, NULL) < 0)
			syslog(LOG_ERR, "signal: %m");
	}
#else
	if ((long)signal(SIGURG, myoob) < 0)
		syslog(LOG_ERR, "signal: %m");
#endif /* POSIX_SIGNALS */
#endif /* SIGURG */

	/* Try to handle urgent data inline */
#ifdef SO_OOBINLINE
	if (setsockopt(0, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on)) < 0)
		syslog(LOG_ERR, "setsockopt: %m");
#endif

#ifdef	F_SETOWN
	if (fcntl(fileno(stdin), F_SETOWN, getpid()) == -1)
		syslog(LOG_ERR, "fcntl F_SETOWN: %m");
#endif
	dolog(&his_addr);
	/*
	 * Set up default state
	 */
	data = -1;
	level = PROT_C;
	type = TYPE_A;
	form = FORM_N;
	stru = STRU_F;
	mode = MODE_S;
	tmpline[0] = '\0';
	(void) gethostname(hostname, sizeof (hostname));
	reply(220, "%s FTP server (%s) ready.", hostname, version);
	(void) setjmp(errcatch);
	for (;;)
		(void) yyparse();
	/* NOTREACHED */
}

void
lostconn()
{
	if (debug)
		syslog(LOG_DEBUG, "lost connection");
	dologout(-1);
}

static char ttyline[20];

/*
 * Helper function for sgetpwnam().
 */
char *
sgetsave(s)
	char *s;
{
	char *new = malloc((unsigned) strlen(s) + 1);

	if (new == NULL) {
		perror_reply(421, "Local resource failure: malloc");
		dologout(1);
		/* NOTREACHED */
	}
	(void) strcpy(new, s);
	return (new);
}

/*
 * Save the result of a getpwnam.  Used for USER command, since
 * the data returned must not be clobbered by any other command
 * (e.g., globbing).
 */
struct passwd *
sgetpwnam(name)
	char *name;
{
	static struct passwd save;
	register struct passwd *p;
#ifdef HAVE_SHADOW
	register struct spwd *sp;
#endif
	char *sgetsave();

	if ((p = getpwnam(name)) == NULL)
		return (p);
	if (save.pw_name) {
		free(save.pw_name);
		free(save.pw_passwd);
		free(save.pw_gecos);
		free(save.pw_dir);
		free(save.pw_shell);
	}
	save = *p;
	save.pw_name = sgetsave(p->pw_name);
#ifdef HAVE_SHADOW
	if ((sp = getspnam(name)) == NULL)
	    save.pw_passwd = sgetsave(p->pw_passwd);
	else
	    save.pw_passwd = sgetsave(sp->sp_pwdp);
#else
	save.pw_passwd = sgetsave(p->pw_passwd);
#endif
	save.pw_gecos = sgetsave(p->pw_gecos);
	save.pw_dir = sgetsave(p->pw_dir);
	save.pw_shell = sgetsave(p->pw_shell);
	return (&save);
}

setlevel(prot_level)
int prot_level;
{
	switch (prot_level) {
		case PROT_S:
#ifndef NOENCRYPTION
		case PROT_P:
#endif
			if (auth_type)
		case PROT_C:
				reply(200, "Protection level set to %s.",
					(level = prot_level) == PROT_S ?
						"Safe" : level == PROT_P ?
						"Private" : "Clear");
			else
		default:	reply(536, "%s protection level not supported.",
					levelnames[prot_level]);
	}
}

int login_attempts;		/* number of failed login attempts */
int askpasswd;			/* had user command, ask for passwd */

/*
 * USER command.
 * Sets global passwd pointer pw if named account exists and is acceptable;
 * sets askpasswd if a PASS command is expected.  If logged in previously,
 * need to reset state.  If name is "ftp" or "anonymous", the name is not in
 * _PATH_FTPUSERS, and ftp account exists, set guest and pw, then just return.
 * If account doesn't exist, ask for passwd anyway.  Otherwise, check user
 * requesting login privileges.  Disallow anyone who does not have a standard
 * shell as returned by getusershell().  Disallow anyone mentioned in the file
 * _PATH_FTPUSERS to allow people such as root and uucp to be avoided.
 */
user(name)
	char *name;
{
	register char *cp;
	char *shell;
#ifdef HAVE_GETUSERSHELL
	char *getusershell();
#endif

	/* Some paranoid sites may want the client to authenticate
	 * before accepting the USER command.  If so, uncomment this:

	if (!auth_type) {
		reply(530,
			"Must perform authentication before identifying USER.");
		return;
	 */
	if (logged_in) {
		if (guest) {
			reply(530, "Can't change user from guest login.");
			return;
		}
		end_login();
	}

	guest = 0;
	if (strcmp(name, "ftp") == 0 || strcmp(name, "anonymous") == 0) {
		if (checkuser("ftp") || checkuser("anonymous"))
			reply(530, "User %s access denied.", name);
		else if ((pw = sgetpwnam("ftp")) != NULL) {
			guest = 1;
			askpasswd = 1;
			reply(331, "Guest login ok, send ident as password.");
		} else
			reply(530, "User %s unknown.", name);
		return;
	}
	if (pw = sgetpwnam(name)) {
		if ((shell = pw->pw_shell) == NULL || *shell == 0)
			shell = "/bin/sh";
#ifdef HAVE_GETUSERSHELL
		while ((cp = getusershell()) != NULL)
			if (strcmp(cp, shell) == 0)
				break;
		/* endusershell(); */ /* this breaks on solaris 2.4 */
#else
		cp = shell;
#endif
		if (cp == NULL || checkuser(name)) {
			reply(530, "User %s access denied.", name);
			if (logging)
				syslog(LOG_NOTICE,
				    "FTP LOGIN REFUSED FROM %s, %s",
				    remotehost, name);
			pw = (struct passwd *) NULL;
			return;
		}
	}
#ifdef KERBEROS
	if (auth_type && strcmp(auth_type, "KERBEROS_V4") == 0) {
		char buf[FTP_BUFSIZ];
		kerb_ok = kuserok(&kdata,name) == 0;
		if (! kerb_ok && authenticate) {
			reply(530, "User %s access denied.", name);
			if (logging)
				syslog(LOG_NOTICE,
				       "FTP KERBEROS LOGIN REFUSED FROM %s, %s",
				       remotehost, name);
			pw = (struct passwd *) NULL;
			return;
		}
		sprintf(buf, "Kerberos user %s%s%s@%s is%s authorized as %s%s",
			kdata.pname, *kdata.pinst ? "." : "",
			kdata.pinst, kdata.prealm,
			kerb_ok ? "" : " not",
			name, kerb_ok ? "" : "; Password required.");
		reply(kerb_ok ? 232 : 331, "%s", buf);
		syslog(kerb_ok ? LOG_INFO : LOG_ERR, "%s", buf);
	} else
#endif /* KERBEROS */
#ifdef GSSAPI
	if (auth_type && strcmp(auth_type, "GSSAPI") == 0) {
		char buf[FTP_BUFSIZ];
		gss_ok = ftpd_userok(&client_name, name) == 0;
		if (! gss_ok && authenticate) {
			reply(530, "User %s access denied.", name);
			if (logging)
				syslog(LOG_NOTICE,
				       "FTP GSSAPI LOGIN REFUSED FROM %s, %s",
				       remotehost, name);
			pw = (struct passwd *) NULL;
			return;
		}
		sprintf(buf, "GSSAPI user %s is%s authorized as %s%s",
			client_name.value,
			gss_ok ? "" : " not",
			name, gss_ok ? "" : "; Password required.");
		/* 232 is per draft-8, but why 331 not 53z? */
		reply(gss_ok ? 232 : 331, "%s", buf);
		syslog(gss_ok ? LOG_INFO : LOG_ERR, "%s", buf);
	} else
#endif /* GSSAPI */
	/* Other auth types go here ... */
	if (authenticate) {
		reply(530, "User %s access denied: authentication required.",
		      name);
		if (logging)
			syslog(LOG_NOTICE,
			       "FTP LOGIN REFUSED FROM %s, %s",
			       remotehost, name);
		pw = (struct passwd *) NULL;
		return;
	} else
		reply(331, "Password required for %s.", name);
	askpasswd = 1;
	/*
	 * Delay before reading passwd after first failed
	 * attempt to slow down passwd-guessing programs.
	 */
	if (login_attempts)
		sleep((unsigned) login_attempts);
}

/*
 * Check if a user is in the file _PATH_FTPUSERS
 */
checkuser(name)
	char *name;
{
	register FILE *fd;
	register char *p;
	char line[FTP_BUFSIZ];

	if ((fd = fopen(_PATH_FTPUSERS, "r")) != NULL) {
		while (fgets(line, sizeof(line), fd) != NULL)
			if ((p = strchr(line, '\n')) != NULL) {
				*p = '\0';
				if (line[0] == '#')
					continue;
				if (strcmp(line, name) == 0)
					return (1);
			}
		(void) fclose(fd);
	}
	return (0);
}

/*
 * Terminate login as previous user, if any, resetting state;
 * used when USER command is given or login fails.
 */
end_login()
{

	(void) seteuid((uid_t)0);
	if (logged_in)
		ftp_logwtmp(ttyline, "", "");
	pw = NULL;
	logged_in = 0;
	guest = 0;
}

#ifdef KERBEROS
static char *services[] = { "ftp", "rcmd", NULL };

kpass(name, passwd)
char *name, *passwd;
{
	char **service;
	char instance[INST_SZ];
	char realm[REALM_SZ];
	char tkt_file[20];
	KTEXT_ST ticket;
	AUTH_DAT authdata;
	des_cblock key;
	unsigned long faddr;
	struct hostent *hp;

	if (krb_get_lrealm(realm, 1) != KSUCCESS)
		return(0);

	strcpy(tkt_file, TKT_ROOT);
	strcat(tkt_file, "_ftpdXXXXXX");
	krb_set_tkt_string(mktemp(tkt_file));

	(void) strncpy(instance, krb_get_phost(hostname), sizeof(instance));

	if ((hp = gethostbyname(instance)) == NULL)
		return(0);

	memcpy((char *) &faddr, (char *)hp->h_addr, sizeof(faddr));

	if (krb_get_pw_in_tkt(name, "", realm, "krbtgt", realm, 1, passwd)) {
	  for (service = services; *service; service++)
	    if (!read_service_key(*service, instance, realm, 0, keyfile, key)) {
	      (void) memset(key, 0, sizeof(key));
	      if (krb_mk_req(&ticket, *service, instance, realm, 33) ||
	          krb_rd_req(&ticket, *service, instance, faddr, &authdata,keyfile)||
	          kuserok(&authdata, name)) {
		dest_tkt();
		return(0);
	      } else {
		dest_tkt();
		return(1);
	      }
	    }
	  dest_tkt();
	  return(0);
	}
	dest_tkt();
	return(1);
}
#endif /* KERBEROS */

pass(passwd)
	char *passwd;
{
	char *xpasswd, *salt;

	if (logged_in || askpasswd == 0) {
		reply(503, "Login with USER first.");
		return;
	}
	askpasswd = 0;
	if (
#ifdef KERBEROS
	    !kerb_ok &&
#endif /* KERBEROS */
#ifdef GSSAPI
	    !gss_ok &&
#endif /* GSSAPI */
	    !guest) {		/* "ftp" is only account allowed no password */
		if (pw == NULL)
			salt = "xx";
		else
			salt = pw->pw_passwd;
#ifdef __SCO__
		/* SCO does not provide crypt.  */
		xpasswd = "";
#else
		xpasswd = crypt(passwd, salt);
#endif
#ifdef KERBEROS
		/* null pw_passwd ok if Kerberos password ok */
		if (pw == NULL ||
		    (*pw->pw_passwd && strcmp(xpasswd, pw->pw_passwd) &&
			!kpass(pw->pw_name, passwd)) ||
		    (!*pw->pw_passwd && !kpass(pw->pw_name, passwd))) {
#else
		/* The strcmp does not catch null passwords! */
		if (pw == NULL || *pw->pw_passwd == '\0' ||
		    strcmp(xpasswd, pw->pw_passwd)) {
#endif /* KERBEROS */
			reply(530, "Login incorrect.");
			pw = NULL;
			if (login_attempts++ >= 5) {
				syslog(LOG_NOTICE,
				    "repeated login failures from %s",
				    remotehost);
				exit(0);
			}
			return;
		}
	}
	login_attempts = 0;		/* this time successful */
	(void) setegid((gid_t)pw->pw_gid);
	(void) initgroups(pw->pw_name, pw->pw_gid);

	/* open wtmp before chroot */
	(void)sprintf(ttyline, "ftp%d", getpid());
	ftp_logwtmp(ttyline, pw->pw_name, remotehost);
	logged_in = 1;

	if (guest) {
		/*
		 * We MUST do a chdir() after the chroot. Otherwise
		 * the old current directory will be accessible as "."
		 * outside the new root!
		 */
		if (chroot(pw->pw_dir) < 0 || chdir("/") < 0) {
			reply(550, "Can't set guest privileges.");
			goto bad;
		}
	} else if (chdir(pw->pw_dir) < 0) {
		if (chdir("/") < 0) {
			reply(530, "User %s: can't change directory to %s.",
			    pw->pw_name, pw->pw_dir);
			goto bad;
		} else
			lreply(230, "No directory! Logging in with home=/");
	}
	if (seteuid((uid_t)pw->pw_uid) < 0) {
		reply(550, "Can't set uid.");
		goto bad;
	}
	if (guest) {
		reply(230, "Guest login ok, access restrictions apply.");
#ifdef SETPROCTITLE
		sprintf(proctitle, "%s: anonymous/%.*s", remotehost,
		    sizeof(proctitle) - sizeof(remotehost) -
		    sizeof(": anonymous/"), passwd);
		setproctitle(proctitle);
#endif /* SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s, %s",
			    remotehost, passwd);
	} else {
		reply(230, "User %s logged in.", pw->pw_name);
#ifdef SETPROCTITLE
		sprintf(proctitle, "%s: %s", remotehost, pw->pw_name);
		setproctitle(proctitle);
#endif /* SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO, "FTP LOGIN FROM %s, %s",
			    remotehost, pw->pw_name);
	}
	home = pw->pw_dir;		/* home dir for globbing */
	(void) umask(defumask);
	return;
bad:
	/* Forget all about it... */
	end_login();
}

retrieve(cmd, name)
	char *cmd, *name;
{
	FILE *fin, *dout;
	struct stat st;
	int (*closefunc)();

	if (cmd == 0) {
		fin = fopen(name, "r"), closefunc = fclose;
		st.st_size = 0;
	} else {
		char line[FTP_BUFSIZ];

		(void) sprintf(line, cmd, name), name = line;
		fin = ftpd_popen(line, "r"), closefunc = ftpd_pclose;
		st.st_size = -1;
#ifndef NOSTBLKSIZE
		st.st_blksize = FTP_BUFSIZ;
#endif
	}
	if (fin == NULL) {
		if (errno != 0)
			perror_reply(550, name);
		return;
	}
	if (cmd == 0 &&
	    (fstat(fileno(fin), &st) < 0 || (st.st_mode&S_IFMT) != S_IFREG)) {
		reply(550, "%s: not a plain file.", name);
		goto done;
	}
	if (restart_point) {
		if (type == TYPE_A) {
			register int i, n, c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fin)) == EOF) {
					perror_reply(550, name);
					goto done;
				}
				if (c == '\n')
					i++;
			}	
		} else if (lseek(fileno(fin), restart_point, L_SET) < 0) {
			perror_reply(550, name);
			goto done;
		}
	}
	dout = dataconn(name, st.st_size, "w");
	if (dout == NULL)
		goto done;
#ifndef NOSTBLKSIZE
	send_data(fin, dout, st.st_blksize);
#else
	send_data(fin, dout, FTP_BUFSIZ);
#endif
	(void) fclose(dout);
	data = -1;
	pdata = -1;
done:
	(*closefunc)(fin);
}

store_file(name, mode, unique)
	char *name, *mode;
	int unique;
{
	FILE *fout, *din;
	struct stat st;
	int (*closefunc)();
	char *gunique();

	if (unique && stat(name, &st) == 0 &&
	    (name = gunique(name)) == NULL)
		return;

	if (restart_point)
		mode = "r+w";
	fout = fopen(name, mode);
	closefunc = fclose;
	if (fout == NULL) {
		perror_reply(553, name);
		return;
	}
	if (restart_point) {
		if (type == TYPE_A) {
			register int i, n, c;

			n = restart_point;
			i = 0;
			while (i++ < n) {
				if ((c=getc(fout)) == EOF) {
					perror_reply(550, name);
					goto done;
				}
				if (c == '\n')
					i++;
			}	
			/*
			 * We must do this seek to "current" position
			 * because we are changing from reading to
			 * writing.
			 */
			if (fseek(fout, 0L, L_INCR) < 0) {
				perror_reply(550, name);
				goto done;
			}
		} else if (lseek(fileno(fout), restart_point, L_SET) < 0) {
			perror_reply(550, name);
			goto done;
		}
	}
	din = dataconn(name, (off_t)-1, "r");
	if (din == NULL)
		goto done;
	if (receive_data(din, fout) == 0) {
		if (unique)
			reply(226, "Transfer complete (unique file name:%s).",
			    name);
		else
			reply(226, "Transfer complete.");
	}
	(void) fclose(din);
	data = -1;
	pdata = -1;
done:
	(*closefunc)(fout);
}

FILE *
getdatasock(mode)
	char *mode;
{
	int s, on = 1, tries;

	if (data >= 0)
		return (fdopen(data, mode));
	(void) seteuid((uid_t)0);
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		goto bad;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
	    (char *) &on, sizeof (on)) < 0)
		goto bad;
	/* anchor socket to avoid multi-homing problems */
	data_source.sin_family = AF_INET;
	data_source.sin_addr = ctrl_addr.sin_addr;
	for (tries = 1; ; tries++) {
		if (bind(s, (struct sockaddr *)&data_source,
		    sizeof (data_source)) >= 0)
			break;
		if (errno != EADDRINUSE || tries > 10)
			goto bad;
		sleep(tries);
	}
	(void) seteuid((uid_t)pw->pw_uid);
#ifdef IP_TOS
#ifdef IPTOS_THROUGHPUT
	on = IPTOS_THROUGHPUT;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
#endif
	return (fdopen(s, mode));
bad:
	(void) seteuid((uid_t)pw->pw_uid);
	(void) close(s);
	return (NULL);
}

FILE *
dataconn(name, size, mode)
	char *name;
	off_t size;
	char *mode;
{
	char sizebuf[32];
	FILE *file;
	int retry = 0, tos;

	file_size = size;
	byte_count = 0;
	if (size != (off_t) -1)
		(void) sprintf (sizebuf, " (%ld bytes)", size);
	else
		(void) strcpy(sizebuf, "");
	if (pdata >= 0) {
		int s, fromlen = sizeof(data_dest);

		s = accept(pdata, (struct sockaddr *)&data_dest, &fromlen);
		if (s < 0) {
			reply(425, "Can't open data connection.");
			(void) close(pdata);
			pdata = -1;
			return(NULL);
		}
		(void) close(pdata);
		pdata = s;
#ifdef IP_TOS
#ifdef IPTOS_LOWDELAY
		tos = IPTOS_LOWDELAY;
		(void) setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&tos,
		    sizeof(int));
#endif
#endif
		reply(150, "Opening %s mode data connection for %s%s.",
		     type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
		return(fdopen(pdata, mode));
	}
	if (data >= 0) {
		reply(125, "Using existing data connection for %s%s.",
		    name, sizebuf);
		usedefault = 1;
		return (fdopen(data, mode));
	}
	if (usedefault)
		data_dest = his_addr;
	usedefault = 1;
	file = getdatasock(mode);
	if (file == NULL) {
		reply(425, "Can't create data socket (%s,%d): %s.",
		    inet_ntoa(data_source.sin_addr),
		    ntohs(data_source.sin_port), strerror(errno));
		return (NULL);
	}
	data = fileno(file);
	while (connect(data, (struct sockaddr *)&data_dest,
	    sizeof (data_dest)) < 0) {
		if (errno == EADDRINUSE && retry < swaitmax) {
			sleep((unsigned) swaitint);
			retry += swaitint;
			continue;
		}
		perror_reply(425, "Can't build data connection");
		(void) fclose(file);
		data = -1;
		return (NULL);
	}
	reply(150, "Opening %s mode data connection for %s%s.",
	     type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	return (file);
}

#ifdef STDARG
secure_error(char *fmt, ...)
#else
/* VARARGS1 */
secure_error(fmt, p1, p2, p3, p4, p5)
	char *fmt;
#endif
{
	char buf[FTP_BUFSIZ];
#ifdef STDARG
	va_list ap;

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
#else
	sprintf(buf, fmt, p1, p2, p3, p4, p5);
#endif
	reply(535, "%s", buf);
	syslog(LOG_ERR, "%s", buf);
}

/*
 * Tranfer the contents of "instr" to
 * "outstr" peer using the appropriate
 * encapsulation of the data subject
 * to Mode, Structure, and Type.
 *
 * NB: Form isn't handled.
 */
send_data(instr, outstr, blksize)
	FILE *instr, *outstr;
	off_t blksize;
{
	register int c, cnt;
	register char *buf;
	int netfd, filefd;
	int ret = 0;

	transflag++;
	if (sigsetjmp(urgcatch, 1)) {
		transflag = 0;
		(void)secure_flush(fileno(outstr));
		return;
	}
	switch (type) {

	case TYPE_A:
		while ((c = getc(instr)) != EOF) {
			byte_count++;
			if (c == '\n') {
				if (ferror(outstr) ||
				    (ret = secure_putc('\r', outstr)) < 0)
					goto data_err;
			}
			if ((ret = secure_putc(c, outstr)) < 0)
				goto data_err;
		}
		transflag = 0;
		if (ferror(instr))
			goto file_err;
		if (ferror(outstr) ||
		    (ret = secure_flush(fileno(outstr))) < 0)
			goto data_err;
		reply(226, "Transfer complete.");
		return;

	case TYPE_I:
	case TYPE_L:
		if ((buf = malloc((u_int)blksize)) == NULL) {
			transflag = 0;
			perror_reply(451, "Local resource failure: malloc");
			return;
		}
		netfd = fileno(outstr);
		filefd = fileno(instr);
		while ((cnt = read(filefd, buf, (u_int)blksize)) > 0 &&
		    (ret = secure_write(netfd, buf, cnt)) == cnt)
			byte_count += cnt;
		transflag = 0;
		(void)free(buf);
		if (cnt != 0) {
			if (cnt < 0)
				goto file_err;
			goto data_err;
		}
		if ((ret = secure_flush(netfd)) < 0)
			goto data_err;
		reply(226, "Transfer complete.");
		return;
	default:
		transflag = 0;
		reply(550, "Unimplemented TYPE %d in send_data", type);
		return;
	}

data_err:
	transflag = 0;
	if (ret != -2) perror_reply(426, "Data connection");
	return;

file_err:
	transflag = 0;
	perror_reply(551, "Error on input file");
}

/*
 * Transfer data from peer to
 * "outstr" using the appropriate
 * encapulation of the data subject
 * to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled.
 */
receive_data(instr, outstr)
	FILE *instr, *outstr;
{
	register int c;
	int cnt, bare_lfs = 0;
	char buf[FTP_BUFSIZ];
	int ret = 0;

	transflag++;
	if (sigsetjmp(urgcatch, 1)) {
		transflag = 0;
		return (-1);
	}
	switch (type) {

	case TYPE_I:
	case TYPE_L:
		while ((cnt = secure_read(fileno(instr), buf, sizeof buf)) > 0) {
			if (write(fileno(outstr), buf, cnt) != cnt)
				goto file_err;
			byte_count += cnt;
		}
		transflag = 0;
		ret = cnt;
		if (cnt < 0)
			goto data_err;
		return (0);

	case TYPE_E:
		reply(553, "TYPE E not implemented.");
		transflag = 0;
		return (-1);

	case TYPE_A:
		while ((c = secure_getc(instr)) >= 0) {
			byte_count++;
			if (c == '\n')
				bare_lfs++;
			while (c == '\r') {
				if (ferror(outstr))
					goto data_err;
				if ((c = secure_getc(instr)) != '\n') {
					(void) putc ('\r', outstr);
					if (c == '\0')
						goto contin2;
				}
			}
			if (c < 0) break;
			(void) putc(c, outstr);
	contin2:	;
		}
		fflush(outstr);
		ret = c;
		if (c == -2 || ferror(instr))
			goto data_err;
		if (ferror(outstr))
			goto file_err;
		transflag = 0;
		if (bare_lfs) {
			lreply(226, "WARNING! %d bare linefeeds received in ASCII mode", bare_lfs);
			reply(0, "   File may not have transferred correctly.");
		}
		return (0);
	default:
		reply(550, "Unimplemented TYPE %d in receive_data", type);
		transflag = 0;
		return (-1);
	}

data_err:
	transflag = 0;
	if (ret != -2) perror_reply(426, "Data Connection");
	return (-1);

file_err:
	transflag = 0;
	perror_reply(452, "Error writing file");
	return (-1);
}

statfilecmd(filename)
	char *filename;
{
	char line[FTP_BUFSIZ];
	FILE *fin;
	int c;
	char str[FTP_BUFSIZ], *p;

	(void) sprintf(line, "/bin/ls -lgA %s", filename);
	fin = ftpd_popen(line, "r");
	lreply(211, "status of %s:", filename);
	p = str;
	while ((c = getc(fin)) != EOF) {
		if (c == '\n') {
			if (ferror(stdout)){
				perror_reply(421, "control connection");
				(void) ftpd_pclose(fin);
				dologout(1);
				/* NOTREACHED */
			}
			if (ferror(fin)) {
				perror_reply(551, filename);
				(void) ftpd_pclose(fin);
				return;
			}
			*p = '\0';
			reply(0, "%s", str);
			p = str;
		} else	*p++ = c;
	}
	if (p != str) {
		*p = '\0';
		reply(0, "%s", str);
	}
	(void) ftpd_pclose(fin);
	reply(211, "End of Status");
}

statcmd()
{
	struct sockaddr_in *sin;
	u_char *a, *p;
	char str[FTP_BUFSIZ];

	lreply(211, "%s FTP server status:", hostname, version);
	reply(0, "     %s", version);
	sprintf(str, "     Connected to %s", remotehost);
	if (!isdigit(remotehost[0]))
		sprintf(&str[strlen(str)], " (%s)", inet_ntoa(his_addr.sin_addr));
	reply(0, "%s", str);
	if (auth_type) reply(0, "     Authentication type: %s", auth_type);
	if (logged_in) {
		if (guest)
			reply(0, "     Logged in anonymously");
		else
			reply(0, "     Logged in as %s", pw->pw_name);
	} else if (askpasswd)
		reply(0, "     Waiting for password");
	else if (temp_auth_type)
		reply(0, "     Waiting for authentication data");
	else
		reply(0, "     Waiting for user name");
	reply(0, "     PROTection level: %s", levelnames[level]);
	sprintf(str, "     TYPE: %s", typenames[type]);
	if (type == TYPE_A || type == TYPE_E)
		sprintf(&str[strlen(str)], ", FORM: %s", formnames[form]);
	if (type == TYPE_L)
#if 1
		strncat(str, " 8", sizeof (str) - strlen(str) - 1);
#else
/* this is silly. -- eichin@cygnus.com */
#if NBBY == 8
		sprintf(&str[strlen(str)], " %d", NBBY);
#else
		sprintf(&str[strlen(str)], " %d", bytesize);	/* need definition! */
#endif
#endif
	sprintf(&str[strlen(str)], "; STRUcture: %s; transfer MODE: %s",
	    strunames[stru], modenames[mode]);
	reply(0, "%s", str);
	if (data != -1)
		strcpy(str, "     Data connection open");
	else if (pdata != -1) {
		strcpy(str, "     in Passive mode");
		sin = &pasv_addr;
		goto printaddr;
	} else if (usedefault == 0) {
		strcpy(str, "     PORT");
		sin = &data_dest;
printaddr:
		a = (u_char *) &sin->sin_addr;
		p = (u_char *) &sin->sin_port;
#define UC(b) (((int) b) & 0xff)
		sprintf(&str[strlen(str)], " (%d,%d,%d,%d,%d,%d)", UC(a[0]),
			UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#undef UC
	} else
		strcpy(str, "     No data connection");
	reply(0, "%s", str);
	reply(211, "End of status");
}

fatal(s)
	char *s;
{
	reply(451, "Error in server: %s", s);
	reply(221, "Closing connection due to server error.");
	dologout(0);
	/* NOTREACHED */
}

char cont_char = ' ';

#ifdef STDARG
reply(int n, char *fmt, ...)
#else
/* VARARGS2 */
reply(n, fmt, p0, p1, p2, p3, p4, p5)
	int n;
	char *fmt;
#endif
{
	char buf[FTP_BUFSIZ];
#ifdef STDARG
	va_list ap;

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
#else
	sprintf(buf, fmt, p0, p1, p2, p3, p4, p5);
#endif

	if (auth_type) {
		char in[FTP_BUFSIZ], out[FTP_BUFSIZ];
		int length, kerror;
		/*
		 * File protection level also determines whether
		 * replies are 631 or 632.  Should be independent ...
		 */
		if (n) sprintf(in, "%d%c", n, cont_char);
		else in[0] = '\0';
		strncat(in, buf, sizeof (in) - strlen(in) - 1);
#ifdef KERBEROS
		if (strcmp(auth_type, "KERBEROS_V4") == 0)
		  if ((length = level == PROT_P ?
		    krb_mk_priv((unsigned char *)in, (unsigned char *)out,
				strlen(in), schedule, &kdata.session,
				&ctrl_addr, &his_addr)
		  : krb_mk_safe((unsigned char *)in, (unsigned char *)out,
				strlen(in), &kdata.session,
				&ctrl_addr, &his_addr)) == -1) {
			syslog(LOG_ERR, "krb_mk_%s failed for KERBEROS_V4",
					level == PROT_P ? "priv" : "safe");
			fputs(in,stdout);
		  } else
#endif /* KERBEROS */
#ifdef GSSAPI
		/* reply (based on level) */
		if (strcmp(auth_type, "GSSAPI") == 0) {
			gss_buffer_desc in_buf, out_buf;
			OM_uint32 maj_stat, min_stat;
			int conf_state;
		
			in_buf.value = in;
			in_buf.length = strlen(in) + 1;
			maj_stat = gss_seal(&min_stat, gcontext,
					    level == PROT_P, /* confidential */
					    GSS_C_QOP_DEFAULT,
					    &in_buf, &conf_state,
					    &out_buf);
			if (maj_stat != GSS_S_COMPLETE) {
				/* generally need to deal */
				secure_gss_error(maj_stat, min_stat,
					       (level==PROT_P)?
						 "gss_seal ENC didn't complete":
						 "gss_seal MIC didn't complete");
			} else if ((level == PROT_P) && !conf_state) {
				secure_error("GSSAPI didn't encrypt message");
			} else {
				memcpy(out, out_buf.value, 
				       length=out_buf.length);
				gss_release_buffer(&min_stat, &out_buf);
			}
		}
#endif /* GSSAPI */
		/* Other auth types go here ... */
		if (kerror = radix_encode(out, in, &length, 0)) {
			syslog(LOG_ERR, "Couldn't encode reply (%s)",
					radix_error(kerror));
			fputs(in,stdout);
		} else
		printf("%s%c%s", level == PROT_P ? "632" : "631",
				 n ? cont_char : '-', in);
	} else {
		if (n) printf("%d%c", n, cont_char);
		fputs(buf, stdout);
	}
	printf("\r\n");
	(void)fflush(stdout);
	if (debug) {
		if (n) syslog(LOG_DEBUG, "<--- %d%c", n, cont_char);
		syslog(LOG_DEBUG, "%s", buf);
	}
}

#ifdef STDARG
lreply(int n, char *fmt, ...)
#else
/* VARARGS2 */
lreply(n, fmt, p0, p1, p2, p3, p4, p5)
	int n;
	char *fmt;
#endif
{
	char buf[FTP_BUFSIZ];
#ifdef STDARG
	va_list ap;

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
#else
	sprintf(buf, fmt, p0, p1, p2, p3, p4, p5);
#endif
	cont_char = '-';
	reply(n, "%s", buf);
	cont_char = ' ';
}

ack(s)
	char *s;
{
	reply(250, "%s command successful.", s);
}

nack(s)
	char *s;
{
	reply(502, "%s command not implemented.", s);
}

/* ARGSUSED */
yyerror(s)
	char *s;
{
	char *cp;

	if (cp = strchr(cbuf,'\n'))
		*cp = '\0';
	reply(500, "'%s': command not understood.", cbuf);
}

delete_file(name)
	char *name;
{
	struct stat st;

	if (stat(name, &st) < 0) {
		perror_reply(550, name);
		return;
	}
	if ((st.st_mode&S_IFMT) == S_IFDIR) {
		if (rmdir(name) < 0) {
			perror_reply(550, name);
			return;
		}
		goto done;
	}
	if (unlink(name) < 0) {
		perror_reply(550, name);
		return;
	}
done:
	ack("DELE");
}

cwd(path)
	char *path;
{
	if (chdir(path) < 0)
		perror_reply(550, path);
	else
		ack("CWD");
}

makedir(name)
	char *name;
{
	if (mkdir(name, 0777) < 0)
		perror_reply(550, name);
	else
		reply(257, "MKD command successful.");
}

removedir(name)
	char *name;
{
	if (rmdir(name) < 0)
		perror_reply(550, name);
	else
		ack("RMD");
}

pwd()
{
	char path[MAXPATHLEN + 1];

	if (getcwd(path, sizeof path) == (char *)NULL)
#ifdef POSIX
		perror_reply(550, path);
#else
		reply(550, "%s.", path);
#endif
	else
		reply(257, "\"%s\" is current directory.", path);
}

char *
renamefrom(name)
	char *name;
{
	struct stat st;

	if (stat(name, &st) < 0) {
		perror_reply(550, name);
		return ((char *)0);
	}
	reply(350, "File exists, ready for destination name");
	return (name);
}

renamecmd(from, to)
	char *from, *to;
{
	if (rename(from, to) < 0)
		perror_reply(550, "rename");
	else
		ack("RNTO");
}

dolog(sin)
	struct sockaddr_in *sin;
{
	struct hostent *hp = gethostbyaddr((char *)&sin->sin_addr,
		sizeof (struct in_addr), AF_INET);
	time_t t, time();
	extern char *ctime();

	if (hp)
		(void) strncpy(remotehost, hp->h_name, sizeof (remotehost));
	else
		(void) strncpy(remotehost, inet_ntoa(sin->sin_addr),
		    sizeof (remotehost));
#ifdef SETPROCTITLE
	sprintf(proctitle, "%s: connected", remotehost);
	setproctitle(proctitle);
#endif /* SETPROCTITLE */

	if (logging) {
		t = time((time_t *) 0);
		syslog(LOG_INFO, "connection from %s at %s",
		    remotehost, ctime(&t));
	}
}

/*
 * Record logout in wtmp file
 * and exit with supplied status.
 */
dologout(status)
	int status;
{
	if (logged_in) {
		(void) seteuid((uid_t)0);
		ftp_logwtmp(ttyline, "", "");
	}
	/* beware of flushing buffers after a SIGPIPE */
	_exit(status);
}

void
myoob()
{
	char *cp, *cs;
	extern char *strpbrk();

	/* only process if transfer occurring */
	if (!transflag)
		return;
	cp = tmpline;
	if (getline(cp, sizeof(tmpline), stdin) == NULL) {
		reply(221, "You could at least say goodbye.");
		dologout(0);
	}
	upper(cp);
	if ((cs = strpbrk(cp, "\r\n")))
		*cs++ = '\0';
	if (strcmp(cp, "ABOR") == 0) {
		tmpline[0] = '\0';
		reply(426, "Transfer aborted. Data connection closed.");
		reply(226, "Abort successful");
		siglongjmp(urgcatch, 1);
	}
	if (strcmp(cp, "STAT") == 0) {
		if (file_size != (off_t) -1)
			reply(213, "Status: %lu of %lu bytes transferred",
			    byte_count, file_size);
		else
			reply(213, "Status: %lu bytes transferred", byte_count);
	}
}

/*
 * Note: a response of 425 is not mentioned as a possible response to
 * 	the PASV command in RFC959. However, it has been blessed as
 * 	a legitimate response by Jon Postel in a telephone conversation
 *	with Rick Adams on 25 Jan 89.
 */
passive()
{
	int len;
	register char *p, *a;

	pdata = socket(AF_INET, SOCK_STREAM, 0);
	if (pdata < 0) {
		perror_reply(425, "Can't open passive connection");
		return;
	}
	pasv_addr = ctrl_addr;
	pasv_addr.sin_port = 0;
	(void) seteuid((uid_t)0);
	if (bind(pdata, (struct sockaddr *)&pasv_addr, sizeof(pasv_addr)) < 0) {
		(void) seteuid((uid_t)pw->pw_uid);
		goto pasv_error;
	}
	(void) seteuid((uid_t)pw->pw_uid);
	len = sizeof(pasv_addr);
	if (getsockname(pdata, (struct sockaddr *) &pasv_addr, &len) < 0)
		goto pasv_error;
	if (listen(pdata, 1) < 0)
		goto pasv_error;
	a = (char *) &pasv_addr.sin_addr;
	p = (char *) &pasv_addr.sin_port;

#define UC(b) (((int) b) & 0xff)

	reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
		UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
	return;

pasv_error:
	(void) close(pdata);
	pdata = -1;
	perror_reply(425, "Can't open passive connection");
	return;
}

/*
 * Generate unique name for file with basename "local".
 * The file named "local" is already known to exist.
 * Generates failure reply on error.
 */
char *
gunique(local)
	char *local;
{
	static char new[MAXPATHLEN];
	struct stat st;
	char *cp = strrchr(local, '/');
	int count = 0;

	if (cp)
		*cp = '\0';
	if (stat(cp ? local : ".", &st) < 0) {
		perror_reply(553, cp ? local : ".");
		return((char *) 0);
	}
	if (cp)
		*cp = '/';
	(void) strcpy(new, local);
	cp = new + strlen(new);
	*cp++ = '.';
	for (count = 1; count < 100; count++) {
		(void) sprintf(cp, "%d", count);
		if (stat(new, &st) < 0)
			return(new);
	}
	reply(452, "Unique file name cannot be created.");
	return((char *) 0);
}

/*
 * Format and send reply containing system error number.
 */
perror_reply(code, string)
	int code;
	char *string;
{
	reply(code, "%s: %s.", string, strerror(errno));
}

auth(type)
char *type;
{
	if (auth_type)
		reply(534, "Authentication type already set to %s", auth_type);
	else
#ifdef KERBEROS
	if (strcmp(type, "KERBEROS_V4") == 0)
		reply(334, "Using authentication type %s; ADAT must follow",
				temp_auth_type = type);
	else
#endif /* KERBEROS */
#ifdef GSSAPI
	if (strcmp(type, "GSSAPI") == 0)
		reply(334, "Using authentication type %s; ADAT must follow",
				temp_auth_type = type);
	else
#endif /* KERBEROS */
	/* Other auth types go here ... */
		reply(504, "Unknown authentication type: %s", type);
}

auth_data(data)
char *data;
{
	int kerror, length;
#ifdef KERBEROS
	int i;
	static char *service;
	char instance[INST_SZ];
	u_long cksum;
	char buf[FTP_BUFSIZ];
	u_char out_buf[sizeof(buf)];
#endif /* KERBEROS */

	if (auth_type) {
		reply(503, "Authentication already established");
		return(0);
	}
	if (!temp_auth_type) {
		reply(503, "Must identify AUTH type before ADAT");
		return(0);
	}
#ifdef KERBEROS
	if (strcmp(temp_auth_type, "KERBEROS_V4") == 0) {
		if (kerror = radix_encode(data, out_buf, &length, 1)) {
			reply(501, "Couldn't decode ADAT (%s)",
			      radix_error(kerror));
			syslog(LOG_ERR, "Couldn't decode ADAT (%s)",
			       radix_error(kerror));
			return(0);
		}
		(void) memcpy((char *)ticket.dat, (char *)out_buf, ticket.length = length);
		strcpy(instance, "*");
		if (!service) {
			char realm[REALM_SZ];
			des_cblock key;
			
			service = "ftp";
			if (krb_get_lrealm(realm, 1) == KSUCCESS &&
			    read_service_key(service, instance, realm, 0, keyfile, key))
				service = "rcmd";
			else
				(void) memset(key, 0, sizeof(key));
		}
		if (kerror = krb_rd_req(&ticket, service, instance,
					his_addr.sin_addr.s_addr, &kdata, keyfile)) {
			secure_error("ADAT: Kerberos V4 krb_rd_req: %s",
				     krb_get_err_text(kerror));
			return(0);
		}
		/* add one to the (formerly) sealed checksum, and re-seal it */
		cksum = kdata.checksum + 1;
		cksum = htonl(cksum);
		key_sched(kdata.session,schedule);
		if ((length = krb_mk_safe((u_char *)&cksum, out_buf, sizeof(cksum),
					  &kdata.session,&ctrl_addr, &his_addr)) == -1) {
			secure_error("ADAT: krb_mk_safe failed");
			return(0);
		}
		if (kerror = radix_encode(out_buf, buf, &length, 0)) {
			secure_error("Couldn't encode ADAT reply (%s)",
				     radix_error(kerror));
			return(0);
		}
		reply(235, "ADAT=%s", buf);
		/* Kerberos V4 authentication succeeded */
		auth_type = temp_auth_type;
		temp_auth_type = NULL;
		return(1);
	}
#endif /* KERBEROS */
#ifdef GSSAPI
	if (strcmp(temp_auth_type, "GSSAPI") == 0) {
		int replied = 0;
		int found = 0;
		gss_cred_id_t server_creds;     
		gss_name_t client;
		int ret_flags;
		struct gss_channel_bindings_struct chan;
		gss_buffer_desc name_buf;
		gss_name_t server_name;
		OM_uint32 acquire_maj, acquire_min, accept_maj, accept_min,
				stat_maj, stat_min;
		gss_OID mechid;
		gss_buffer_desc tok, out_tok;
		char gbuf[FTP_BUFSIZ];
		u_char gout_buf[FTP_BUFSIZ];
		char localname[MAXHOSTNAMELEN];
		char service_name[MAXHOSTNAMELEN+10];
		char **service;
		struct hostent *hp;

		chan.initiator_addrtype = GSS_C_AF_INET;
		chan.initiator_address.length = 4;
		chan.initiator_address.value = &his_addr.sin_addr.s_addr;
		chan.acceptor_addrtype = GSS_C_AF_INET;
		chan.acceptor_address.length = 4;
		chan.acceptor_address.value = &ctrl_addr.sin_addr.s_addr;
		chan.application_data.length = 0;
		chan.application_data.value = 0;

		if (kerror = radix_encode(data, gout_buf, &length, 1)) {
			reply(501, "Couldn't decode ADAT (%s)",
			      radix_error(kerror));
			syslog(LOG_ERR, "Couldn't decode ADAT (%s)",
			       radix_error(kerror));
			return(0);
		}
		tok.value = gout_buf;
		tok.length = length;

		if (gethostname(localname, MAXHOSTNAMELEN)) {
			reply(501, "couldn't get local hostname (%d)\n", errno);
			syslog(LOG_ERR, "Couldn't get local hostname (%d)", errno);
			return 0;
		}
		if (!(hp = gethostbyname(localname))) {
			extern int h_errno;
			reply(501, "couldn't canonicalize local hostname (%d)\n", h_errno);
			syslog(LOG_ERR, "Couldn't canonicalize local hostname (%d)", h_errno);
			return 0;
		}
		strcpy(localname, hp->h_name);

		for (service = gss_services; *service; service++) {
			sprintf(service_name, "%s@%s", *service, localname);
			name_buf.value = service_name;
			name_buf.length = strlen(name_buf.value) + 1;
			if (debug)
				syslog(LOG_INFO, "importing <%s>", service_name);
			stat_maj = gss_import_name(&stat_min, &name_buf, 
						   gss_nt_service_name,
						   &server_name);
			if (stat_maj != GSS_S_COMPLETE) {
				reply_gss_error(501, stat_maj, stat_min,
						"importing name");
				syslog(LOG_ERR, "gssapi error importing name");
				return 0;
			}
			
			acquire_maj = gss_acquire_cred(&acquire_min, server_name, 0,
						       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
						       &server_creds, NULL, NULL);
			(void) gss_release_name(&stat_min, &server_name);

			if (acquire_maj != GSS_S_COMPLETE)
				continue;

			found++;

			gcontext = GSS_C_NO_CONTEXT;

			accept_maj = gss_accept_sec_context(&accept_min,
							    &gcontext, /* context_handle */
							    server_creds, /* verifier_cred_handle */
							    &tok, /* input_token */
							    &chan, /* channel bindings */
							    &client, /* src_name */
							    &mechid, /* mech_type */
							    &out_tok, /* output_token */
							    &ret_flags,
							    NULL, 	/* ignore time_rec */
							    NULL   /* ignore del_cred_handle */
							    );
			if (accept_maj==GSS_S_COMPLETE||accept_maj==GSS_S_CONTINUE_NEEDED)
				break;
		}

		if (found) {
			if (accept_maj!=GSS_S_COMPLETE && accept_maj!=GSS_S_CONTINUE_NEEDED) {
				reply_gss_error(535, accept_maj, accept_min,
						"accepting context");
				syslog(LOG_ERR, "failed accepting context");
				(void) gss_release_cred(&stat_min, &server_creds);
				return 0;
			}
		} else {
			reply_gss_error(501, stat_maj, stat_min,
					"acquiring credentials");
			syslog(LOG_ERR, "gssapi error acquiring credentials");
			return 0;
		}

		if (out_tok.length) {
			if (kerror = radix_encode(out_tok.value, gbuf, &out_tok.length, 0)) {
				secure_error("Couldn't encode ADAT reply (%s)",
					     radix_error(kerror));
				syslog(LOG_ERR, "couldn't encode ADAT reply");
				return(0);
			}
			if (stat_maj == GSS_S_COMPLETE) {
				reply(235, "ADAT=%s", gbuf);
				replied = 1;
			} else {
				/* If the server accepts the security data, and
				   requires additional data, it should respond with
				   reply code 335. */
				reply(335, "ADAT=%s", gbuf);
			}
			(void) gss_release_buffer(&stat_min, &out_tok);
		}
		if (stat_maj == GSS_S_COMPLETE) {
			/* GSSAPI authentication succeeded */
			stat_maj = gss_display_name(&stat_min, client, &client_name, 
						    &mechid);
			if (stat_maj != GSS_S_COMPLETE) {
				/* "If the server rejects the security data (if 
				   a checksum fails, for instance), it should 
				   respond with reply code 535." */
				reply_gss_error(535, stat_maj, stat_min,
						"extracting GSSAPI identity name");
				syslog(LOG_ERR, "gssapi error extracting identity");
				(void) gss_release_cred(&stat_min, &server_creds);
				return 0;
			}
			/* If the server accepts the security data, but does
				   not require any additional data (i.e., the security
				   data exchange has completed successfully), it must
				   respond with reply code 235. */
			if (!replied) reply(235, "GSSAPI Authentication succeeded");
				
			auth_type = temp_auth_type;
			temp_auth_type = NULL;
				
			(void) gss_release_cred(&stat_min, &server_creds);
			return(1);
		} else if (stat_maj == GSS_S_CONTINUE_NEEDED) {
			/* If the server accepts the security data, and
				   requires additional data, it should respond with
				   reply code 335. */
			reply(335, "more data needed");
			(void) gss_release_cred(&stat_min, &server_creds);
			return(0);
		} else {
			/* "If the server rejects the security data (if 
				   a checksum fails, for instance), it should 
				   respond with reply code 535." */
			reply_gss_error(535, stat_maj, stat_min, 
					"GSSAPI failed processing ADAT");
			syslog(LOG_ERR, "GSSAPI failed processing ADAT");
			(void) gss_release_cred(&stat_min, &server_creds);
			return(0);
		}
	}
#endif /* GSSAPI */
	/* Other auth types go here ... */
	/* Also need to check authorization, but that is done in user() */
}

static char *onefile[] = {
	"",
	0
};

/* returns:
 *	n>=0 on success
 *	-1 on error
 *	-2 on security error
 */
#ifdef STDARG
secure_fprintf(FILE *stream, char *fmt, ...)
#else
secure_fprintf(stream, fmt, p1, p2, p3, p4, p5)
FILE *stream;
char *fmt;
#endif
{
        char s[FTP_BUFSIZ];
        int rval;
#ifdef STDARG
        va_list ap;

        va_start(ap, fmt);
        if (level == PROT_C) rval = vfprintf(stream, fmt, ap);
        else {
                vsprintf(s, fmt, ap);
                rval = secure_write(fileno(stream), s, strlen(s));
        }
        va_end(ap);

        return(rval);
#else
        if (level == PROT_C)
                return(fprintf(stream, fmt, p1, p2, p3, p4, p5));
        sprintf(s, fmt, p1, p2, p3, p4, p5);
        return(secure_write(fileno(stream), s, strlen(s)));
#endif
}

send_file_list(whichfiles)
	char *whichfiles;
{
	struct stat st;
	DIR *dirp = NULL;
	struct dirent *dir;
	FILE *dout = NULL;
	register char **dirlist, *dirname;
	int simple = 0;
	char *strpbrk();
	int ret = 0;

	if (strpbrk(whichfiles, "~{[*?") != NULL) {
		extern char **ftpglob(), *globerr;

		globerr = NULL;
		dirlist = ftpglob(whichfiles);
		if (globerr != NULL) {
			reply(550, globerr);
			return;
		} else if (dirlist == NULL) {
			errno = ENOENT;
			perror_reply(550, whichfiles);
			return;
		}
	} else {
		onefile[0] = whichfiles;
		dirlist = onefile;
		simple = 1;
	}

	if (sigsetjmp(urgcatch, 1)) {
		transflag = 0;
		(void)secure_flush(fileno(dout));
		return;
	}
	while (dirname = *dirlist++) {
		if (stat(dirname, &st) < 0) {
			/*
			 * If user typed "ls -l", etc, and the client
			 * used NLST, do what the user meant.
			 */
			if (dirname[0] == '-' && *dirlist == NULL &&
			    transflag == 0) {
				retrieve("/bin/ls %s", dirname);
				return;
			}
			perror_reply(550, whichfiles);
			if (dout != NULL) {
				(void) fclose(dout);
				transflag = 0;
				data = -1;
				pdata = -1;
			}
			return;
		}

		if ((st.st_mode&S_IFMT) == S_IFREG) {
			if (dout == NULL) {
				dout = dataconn("file list", (off_t)-1, "w");
				if (dout == NULL)
					return;
				transflag++;
			}
			if ((ret = secure_fprintf(dout, "%s%s\n", dirname,
				type == TYPE_A ? "\r" : "")) < 0)
					goto data_err;
			byte_count += strlen(dirname) + 1;
			continue;
		} else if ((st.st_mode&S_IFMT) != S_IFDIR)
			continue;

		if ((dirp = opendir(dirname)) == NULL)
			continue;

		while ((dir = readdir(dirp)) != NULL) {
			char nbuf[MAXPATHLEN];

			if (dir->d_name[0] == '.' && dir->d_name[1] == '\0')
				continue;
			if (dir->d_name[0] == '.' && dir->d_name[1] == '.' &&
			    dir->d_name[2] == '\0')
				continue;

			sprintf(nbuf, "%s/%s", dirname, dir->d_name);

			/*
			 * We have to do a stat to insure it's
			 * not a directory or special file.
			 */
			if (simple || (stat(nbuf, &st) == 0 &&
			    (st.st_mode&S_IFMT) == S_IFREG)) {
				if (dout == NULL) {
					dout = dataconn("file list", (off_t)-1,
						"w");
					if (dout == NULL)
						return;
					transflag++;
				}
				if (nbuf[0] == '.' && nbuf[1] == '/')
				{
					if ((ret = secure_fprintf(dout, "%s%s\n", &nbuf[2],
						type == TYPE_A ? "\r" : "")) < 0)
							goto data_err;
				}
				else
					if ((ret = secure_fprintf(dout, "%s%s\n", nbuf,
						type == TYPE_A ? "\r" : "")) < 0)
							goto data_err;
				byte_count += strlen(nbuf) + 1;
			}
		}
		(void) closedir(dirp);
	}
	ret = secure_write(fileno(dout), "", 0);
data_err:
	if (dout == NULL)
		reply(550, "No files found.");
	else if (ferror(dout) != 0 || ret == EOF)
		perror_reply(550, "Data connection");
	else if (ret != -2)
		reply(226, "Transfer complete.");

	transflag = 0;
	if (dout != NULL)
		(void) fclose(dout);
	data = -1;
	pdata = -1;
}

#ifdef SETPROCTITLE
/*
 * clobber argv so ps will show what we're doing.
 * (stolen from sendmail)
 * warning, since this is usually started from inetd.conf, it
 * often doesn't have much of an environment or arglist to overwrite.
 */

setproctitle(buf)
char *buf;
{
	register char *p, *bp, ch;
	register int i;

	/* make ps print our process name */
	p = Argv[0];
	*p++ = '-';

	i = strlen(buf);
	if (i > LastArgv - p - 2) {
		i = LastArgv - p - 2;
		buf[i] = '\0';
	}
	bp = buf;
	while (ch = *bp++)
		if (ch != '\n' && ch != '\r')
			*p++ = ch;
	while (p < LastArgv)
		*p++ = ' ';
}
#endif /* SETPROCTITLE */
#ifdef GSSAPI
reply_gss_error(code, maj_stat, min_stat, s)
int code;
OM_uint32 maj_stat, min_stat;
char *s;
{
	/* a lot of work just to report the error */
	OM_uint32 gmaj_stat, gmin_stat;
	gss_buffer_desc msg;
	int msg_ctx;
	msg_ctx = 0;
	while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
					       GSS_C_GSS_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
			lreply(code, "GSSAPI error major: %s", 
			       (char*)msg.value);
			(void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	}
	msg_ctx = 0;
	while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, min_stat,
					       GSS_C_MECH_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
			lreply(code, "GSSAPI error minor: %s",
			       (char*)msg.value);
			(void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	}
	reply(code, "GSSAPI error: %s", s);
}

secure_gss_error(maj_stat, min_stat, s)
OM_uint32 maj_stat, min_stat;
char *s;
{
  return reply_gss_error(535, maj_stat, min_stat, s);
}


#include <krb5.h>
/* ftpd_userok -- hide details of getting the name and verifying it */
/* returns 0 for OK */
ftpd_userok(client_name, name)
	gss_buffer_t client_name;
	char *name;
{
	int retval = -1;
	krb5_boolean k5ret;
	krb5_context kc;
	krb5_principal p;
	krb5_error_code kerr;
	
	kerr = krb5_init_context(&kc);
	if (kerr)
		return -1;

	kerr = krb5_parse_name(kc, client_name->value, &p);
	if (kerr) { retval = -1; goto fail; }
	k5ret = krb5_kuserok(kc, p, name);
	if (k5ret == TRUE)
		retval = 0;
	else 
		retval = 1;
	krb5_free_principal(kc, p);
 fail:
	krb5_free_context(kc);
	return retval;
}
#endif /* GSSAPI */
