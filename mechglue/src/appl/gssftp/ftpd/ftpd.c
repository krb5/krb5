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
#ifndef KRB5_KRB4_COMPAT
/* krb.h gets this, and Ultrix doesn't protect vs multiple inclusion */
#include <sys/socket.h>
#endif
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
#include <grp.h> 
#include <setjmp.h>
#ifndef POSIX_SETJMP
#undef sigjmp_buf
#undef sigsetjmp
#undef siglongjmp
#define sigjmp_buf	jmp_buf
#define sigsetjmp(j,s)	setjmp(j)
#define siglongjmp	longjmp
#endif
#ifndef KRB5_KRB4_COMPAT
/* krb.h gets this, and Ultrix doesn't protect vs multiple inclusion */
#include <netdb.h>
#endif
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
#include <libpty.h>

#ifdef NEED_SETENV
extern int setenv(char *, char *, int);
#endif

#ifndef L_SET
#define L_SET 0
#endif
#ifndef L_INCR
#define L_INCR 1
#endif

#ifndef HAVE_STRERROR
#define strerror(error)	(sys_errlist[error])
#ifdef NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif
#endif

extern char *mktemp ();
char *ftpusers;
extern int yyparse(void);

#include <k5-util.h>
#include "port-sockets.h"

#ifdef KRB5_KRB4_COMPAT
#include <krb5.h>
#include <krb.h>

AUTH_DAT kdata;
KTEXT_ST ticket;
MSG_DAT msg_data;
Key_schedule schedule;
char *keyfile;
static char *krb4_services[] = { "ftp", "rcmd", NULL };
#endif /* KRB5_KRB4_COMPAT */

#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
gss_ctx_id_t gcontext;
gss_buffer_desc client_name;
static char *gss_services[] = { "ftp", "host", NULL };

#include <krb5.h>
krb5_context kcontext;
krb5_ccache ccache;

static void ftpd_gss_convert_creds(char *name, gss_cred_id_t);
static int ftpd_gss_userok(gss_buffer_t, char *name);

static void log_gss_error(int, OM_uint32, OM_uint32, const char *);

#endif /* GSSAPI */

char *auth_type;	/* Authentication succeeded?  If so, what type? */
static char *temp_auth_type;
int authorized;		/* Auth succeeded and was accepted by krb4 or gssapi */
int have_creds;		/* User has credentials on disk */

/*
 * File containing login names
 * NOT to be used on this machine.
 * Commonly used to disallow uucp.
 */
#include "ftpd_var.h"
#include "secure.h"

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
int	allow_ccc = 0;    /* whether or not the CCC command is allowed */
int	ccc_ok = 0;       /* whether or not to accept cleartext commands */
int	timeout = 900;    /* timeout after 15 minutes of inactivity */
int	maxtimeout = 7200;/* don't allow idle time to be set beyond 2 hours */
int	logging;
int	authlevel;
int	want_creds;
int	guest;
int	restricted;
int	type;
int	clevel;			/* control protection level */
int	dlevel;			/* data protection level */
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
char    pathbuf[MAXPATHLEN + 1];
char	hostname[MAXHOSTNAMELEN];
char	remotehost[MAXHOSTNAMELEN];
char	rhost_addra[16];
char	*rhost_sane;

/* Defines for authlevel */
#define AUTHLEVEL_NONE		0
#define AUTHLEVEL_AUTHENTICATE	1
#define AUTHLEVEL_AUTHORIZE	2

/*
 * Timeout intervals for retrying connections
 * to hosts that don't accept PORT cmds.  This
 * is a kludge, but given the problems with TCP...
 */
#define	SWAITMAX	90	/* wait at most 90 seconds */
#define	SWAITINT	5	/* interval between retries */

int	swaitmax = SWAITMAX;
int	swaitint = SWAITINT;

void	lostconn(int), myoob(int);
FILE	*getdatasock(char *); 
#if defined(__STDC__)
/* 
 * The following prototypes must be ANSI for systems for which
 * sizeof(off_t) > sizeof(int) to prevent stack overflow problems 
 */
FILE	*dataconn(char *name, off_t size, char *mymode);
void	send_data(FILE *instr, FILE *outstr, off_t blksize);
#else
void	send_data();
FILE	*dataconn();
#endif
static void dolog(struct sockaddr_in *);
static int receive_data(FILE *, FILE *);
static void login(char *passwd, int logincode);
static void end_login(void);
static int disallowed_user(char *);
static int restricted_user(char *);
static int checkuser(char *);
static char *gunique(char *);

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

int stripdomain = 1;
int maxhostlen = 0;
int always_ip = 0;

int
main(argc, argv, envp)
	int argc;
	char *argv[];
	char **envp;
{
	int addrlen, c, on = 1, tos, port = -1;
	extern char *optarg;
	extern int optopt;
#ifdef KRB5_KRB4_COMPAT
	char *option_string = "AaCcdElp:r:s:T:t:U:u:vw:";
#else /* !KRB5_KRB4_COMPAT */
	char *option_string = "AaCcdElp:r:T:t:U:u:vw:";
#endif /* KRB5_KRB4_COMPAT */
	ftpusers = _PATH_FTPUSERS_DEFAULT;

#ifdef KRB5_KRB4_COMPAT
	keyfile = KEYFILE;
#endif /* KRB5_KRB4_COMPAT */
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

#ifdef GSSAPI
	krb5_init_context(&kcontext);
#endif

	while ((c = getopt(argc, argv, option_string)) != -1) {
		switch (c) {

		case 'v':
			debug = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'E':
			if (!authlevel)
				authlevel = AUTHLEVEL_AUTHENTICATE;
			break;

		case 'l':
			logging ++;
			break;

		case 'a':
			authlevel = AUTHLEVEL_AUTHORIZE;
			break;

		case 'A':
			authlevel = AUTHLEVEL_AUTHENTICATE;
			break;

		case 'C':
			want_creds = 1;
			break;

		case 'c':
			allow_ccc = 1;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'r':
			setenv("KRB_CONF", optarg, 1);
			break;

#ifdef KRB5_KRB4_COMPAT
		case 's':
			keyfile = optarg;
			break;
#endif /* KRB5_KRB4_COMPAT */

		case 't':
			timeout = atoi(optarg);
			if (maxtimeout < timeout)
				maxtimeout = timeout;
			break;

		case 'T':
			maxtimeout = atoi(optarg);
			if (timeout > maxtimeout)
				timeout = maxtimeout;
			break;

		case 'u':
			{
			    int val = 0;
			    char *umask_val = optarg;

			    while (*umask_val >= '0' && *umask_val <= '9') {
				    val = val*8 + *umask_val - '0';
				    umask_val++;
			    }
			    if (*umask_val != ' ' && *umask_val != '\0')
				    fprintf(stderr, "ftpd: Bad value for -u\n");
			    else
				    defumask = val;
			    break;
			}

		case 'U':
			ftpusers = optarg;
			break;

		case 'w':
		{
			char *foptarg;
			foptarg = optarg;

			if (!strcmp(foptarg, "ip"))
				always_ip = 1;
			else {
				char *cp2;
				cp2 = strchr(foptarg, ',');
				if (cp2 == NULL)
					maxhostlen = atoi(foptarg);
				else if (*(++cp2)) {
					if (!strcmp(cp2, "striplocal"))
						stripdomain = 1;
					else if (!strcmp(cp2, "nostriplocal"))
						stripdomain = 0;
					else {
						fprintf(stderr,
							"ftpd: bad arg to -w\n");
						exit(1);
					}
					*(--cp2) = '\0';
					maxhostlen = atoi(foptarg);
				}
			}
			break;
		}
		default:
			fprintf(stderr, "ftpd: Unknown flag -%c ignored.\n",
			     (char)optopt);
			break;
		}
	}

	if (port != -1) {
		struct sockaddr_in sin4;
		int s, ns;
		socklen_t sz;

		/* Accept an incoming connection on port.  */
		sin4.sin_family = AF_INET;
		sin4.sin_addr.s_addr = INADDR_ANY;
		sin4.sin_port = htons(port);
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) {
			perror("socket");
			exit(1);
		}
		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&on, sizeof(on));
		if (bind(s, (struct sockaddr *)&sin4, sizeof sin4) < 0) {
			perror("bind");
			exit(1);
		}
		if (listen(s, 1) < 0) {
			perror("listen");
			exit(1);
		}
		sz = sizeof sin4;
		ns = accept(s, (struct sockaddr *)&sin4, &sz);
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
	clevel = dlevel = PROT_C;
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
lostconn(sig)
int sig;
{
	if (debug)
		syslog(LOG_DEBUG, "lost connection");
	dologout(-1);
}

static char ttyline[20];

/*
 * Helper function for sgetpwnam().
 */
static char *
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
static struct passwd *
sgetpwnam(name)
	char *name;
{
	static struct passwd save;
	register struct passwd *p;
#ifdef HAVE_SHADOW
	register struct spwd *sp;
#endif
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

/*
 * Expand the given pathname relative to the current working directory.
 */
static char *
path_expand(path)
       char *path;
{
	pathbuf[0] = '\x0';
	if (!path) return pathbuf;
	/* Don't bother with getcwd() if the path is absolute */
	if (path[0] != '/') {
	        if (!getcwd(pathbuf, sizeof pathbuf)) {
		        pathbuf[0] = '\x0';
			syslog(LOG_ERR, "getcwd() failed");
		}
		else {
		        int len = strlen(pathbuf);
			if (pathbuf[len-1] != '/') {
			        pathbuf[len++] = '/';
				pathbuf[len] = '\x0';
			}
		}
	}
	return strncat(pathbuf, path,
		       sizeof (pathbuf) - strlen(pathbuf) - 1);
}

/*
 * Set data channel protection level
 */
void
setdlevel(prot_level)
int prot_level;
{
	switch (prot_level) {
		case PROT_S:
#ifndef NOENCRYPTION
		case PROT_P:
#endif
			if (auth_type)
		case PROT_C:
				reply(200, "Data channel protection level set to %s.",
					(dlevel = prot_level) == PROT_S ?
						"safe" : dlevel == PROT_P ?
						"private" : "clear");
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
 * ftpusers, and ftp account exists, set guest and pw, then just return.
 * If account doesn't exist, ask for passwd anyway.  Otherwise, check user
 * requesting login privileges.  Disallow anyone who does not have a standard
 * shell as returned by getusershell().  Disallow anyone mentioned in the file
 * ftpusers to allow people such as root and uucp to be avoided, except
 * for users whose names are followed by whitespace and then the keyword
 * "restrict."  Restricted users are allowed to login, but a chroot() is
 * done to their home directory.
 */
void
user(name)
	char *name;
{
	register char *cp;
	char *shell;
	char buf[FTP_BUFSIZ];
#ifdef HAVE_GETUSERSHELL
	char *getusershell();
#endif

	if (logged_in) {
		if (guest) {
			reply(530, "Can't change user from guest login.");
			return;
		}
		end_login();
	}

	authorized = guest = 0;
	if (strcmp(name, "ftp") == 0 || strcmp(name, "anonymous") == 0) {
		if (disallowed_user("ftp") || disallowed_user("anonymous"))
			reply(530, "User %s access denied.", name);
		else if ((pw = sgetpwnam("ftp")) != NULL) {
			guest = 1;
			askpasswd = 1;
			reply(331, "Guest login ok, send ident as password.");
		} else
			reply(530, "User %s unknown.", name);
		return;
	}

	/*
	 * If authentication is required, check that before anything
	 * else to avoid leaking information.
	 */
	if (authlevel && !auth_type) {
		reply(530,
		      "Must perform authentication before identifying USER.");
		return;
	}

	pw = sgetpwnam(name);
	if (pw) {
		if ((shell = pw->pw_shell) == NULL || *shell == 0)
			shell = "/bin/sh";
#ifdef HAVE_GETUSERSHELL
		setusershell();
		while ((cp = getusershell()) != NULL)
			if (strcmp(cp, shell) == 0)
				break;
		endusershell();
#else
		cp = shell;
#endif
		if (cp == NULL || disallowed_user(name)) {
			reply(530, "User %s access denied.", name);
			if (logging)
				syslog(LOG_NOTICE,
				    "FTP LOGIN REFUSED FROM %s, %s (%s)",
				    rhost_addra, remotehost, name);
			pw = (struct passwd *) NULL;
			return;
		}
		restricted = restricted_user(name);
	}

	if (auth_type) {
		int result;
#ifdef GSSAPI
		if (auth_type && strcmp(auth_type, "GSSAPI") == 0) {
			int len;

			authorized = ftpd_gss_userok(&client_name, name) == 0;
			len = sizeof("GSSAPI user  is not authorized as "
				     "; Password required.")
				+ strlen(client_name.value)
				+ strlen(name);
			if (len >= sizeof(buf)) {
				syslog(LOG_ERR, "user: username too long");
				name = "[username too long]";
			}
			sprintf(buf, "GSSAPI user %s is%s authorized as %s",
				(char *) client_name.value, 
				authorized ? "" : " not",
				name);
		}
#ifdef KRB5_KRB4_COMPAT
		else
#endif /* KRB5_KRB4_COMPAT */
#endif /* GSSAPI */
#ifdef KRB5_KRB4_COMPAT
		if (auth_type && strcmp(auth_type, "KERBEROS_V4") == 0) {
			int len;

			authorized = kuserok(&kdata,name) == 0;
			len = sizeof("Kerberos user .@ is not authorized as "
				     "; Password required.")
				+ strlen(kdata.pname)
				+ strlen(kdata.pinst)
				+ strlen(kdata.prealm)
				+ strlen(name);
			if (len >= sizeof(buf)) {
				syslog(LOG_ERR, "user: username too long");
				name = "[username too long]";
			}
			sprintf(buf, "Kerberos user %s%s%s@%s is%s authorized as %s",
				kdata.pname, *kdata.pinst ? "." : "",
				kdata.pinst, kdata.prealm,
				authorized ? "" : " not", name);
		}
#endif /* KRB5_KRB4_COMPAT */

		if (!authorized && authlevel == AUTHLEVEL_AUTHORIZE) {
			strncat(buf, "; Access denied.",
				sizeof(buf) - strlen(buf) - 1);
			result = 530;
			pw = NULL;
		} else if (!authorized || (want_creds && !have_creds)) {
			strncat(buf, "; Password required.",
				sizeof(buf) - strlen(buf) - 1);
			askpasswd = 1;
			result = 331;
		} else
			result = 232;
		reply(result, "%s", buf);
		syslog(authorized ? LOG_INFO : LOG_ERR, "%s", buf);

		if (result == 232)
			login(NULL, result);
		return;
	}

	/* User didn't authenticate and authentication wasn't required. */
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
 * Check if a user is in the file ftpusers.
 * Return 1 if they are (a disallowed user), -1 if their username
 * is followed by "restrict." (a restricted user).  Otherwise return 0.
 */
static int
checkuser(name)
	char *name;
{
	register FILE *fd;
	register char *p;
	char line[FTP_BUFSIZ];

	if ((fd = fopen(ftpusers, "r")) != NULL) {
	     while (fgets(line, sizeof(line), fd) != NULL) {
	          if ((p = strchr(line, '\n')) != NULL) {
			*p = '\0';
			if (line[0] == '#')
			     continue;
			if (strcmp(line, name) == 0)
			     return (1);
			if (strncmp(line, name, strlen(name)) == 0) {
			     int i = strlen(name) + 1;
			     
			     /* Make sure foo doesn't match foobar */
			     if (line[i] == '\0' || !isspace((int) line[i]))
			          continue;
			     /* Ignore whitespace */
			     while (isspace((int) line[++i]));

			     if (strcmp(&line[i], "restrict") == 0)
			          return (-1);
			     else
			          return (1);
			}
		  }
	     }
	     (void) fclose(fd);
	}

	return (0);
}

static int
disallowed_user(name)
        char *name;
{
        return(checkuser(name) == 1);
}

static int
restricted_user(name)
        char *name;
{
        return(checkuser(name) == -1);
}

/*
 * Terminate login as previous user, if any, resetting state;
 * used when USER command is given or login fails.
 */
static void 
end_login()
{

	(void) krb5_seteuid((uid_t)0);
	if (logged_in)
		pty_logwtmp(ttyline, "", "");
	if (have_creds) {
#ifdef GSSAPI
		krb5_cc_destroy(kcontext, ccache);
#endif
#ifdef KRB5_KRB4_COMPAT
		dest_tkt();
#endif
		have_creds = 0;
	}
	pw = NULL;
	logged_in = 0;
	guest = 0;
}

static int
kpass(name, passwd)
char *name, *passwd;
{
#ifdef GSSAPI
	krb5_principal server, me;
	krb5_creds my_creds;
	krb5_timestamp now;
#endif /* GSSAPI */
#ifdef KRB5_KRB4_COMPAT
	char realm[REALM_SZ];
#ifndef GSSAPI
	char **service;
	KTEXT_ST ticket;
	AUTH_DAT authdata;
	des_cblock key;
	char instance[INST_SZ];
	unsigned long faddr;
	struct hostent *hp;
#endif /* GSSAPI */
#endif /* KRB5_KRB4_COMPAT */
	char ccname[MAXPATHLEN];

#ifdef GSSAPI
	memset((char *)&my_creds, 0, sizeof(my_creds));
	if (krb5_parse_name(kcontext, name, &me))
		return 0;
	my_creds.client = me;

	sprintf(ccname, "FILE:/tmp/krb5cc_ftpd%ld", (long) getpid());
	if (krb5_cc_resolve(kcontext, ccname, &ccache))
		return(0);
	if (krb5_cc_initialize(kcontext, ccache, me))
		return(0);
	if (krb5_build_principal_ext(kcontext, &server,
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     0))
		goto nuke_ccache;

	my_creds.server = server;
	if (krb5_timeofday(kcontext, &now))
		goto nuke_ccache;
	my_creds.times.starttime = 0; /* start timer when 
					 request gets to KDC */
	my_creds.times.endtime = now + 60 * 60 * 10;
	my_creds.times.renew_till = 0;

	if (krb5_get_init_creds_password(kcontext, &my_creds, me,
					 passwd, NULL, NULL, 0, NULL, NULL))
	  goto nuke_ccache;

	if (krb5_cc_store_cred(kcontext, ccache, &my_creds))
	  goto nuke_ccache;

	if (!want_creds) {
		krb5_cc_destroy(kcontext, ccache);
		return(1);
	}
#endif /* GSSAPI */

#ifdef KRB5_KRB4_COMPAT
	if (krb_get_lrealm(realm, 1) != KSUCCESS)
		goto nuke_ccache;

	sprintf(ccname, "%s_ftpd%ld", TKT_ROOT, (long) getpid());
	krb_set_tkt_string(ccname);

	if (krb_get_pw_in_tkt(name, "", realm, "krbtgt", realm, 1, passwd))
		goto nuke_ccache;

#ifndef GSSAPI
	/* Verify the ticket since we didn't verify the krb5 one. */
	strncpy(instance, krb_get_phost(hostname), sizeof(instance));

	if ((hp = gethostbyname(instance)) == NULL)
		goto nuke_ccache;
	memcpy((char *) &faddr, (char *)hp->h_addr, sizeof(faddr));

	for (service = krb4_services; *service; service++) {
		if (!read_service_key(*service, instance,
				      realm, 0, keyfile, key)) {
			(void) memset(key, 0, sizeof(key));
			if (krb_mk_req(&ticket, *service,
				       instance, realm, 33) ||
			    krb_rd_req(&ticket, *service, instance,
				       faddr, &authdata,keyfile) ||
			    kuserok(&authdata, name)) {
				dest_tkt();
				goto nuke_ccache;
			} else
				break;
		}
	}

	if (!*service) {
		dest_tkt();
		goto nuke_ccache;
	}

	if (!want_creds) {
		dest_tkt();
		return(1);
	}
#endif /* GSSAPI */
#endif /* KRB5_KRB4_COMPAT */

#if defined(GSSAPI) || defined(KRB5_KRB4_COMPAT)
	have_creds = 1;
	return(1);
#endif /* GSSAPI || KRB5_KRB4_COMPAT */

nuke_ccache:
#ifdef GSSAPI
	krb5_cc_destroy(kcontext, ccache);
#endif /* GSSAPI */
	return(0);
}

void
pass(passwd)
	char *passwd;
{
	char *xpasswd, *salt;

	if (authorized && !want_creds) {
		reply(202, "PASS command superfluous.");
		return;
	}

	if (logged_in || askpasswd == 0) {
	  	reply(503, "Login with USER first.");
		return;
	} 

	if (!guest) {
	    	/* "ftp" is only account allowed no password */
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
		/* Fail if:
		 *   pw is NULL
		 *   kpass fails and we want_creds
		 *   kpass fails and the user has no local password
		 *   kpass fails and the provided password doesn't match pw
		 */
		if (pw == NULL || (!kpass(pw->pw_name, passwd) &&
				   (want_creds || !*pw->pw_passwd ||
				    strcmp(xpasswd, pw->pw_passwd)))) {
			pw = NULL;
			sleep(5);
			if (++login_attempts >= 3) {
				reply(421,
				      "Login incorrect, closing connection.");
				syslog(LOG_NOTICE,
				       "repeated login failures from %s (%s)",
				       rhost_addra, remotehost);
				dologout(0);
			}
			reply(530, "Login incorrect.");
			return;
	        }
	}
	login_attempts = 0;		/* this time successful */

	login(passwd, 0);
	return;
}

static void
login(passwd, logincode)
	char *passwd;
	int logincode;
{
	if (have_creds) {
#ifdef GSSAPI
		const char *ccname = krb5_cc_get_name(kcontext, ccache);
		chown(ccname, pw->pw_uid, pw->pw_gid);
#endif
#ifdef KRB5_KRB4_COMPAT
		chown(tkt_string(), pw->pw_uid, pw->pw_gid);
#endif
	}

	(void) krb5_setegid((gid_t)pw->pw_gid);
	(void) initgroups(pw->pw_name, pw->pw_gid);

	/* open wtmp before chroot */
	(void) sprintf(ttyline, "ftp%ld", (long) getpid());
	pty_logwtmp(ttyline, pw->pw_name, rhost_sane);
	logged_in = 1;

	if (guest || restricted) {
		if (chroot(pw->pw_dir) < 0) {
			reply(550, "Can't set privileges.");
			goto bad;
		}
	}
#ifdef HAVE_SETLUID
  	/*
  	 * If we're on a system which keeps track of login uids, then
 	 * set the login uid. If this fails this opens up a problem on DEC OSF
 	 * with C2 enabled.
	 */
	if (((uid_t)getluid() != pw->pw_uid)
	    && setluid((uid_t)pw->pw_uid) < 0) {
	        reply(550, "Can't set luid.");
		goto bad;
	}
#endif
	if (krb5_seteuid((uid_t)pw->pw_uid) < 0) {
	        reply(550, "Can't set uid.");
		goto bad;
	}
	if (guest) {
		/*
		 * We MUST do a chdir() after the chroot. Otherwise
		 * the old current directory will be accessible as "."
		 * outside the new root!
		 */
		if (chdir("/") < 0) {
			reply(550, "Can't set guest privileges.");
			goto bad;
		}
	} else {
	        if (chdir(restricted ? "/" : pw->pw_dir) < 0) {
		        if (chdir("/") < 0) {
			        reply(530, "User %s: can't change directory to %s.",
				      pw->pw_name, pw->pw_dir);
				goto bad;
			} else {
				if (!logincode)
					logincode = 230;
			        lreply(logincode, "No directory! Logging in with home=/");
			}
		}
	}
	if (guest) {
		reply(230, "Guest login ok, access restrictions apply.");
#ifdef SETPROCTITLE
		sprintf(proctitle, "%s: anonymous/%.*s", rhost_sane,
		    sizeof(proctitle) - strlen(rhost_sane) -
		    sizeof(": anonymous/"), passwd);
		setproctitle(proctitle);
#endif /* SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO,
			       "ANONYMOUS FTP LOGIN FROM %s, %s (%s)",
			       rhost_addra, remotehost, passwd);
	} else {
		if (askpasswd) {
			askpasswd = 0;
			reply(230, "User %s logged in.", pw->pw_name);
		}
#ifdef SETPROCTITLE
		sprintf(proctitle, "%s: %s", rhost_sane, pw->pw_name);
		setproctitle(proctitle);
#endif /* SETPROCTITLE */
		if (logging)
			syslog(LOG_INFO, "FTP LOGIN FROM %s, %s (%s)",
			    rhost_addra, remotehost, pw->pw_name);
	}
	home = pw->pw_dir;		/* home dir for globbing */
	(void) umask(defumask);
	return;
bad:
	/* Forget all about it... */
	end_login();
}

void
retrieve(cmd, name)
	char *cmd, *name;
{
	FILE *fin, *dout;
	struct stat st;
	int (*closefunc)();

	if (logging > 1 && !cmd)
	        syslog(LOG_NOTICE, "get %s", path_expand(name));
	if (cmd == 0) {
		fin = fopen(name, "r"), closefunc = fclose;
		st.st_size = 0;
	} else {
		char line[FTP_BUFSIZ];

		if (strlen(cmd) + strlen(name) + 1 >= sizeof(line)) {
			syslog(LOG_ERR, "retrieve: filename too long");
			reply(501, "filename too long");
			return;
		}
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
	if (logging > 2 && !cmd)
	        syslog(LOG_NOTICE, "get: %i bytes transferred", byte_count);
}

void
store_file(name, fmode, unique)
	char *name, *fmode;
	int unique;
{
	FILE *fout, *din;
	struct stat st;
	int (*closefunc)();

	if (logging > 1) syslog(LOG_NOTICE, "put %s", path_expand(name));

	if (unique && stat(name, &st) == 0 &&
	    (name = gunique(name)) == NULL)
		return;

	if (restart_point)
		fmode = "r+w";
	fout = fopen(name, fmode);
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
	if (logging > 2)
	        syslog(LOG_NOTICE, "put: %i bytes transferred", byte_count);
}

FILE *
getdatasock(fmode)
	char *fmode;
{
	int s, on = 1, tries;

	if (data >= 0)
		return (fdopen(data, fmode));
	(void) krb5_seteuid((uid_t)0);
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
	(void) krb5_seteuid((uid_t)pw->pw_uid);
#ifdef IP_TOS
#ifdef IPTOS_THROUGHPUT
	on = IPTOS_THROUGHPUT;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
#endif
	return (fdopen(s, fmode));
bad:
	(void) krb5_seteuid((uid_t)pw->pw_uid);
	(void) close(s);
	return (NULL);
}

FILE *
dataconn(name, size, fmode)
	char *name;
	off_t size;
	char *fmode;
{
	char sizebuf[32];
	FILE *file;
	int retry = 0, tos;

	file_size = size;
	byte_count = 0;
	if (size != (off_t) -1)
		/* cast size to long in case sizeof(off_t) > sizeof(long) */
		(void) sprintf (sizebuf, " (%ld bytes)", (long)size);
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
		return(fdopen(pdata, fmode));
	}
	if (data >= 0) {
		reply(125, "Using existing data connection for %s%s.",
		    name, sizebuf);
		usedefault = 1;
		return (fdopen(data, fmode));
	}
	if (usedefault)
		data_dest = his_addr;
	usedefault = 1;
	file = getdatasock(fmode);
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

/*
 * XXX callers need to limit total length of output string to
 * FTP_BUFSIZ
 */
#ifdef STDARG
void
secure_error(char *fmt, ...)
#else
/* VARARGS1 */
void
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
void send_data(instr, outstr, blksize)
	FILE *instr, *outstr;
	off_t blksize;
{
	register int c, cnt;
	register char *buf;
	int netfd, filefd;
	volatile int ret = 0;

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
static int
receive_data(instr, outstr)
	FILE *instr, *outstr;
{
	register int c;
	volatile int cnt, bare_lfs = 0;
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

void
statfilecmd(filename)
	char *filename;
{
	char line[FTP_BUFSIZ];
	FILE *fin;
	int c, n;
	char str[FTP_BUFSIZ], *p;

	if (strlen(filename) + sizeof("/bin/ls -lgA ")
	    >= sizeof(line)) {
		reply(501, "filename too long");
		return;
	}
	(void) sprintf(line, "/bin/ls -lgA %s", filename);
	fin = ftpd_popen(line, "r");
	lreply(211, "status of %s:", filename);
	p = str;
	n = 0;
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
			n = 0;
		} else {
			*p++ = c;
			n++;
			if (n >= sizeof(str)) {
				reply(551, "output line too long");
				(void) ftpd_pclose(fin);
				return;
			}
		}
	}
	if (p != str) {
		*p = '\0';
		reply(0, "%s", str);
	}
	(void) ftpd_pclose(fin);
	reply(211, "End of Status");
}

void
statcmd()
{
	struct sockaddr_in *sin4;
	u_char *a, *p;
	char str[FTP_BUFSIZ];

	lreply(211, "%s FTP server status:", hostname);
	reply(0, "     %s", version);
	sprintf(str, "     Connected to %s", remotehost[0] ? remotehost : "");
	sprintf(&str[strlen(str)], " (%s)", rhost_addra);
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
	reply(0, "     Protection level: %s", levelnames[dlevel]);
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
		sin4 = &pasv_addr;
		goto printaddr;
	} else if (usedefault == 0) {
		strcpy(str, "     PORT");
		sin4 = &data_dest;
printaddr:
		a = (u_char *) &sin4->sin_addr;
		p = (u_char *) &sin4->sin_port;
#define UC(b) (((int) b) & 0xff)
		sprintf(&str[strlen(str)], " (%d,%d,%d,%d,%d,%d)", UC(a[0]),
			UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#undef UC
	} else
		strcpy(str, "     No data connection");
	reply(0, "%s", str);
	reply(211, "End of status");
}

void
fatal(s)
	char *s;
{
	reply(451, "Error in server: %s", s);
	reply(221, "Closing connection due to server error.");
	dologout(0);
	/* NOTREACHED */
}

char cont_char = ' ';

/*
 * XXX callers need to limit total length of output string to
 * FTP_BUFSIZ bytes for now.
 */
#ifdef STDARG
void
reply(int n, char *fmt, ...)
#else
/* VARARGS2 */
void
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
		/*
		 * Deal with expansion in mk_{safe,priv},
		 * radix_encode, gss_seal, plus slop.
		 */
		char in[FTP_BUFSIZ*3/2], out[FTP_BUFSIZ*3/2];
		int length, kerror;
		if (n) sprintf(in, "%d%c", n, cont_char);
		else in[0] = '\0';
		strncat(in, buf, sizeof (in) - strlen(in) - 1);
#ifdef KRB5_KRB4_COMPAT
		if (strcmp(auth_type, "KERBEROS_V4") == 0) {
			if (clevel == PROT_P)
				length = krb_mk_priv((unsigned char *)in,
						     (unsigned char *)out,
						     strlen(in),
						     schedule, &kdata.session,
						     &ctrl_addr,
						     &his_addr);
			else
				length = krb_mk_safe((unsigned char *)in,
						     (unsigned char *)out,
						     strlen(in),
						     &kdata.session,
						     &ctrl_addr,
						     &his_addr);
			if (length == -1) {
				syslog(LOG_ERR,
				       "krb_mk_%s failed for KERBEROS_V4",
				       clevel == PROT_P ? "priv" : "safe");
				fputs(in,stdout);
			}
		} else
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
		/* reply (based on level) */
		if (strcmp(auth_type, "GSSAPI") == 0) {
			gss_buffer_desc in_buf, out_buf;
			OM_uint32 maj_stat, min_stat;
			int conf_state;
		
			in_buf.value = in;
			in_buf.length = strlen(in);
			maj_stat = gss_seal(&min_stat, gcontext,
					    clevel == PROT_P, /* private */
					    GSS_C_QOP_DEFAULT,
					    &in_buf, &conf_state,
					    &out_buf);
			if (maj_stat != GSS_S_COMPLETE) {
#if 0
/* Don't setup an infinite loop */
				/* generally need to deal */
				secure_gss_error(maj_stat, min_stat,
					       (clevel==PROT_P)?
						 "gss_seal ENC didn't complete":
						 "gss_seal MIC didn't complete");
#endif /* 0 */
			} else if ((clevel == PROT_P) && !conf_state) {
#if 0
/* Don't setup an infinite loop */
				secure_error("GSSAPI didn't encrypt message");
#endif /* 0 */
			} else {
				memcpy(out, out_buf.value, 
				       length=out_buf.length);
				gss_release_buffer(&min_stat, &out_buf);
			}
		}
#endif /* GSSAPI */
		/* Other auth types go here ... */
		if (length >= sizeof(in) / 4 * 3) {
			syslog(LOG_ERR, "input to radix_encode too long");
			fputs(in, stdout);
		} else if ((kerror = radix_encode(out, in, &length, 0))) {
			syslog(LOG_ERR, "Couldn't encode reply (%s)",
					radix_error(kerror));
			fputs(in,stdout);
		} else
			printf("%s%c%s", clevel == PROT_P ? "632" : "631",
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

/*
 * XXX callers need to limit total length of output string to
 * FTP_BUFSIZ
 */
#ifdef STDARG
void
lreply(int n, char *fmt, ...)
#else
/* VARARGS2 */
void
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

void
ack(s)
	char *s;
{
	reply(250, "%s command successful.", s);
}

void
nack(s)
	char *s;
{
	reply(502, "%s command not implemented.", s);
}

/* ARGSUSED */
void
yyerror(s)
	char *s;
{
	char *cp;

	cp = strchr(cbuf,'\n');
	if (cp)
		*cp = '\0';
	reply(500, "'%.*s': command not understood.",
	      (int) (FTP_BUFSIZ - sizeof("'': command not understood.")),
	      cbuf);
}

void
delete_file(name)
	char *name;
{
	struct stat st;

	if (logging > 1) syslog(LOG_NOTICE, "del %s", path_expand(name));

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

void
cwd(path)
	char *path;
{
	if (chdir(path) < 0)
		perror_reply(550, path);
	else
		ack("CWD");
}

void
makedir(name)
	char *name;
{
        if (logging > 1) syslog(LOG_NOTICE, "mkdir %s", path_expand(name));

	if (mkdir(name, 0777) < 0)
		perror_reply(550, name);
	else
		reply(257, "MKD command successful.");
}

void
removedir(name)
	char *name;
{
        if (logging > 1) syslog(LOG_NOTICE, "rmdir %s", path_expand(name));

	if (rmdir(name) < 0)
		perror_reply(550, name);
	else
		ack("RMD");
}

void
pwd()
{
	if (getcwd(pathbuf, sizeof pathbuf) == (char *)NULL)
#ifdef POSIX
		perror_reply(550, pathbuf);
#else
		reply(550, "%s.", pathbuf);
#endif
	else
		reply(257, "\"%s\" is current directory.", pathbuf);
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

void
renamecmd(from, to)
	char *from, *to;
{
        if(logging > 1)
                syslog(LOG_NOTICE, "rename %s %s", path_expand(from), to);

	if (rename(from, to) < 0)
		perror_reply(550, "rename");
	else
		ack("RNTO");
}

static void
dolog(sin4)
	struct sockaddr_in *sin4;
{
	struct hostent *hp = gethostbyaddr((char *)&sin4->sin_addr,
		sizeof (struct in_addr), AF_INET);
	time_t t, time();
	extern char *ctime();
	krb5_error_code retval;

	if (hp != NULL) {
		(void) strncpy(remotehost, hp->h_name, sizeof (remotehost));
		remotehost[sizeof (remotehost) - 1] = '\0';
	} else
		remotehost[0] = '\0';
	strncpy(rhost_addra, inet_ntoa(sin4->sin_addr), sizeof (rhost_addra));
	rhost_addra[sizeof (rhost_addra) - 1] = '\0';
	retval = pty_make_sane_hostname((struct sockaddr *) sin4, maxhostlen,
					stripdomain, always_ip, &rhost_sane);
	if (retval) {
		fprintf(stderr, "make_sane_hostname: %s\n",
			error_message(retval));
		exit(1);
	}
#ifdef SETPROCTITLE
	sprintf(proctitle, "%s: connected", rhost_sane);
	setproctitle(proctitle);
#endif /* SETPROCTITLE */

	if (logging) {
		t = time((time_t *) 0);
		syslog(LOG_INFO, "connection from %s (%s) at %s",
		    rhost_addra, remotehost, ctime(&t));
	}
}

/*
 * Record logout in wtmp file
 * and exit with supplied status.
 */
void
dologout(status)
	int status;
{
	if (logged_in) {
		(void) krb5_seteuid((uid_t)0);
		pty_logwtmp(ttyline, "", "");
	}
	if (have_creds) {
#ifdef GSSAPI
		krb5_cc_destroy(kcontext, ccache);
#endif
#ifdef KRB5_KRB4_COMPAT
		dest_tkt();
#endif
	}
	/* beware of flushing buffers after a SIGPIPE */
	_exit(status);
}

void
myoob(sig)
    int sig;
{
	char *cp, *cs;
#ifndef strpbrk
	extern char *strpbrk();
#endif

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
			      (unsigned long) byte_count, 
			      (unsigned long) file_size);
		else
			reply(213, "Status: %lu bytes transferred", 
			      (unsigned long) byte_count);
	}
}

/*
 * Note: a response of 425 is not mentioned as a possible response to
 * 	the PASV command in RFC959. However, it has been blessed as
 * 	a legitimate response by Jon Postel in a telephone conversation
 *	with Rick Adams on 25 Jan 89.
 */
void
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
	(void) krb5_seteuid((uid_t)0);
	if (bind(pdata, (struct sockaddr *)&pasv_addr, sizeof(pasv_addr)) < 0) {
		(void) krb5_seteuid((uid_t)pw->pw_uid);
		goto pasv_error;
	}
	(void) krb5_seteuid((uid_t)pw->pw_uid);
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
static char *
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
	(void) strncpy(new, local, sizeof(new) - 1);
	new[sizeof(new) - 1] = '\0';
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
void
perror_reply(code, string)
	int code;
	char *string;
{
	char *err_string;
	size_t extra_len;

	err_string = strerror(errno);
	if (err_string == NULL)
		err_string = "(unknown error)";
	extra_len = strlen(err_string) + sizeof("(truncated): .");

	/*
	 * XXX knows about FTP_BUFSIZ in reply()
	 */
	if (strlen(string) + extra_len > FTP_BUFSIZ) {
		reply(code, "(truncated)%.*s: %s.",
		      (int) (FTP_BUFSIZ - extra_len), string, err_string);
	} else {
		reply(code, "%s: %s.", string, err_string);
	}
}

void
auth(atype)
char *atype;
{
	if (auth_type)
		reply(534, "Authentication type already set to %s", auth_type);
	else
#ifdef KRB5_KRB4_COMPAT
	if (strcmp(atype, "KERBEROS_V4") == 0)
		reply(334, "Using authentication type %s; ADAT must follow",
				temp_auth_type = atype);
	else
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
	if (strcmp(atype, "GSSAPI") == 0)
		reply(334, "Using authentication type %s; ADAT must follow",
				temp_auth_type = atype);
	else
#endif /* GSSAPI */
	/* Other auth types go here ... */
		reply(504, "Unknown authentication type: %s", atype);
}

int
auth_data(adata)
char *adata;
{
	int kerror, length;
#ifdef KRB5_KRB4_COMPAT
	static char **service=NULL;
	char instance[INST_SZ];
	KRB4_32 cksum;
	char buf[FTP_BUFSIZ];
	u_char out_buf[sizeof(buf)];
#endif /* KRB5_KRB4_COMPAT */

	if (auth_type) {
		reply(503, "Authentication already established");
		return(0);
	}
	if (!temp_auth_type) {
		reply(503, "Must identify AUTH type before ADAT");
		return(0);
	}
#ifdef KRB5_KRB4_COMPAT
	if (strcmp(temp_auth_type, "KERBEROS_V4") == 0) {
	        kerror = radix_encode(adata, out_buf, &length, 1);
		if (kerror) {
			reply(501, "Couldn't decode ADAT (%s)",
			      radix_error(kerror));
			syslog(LOG_ERR, "Couldn't decode ADAT (%s)",
			       radix_error(kerror));
			return(0);
		}
		(void) memcpy((char *)ticket.dat, (char *)out_buf, ticket.length = length);
		strcpy(instance, "*");

		kerror = 255;
		for (service = krb4_services; *service; service++) {
		  kerror = krb_rd_req(&ticket, *service, instance,
				      his_addr.sin_addr.s_addr, 
				      &kdata, keyfile);
		  /* Success */
		  if(!kerror) break;
		} 
		/* rd_req failed.... */
		if(kerror) {
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
		if (length >= (FTP_BUFSIZ - sizeof("ADAT=")) / 4 * 3) {
			secure_error("ADAT: reply too long");
			return(0);
		}

		kerror = radix_encode(out_buf, buf, &length, 0);
		if (kerror) {
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
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
	if (strcmp(temp_auth_type, "GSSAPI") == 0) {
		int replied = 0;
		int found = 0;
		gss_cred_id_t server_creds, deleg_creds;
		gss_name_t client;
		OM_uint32 ret_flags;
		int rad_len;
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
		char **gservice;
		struct hostent *hp;


		kerror = radix_encode(adata, gout_buf, &length, 1);
		if (kerror) {
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
			reply(501, "couldn't canonicalize local hostname\n");
			syslog(LOG_ERR, "Couldn't canonicalize local hostname");
			return 0;
		}
		strncpy(localname, hp->h_name, sizeof(localname) - 1);
		localname[sizeof(localname) - 1] = '\0';

		for (gservice = gss_services; *gservice; gservice++) {
			sprintf(service_name, "%s@%s", *gservice, localname);
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
							    GSS_C_NO_CHANNEL_BINDINGS, /* channel bindings */
							    &client, /* src_name */
							    &mechid, /* mech_type */
							    &out_tok, /* output_token */
							    &ret_flags,
							    NULL, 	/* ignore time_rec */
							    &deleg_creds  /* forwarded credentials */
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
				if (ret_flags & GSS_C_DELEG_FLAG)
					(void) gss_release_cred(&stat_min,
								&deleg_creds);
				return 0;
			}
		} else {
			/* Kludge to make sure the right error gets reported, so we don't *
			 * get those nasty "error: no error" messages.			  */
			if(stat_maj != GSS_S_COMPLETE)
			        reply_gss_error(501, stat_maj, stat_min,
						"acquiring credentials");
			else
			        reply_gss_error(501, acquire_maj, acquire_min,
						"acquiring credentials");
			syslog(LOG_ERR, "gssapi error acquiring credentials");
			return 0;
		}

		if (out_tok.length) {
			if (out_tok.length >= ((FTP_BUFSIZ - sizeof("ADAT="))
					       / 4 * 3)) {
				secure_error("ADAT: reply too long");
				syslog(LOG_ERR, "ADAT: reply too long");
				(void) gss_release_cred(&stat_min, &server_creds);
				if (ret_flags & GSS_C_DELEG_FLAG)
					(void) gss_release_cred(&stat_min,
								&deleg_creds);
				return(0);
			}

			rad_len = out_tok.length;
			kerror = radix_encode(out_tok.value, gbuf, 
					      &rad_len, 0);
			out_tok.length = rad_len;
			if (kerror) {
				secure_error("Couldn't encode ADAT reply (%s)",
					     radix_error(kerror));
				syslog(LOG_ERR, "couldn't encode ADAT reply");
				(void) gss_release_cred(&stat_min, &server_creds);
				if (ret_flags & GSS_C_DELEG_FLAG)
					(void) gss_release_cred(&stat_min,
								&deleg_creds);
				return(0);
			}
			if (accept_maj == GSS_S_COMPLETE) {
				reply(235, "ADAT=%s", gbuf);
			} else {
				/* If the server accepts the security data, and
				   requires additional data, it should respond
				   with reply code 335. */
				reply(335, "ADAT=%s", gbuf);
			}
			replied = 1;
			(void) gss_release_buffer(&stat_min, &out_tok);
		}
		if (accept_maj == GSS_S_COMPLETE) {
			/* GSSAPI authentication succeeded */
			stat_maj = gss_display_name(&stat_min, client,
						    &client_name, &mechid);
			if (stat_maj != GSS_S_COMPLETE) {
				/* "If the server rejects the security data (if
				   a checksum fails, for instance), it should 
				   respond with reply code 535." */
				reply_gss_error(535, stat_maj, stat_min,
						"extracting GSSAPI identity name");
				log_gss_error(LOG_ERR, stat_maj, stat_min,
					      "gssapi error extracting identity");
				(void) gss_release_cred(&stat_min, &server_creds);
				if (ret_flags & GSS_C_DELEG_FLAG)
					(void) gss_release_cred(&stat_min,
								&deleg_creds);
				return 0;
			}
			auth_type = temp_auth_type;
			temp_auth_type = NULL;

			(void) gss_release_cred(&stat_min, &server_creds);
			if (ret_flags & GSS_C_DELEG_FLAG) {
			  if (want_creds)
			    ftpd_gss_convert_creds(client_name.value,
						   deleg_creds);
			  (void) gss_release_cred(&stat_min, &deleg_creds);
			}

			/* If the server accepts the security data, but does
			   not require any additional data (i.e., the security
			   data exchange has completed successfully), it must
			   respond with reply code 235. */
			if (!replied)
			  {
			    if (ret_flags & GSS_C_DELEG_FLAG && !have_creds)
			      reply(235, "GSSAPI Authentication succeeded, but could not accept forwarded credentials");
			    else
			      reply(235, "GSSAPI Authentication succeeded");
			  }
				
			return(1);
		} else if (accept_maj == GSS_S_CONTINUE_NEEDED) {
			/* If the server accepts the security data, and
			   requires additional data, it should respond with
			   reply code 335. */
			if (!replied)
			    reply(335, "more data needed");
			(void) gss_release_cred(&stat_min, &server_creds);
			if (ret_flags & GSS_C_DELEG_FLAG)
			  (void) gss_release_cred(&stat_min, &deleg_creds);
			return(0);
		} else {
			/* "If the server rejects the security data (if 
			   a checksum fails, for instance), it should 
			   respond with reply code 535." */
			reply_gss_error(535, stat_maj, stat_min, 
					"GSSAPI failed processing ADAT");
			syslog(LOG_ERR, "GSSAPI failed processing ADAT");
			(void) gss_release_cred(&stat_min, &server_creds);
			if (ret_flags & GSS_C_DELEG_FLAG)
			  (void) gss_release_cred(&stat_min, &deleg_creds);
			return(0);
		}
	}
#endif /* GSSAPI */
	/* Other auth types go here ... */
	/* Also need to check authorization, but that is done in user() */
	return(0);
}

static char *onefile[] = {
	"",
	0
};

/* returns:
 *	n>=0 on success
 *	-1 on error
 *	-2 on security error
 *
 * XXX callers need to limit total length of output string to
 * FTP_BUFSIZ
 */
#ifdef STDARG
static int
secure_fprintf(FILE *stream, char *fmt, ...)
#else
static int
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
        if (dlevel == PROT_C) rval = vfprintf(stream, fmt, ap);
        else {
                vsprintf(s, fmt, ap);
                rval = secure_write(fileno(stream), s, strlen(s));
        }
        va_end(ap);

        return(rval);
#else
        if (dlevel == PROT_C)
                return(fprintf(stream, fmt, p1, p2, p3, p4, p5));
        sprintf(s, fmt, p1, p2, p3, p4, p5);
        return(secure_write(fileno(stream), s, strlen(s)));
#endif
}

void
send_file_list(whichfiles)
	char *whichfiles;
{
	struct stat st;
	DIR *dirp = NULL;
	struct dirent *dir;
	FILE *volatile dout = NULL;
	register char **volatile dirlist, *dirname;
	volatile int simple = 0;
#ifndef strpbrk
	char *strpbrk();
#endif
	volatile int ret = 0;

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
	while ((dirname = *dirlist++)) {
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

			if (strlen(dirname) + strlen(dir->d_name)
			    + 1 /* slash */
			    + 2	/* CRLF */
			    + 1 > sizeof(nbuf)) {
				syslog(LOG_ERR,
				       "send_file_list: pathname too long");
				ret = -2; /* XXX */
				goto data_err;
			}
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
	if (dout != NULL ) {
	  ret = secure_write(fileno(dout), "", 0);
	  if (ret >= 0)
	    ret = secure_flush(fileno(dout));
	}
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
/* A more general callback would probably use a void*, but currently I
   only need an int in both cases.  */
static void with_gss_error_text(void (*cb)(const char *, int, int),
				OM_uint32 maj_stat, OM_uint32 min_stat,
				int misc);

static void
log_gss_error_1(const char *msg, int severity, int is_major)
{
    syslog(severity, "... GSSAPI error %s: %s",
	   is_major ? "major" : "minor", msg);
}

static void
log_gss_error(int severity, OM_uint32 maj_stat, OM_uint32 min_stat,
	      const char *s)
{
    syslog(severity, s);
    with_gss_error_text(log_gss_error_1, maj_stat, min_stat, severity);
}

static void
reply_gss_error_1(const char *msg, int code, int is_major)
{
    lreply(code, "GSSAPI error %s: %s",
	   is_major ? "major" : "minor", msg);
}

void
reply_gss_error(int code, OM_uint32 maj_stat, OM_uint32 min_stat, char *s)
{
    with_gss_error_text(reply_gss_error_1, maj_stat, min_stat, code);
    reply(code, "GSSAPI error: %s", s);
}

static void with_gss_error_text(void (*cb)(const char *, int, int),
				OM_uint32 maj_stat, OM_uint32 min_stat,
				int misc)
{
	/* a lot of work just to report the error */
	OM_uint32 gmaj_stat, gmin_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;
	msg_ctx = 0;
	while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
					       GSS_C_GSS_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
			(*cb)((char*)msg.value, misc, 1);
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
			(*cb)((char*)msg.value, misc, 0);
			(void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	}
}

void
secure_gss_error(maj_stat, min_stat, s)
OM_uint32 maj_stat, min_stat;
char *s;
{
  reply_gss_error(535, maj_stat, min_stat, s);
  return;
}


/* ftpd_gss_userok -- hide details of getting the name and verifying it */
/* returns 0 for OK */
static int
ftpd_gss_userok(gclient_name, name)
	gss_buffer_t gclient_name;
	char *name;
{
	int retval = -1;
	krb5_principal p;
	
	if (krb5_parse_name(kcontext, gclient_name->value, &p) != 0)
		return -1;
	if (krb5_kuserok(kcontext, p, name))
		retval = 0;
	else 
		retval = 1;
	krb5_free_principal(kcontext, p);
	return retval;
}

/* ftpd_gss_convert_creds -- write out forwarded creds */
/* (code lifted from login.krb5) */
static void
ftpd_gss_convert_creds(name, creds)
	char *name;
	gss_cred_id_t creds;
{
	OM_uint32 major_status, minor_status;
	krb5_principal me;
	char ccname[MAXPATHLEN];
#ifdef KRB5_KRB4_COMPAT
	krb5_principal kpcserver;
	krb5_creds increds, *v5creds;
	CREDENTIALS v4creds;
#endif

	/* Set up ccache */
	if (krb5_parse_name(kcontext, name, &me))
		return;

	sprintf(ccname, "FILE:/tmp/krb5cc_ftpd%ld", (long) getpid());
	if (krb5_cc_resolve(kcontext, ccname, &ccache))
		return;
	if (krb5_cc_initialize(kcontext, ccache, me))
		return;

	/* Copy GSS creds into ccache */
	major_status = gss_krb5_copy_ccache(&minor_status, creds, ccache);
	if (major_status != GSS_S_COMPLETE)
		goto cleanup;

#ifdef KRB5_KRB4_COMPAT
	/* Convert krb5 creds to krb4 */

	if (krb5_build_principal_ext(kcontext, &kpcserver, 
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     6, "krbtgt",
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     0))
		goto cleanup;

	memset((char *) &increds, 0, sizeof(increds));
	increds.client = me;
	increds.server = kpcserver;
	increds.times.endtime = 0;
	increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
	if (krb5_get_credentials(kcontext, 0, ccache, &increds, &v5creds))
		goto cleanup;
	if (krb524_convert_creds_kdc(kcontext, v5creds, &v4creds))
		goto cleanup;

	sprintf(ccname, "%s_ftpd%ld", TKT_ROOT, (long) getpid());
	krb_set_tkt_string(ccname);

	if (in_tkt(v4creds.pname, v4creds.pinst) != KSUCCESS)
		goto cleanup;

	if (krb_save_credentials(v4creds.service, v4creds.instance,
				 v4creds.realm, v4creds.session,
				 v4creds.lifetime, v4creds.kvno,
				 &(v4creds.ticket_st), v4creds.issue_date))
		goto cleanup_v4;
#endif /* KRB5_KRB4_COMPAT */
	have_creds = 1;
	return;

#ifdef KRB5_KRB4_COMPAT
cleanup_v4:
	dest_tkt();
#endif
cleanup:
	krb5_cc_destroy(kcontext, ccache);
}


#endif /* GSSAPI */

