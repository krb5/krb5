/*
 * Copyright (c) 1980, 1987, 1988 The Regents of the University of California.
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
"@(#) Copyright (c) 1980, 1987, 1988 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)login.c	5.25 (Berkeley) 1/6/89";
#endif /* not lint */

/*
 * login [ name ]
 * login -r hostname	(for rlogind)
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
 * ifdef KERBEROS
 * login -e name	(for pre-authenticated encrypted, must do term
 *			 negotiation)
 * login -k hostname (for Kerberos rlogind with password access)
 * login -K hostname (for Kerberos rlogind with restricted access)
 * endif KERBEROS 
 */

#include <sys/param.h>
#ifndef VFS
#include <sys/quota.h>
#endif VFS
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <utmp.h>
#include <signal.h>
#include <lastlog.h>
#include <errno.h>
#ifndef NOTTYENT
#include <ttyent.h>
#endif /* NOTTYENT */
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdio.h>
#include <strings.h>

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "gssapi_defs.h"

#define TOKEN_MAJIC_NUMBER_BYTE0    1
#define TOKEN_MAJIC_NUMBER_BYTE1    1

char userfullname[GSS_C_MAX_PRINTABLE_NAME];
char userlocalname[GSS_C_MAX_PRINTABLE_NAME];
gss_cred_id_t gss_delegated_cred_handle;

#ifdef UIDGID_T
uid_t getuid();
#define uid_type uid_t
#define gid_type gid_t
#else
int getuid();
#define uid_type int
#define gid_type int
#endif /* UIDGID_T */

#define	TTYGRPNAME	"tty"		/* name of group to own ttys */

#define	MOTDFILE	"/etc/motd"
#define	MAILDIR		"/usr/spool/mail"
#define	NOLOGIN		"/etc/nologin"
#define	HUSHLOGIN	".hushlogin"
#define	LASTLOG		"/usr/adm/lastlog"
#define	BSHELL		"/bin/sh"

#ifdef VFS
#define QUOTAWARN	"/usr/ucb/quota" /* warn user about quotas */
#endif VFS

#define	UT_HOSTSIZE	sizeof(((struct utmp *)0)->ut_host)
#define	UT_NAMESIZE	sizeof(((struct utmp *)0)->ut_name)

/*
 * This bounds the time given to login.  Not a define so it can
 * be patched on machines where it's too small.
 */
int	timeout = 300;

struct passwd *pwd;
char term[64], *hostname, *username;

gss_ctx_id_t     context_handle;

struct sgttyb sgttyb;
struct tchars tc = {
	CINTR, CQUIT, CSTART, CSTOP, CEOT, CBRK
};
struct ltchars ltc = {
	CSUSP, CDSUSP, CRPRNT, CFLUSH, CWERASE, CLNEXT
};

extern int errno;

#ifdef POSIX
typedef void sigtype;
#else
typedef int sigtype;
#endif /* POSIX */

#define EXCL_TEST if (rflag || kflag || Kflag || eflag || \
			    fflag || hflag) { \
				fprintf(stderr, \
				    "login: only one of -r, -k, -K, -e,
-h and -f allowed.\n"); \
				exit(1);\
			}
main(argc, argv)
	int argc;
	char **argv;
{
	extern int optind;
	extern char *optarg, **environ;
	struct group *gr;
	register int ch;
	register char *p;

	int gflag;

	int fflag, hflag, pflag, rflag, cnt;
	int kflag, Kflag, eflag;
	int quietlog, passwd_req, ioctlval, major_status, minor_status;
	sigtype timedout();
	char *domain, *salt, *envinit[1], *ttyn, *tty;
	char tbuf[MAXPATHLEN + 2];
	char *ttyname(), *stypeof(), *crypt(), *getpass();
	time_t time();
	off_t lseek();

	(void)signal(SIGALRM, timedout);
	(void)alarm((u_int)timeout);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)setpriority(PRIO_PROCESS, 0, 0);
#ifndef VFS
	(void)quota(Q_SETUID, 0, 0, 0);
#endif VFS

	/*
	 * -s is used by flogind to cause the SPX autologin protocol;
	 * -p is used by getty to tell login not to destroy the environment
	 * -r is used by rlogind to cause the autologin protocol;
 	 * -f is used to skip a second login authentication 
	 * -e is used to skip a second login authentication, but allows
	 * 	login as root.
	 * -h is used by other servers to pass the name of the
	 * remote host to login so that it may be placed in utmp and wtmp
	 * -k is used by klogind to cause the Kerberos autologin protocol;
	 * -K is used by klogind to cause the Kerberos autologin protocol with
	 *    restricted access.;
	 */
	(void)gethostname(tbuf, sizeof(tbuf));
	domain = index(tbuf, '.');

	fflag = hflag = pflag = rflag = kflag = Kflag = eflag = 0;
	passwd_req = 1;
	while ((ch = getopt(argc, argv, "feh:pr:k:K:g:")) != EOF)
		switch (ch) {
		case 'f':
			EXCL_TEST;
			fflag = 1;
			break;
		case 'h':
			EXCL_TEST;
			if (getuid()) {
				fprintf(stderr,
				    "login: -h for super-user only.\n");
				exit(1);
			}
			hflag = 1;
			if (domain && (p = index(optarg, '.')) &&
			    strcmp(p, domain) == 0)
				*p = 0;
			hostname = optarg;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			EXCL_TEST;
			if (getuid()) {
				fprintf(stderr,
				    "login: -r for super-user only.\n");
				exit(1);
			}
			/* "-r hostname" must be last args */
			if (optind != argc) {
				fprintf(stderr, "Syntax error.\n");
				exit(1);
			}
			rflag = 1;
			passwd_req = (doremotelogin(optarg) == -1);
			if (domain && (p = index(optarg, '.')) &&
			    !strcmp(p, domain))
				*p = '\0';
			hostname = optarg;
			break;
	        case 'g':
			if (optind != argc) {
				fprintf(stderr, "Syntax error.\n");
				exit(1);
			}
			gflag = do_gss_login(optarg);
			if (gflag == 1)   passwd_req = 0;
			else {
			  (void)ioctl(0, TIOCHPCL, (char *)0);
			  sleepexitnew(1,1);
			}
			hostname = optarg;
			break;
		case '?':
		default:
			fprintf(stderr, "usage: login [-fp] [username]\n");
			exit(1);
		}
	argc -= optind;
	argv += optind;
	if (*argv)
		username = *argv;

	ioctlval = 0;
	(void)ioctl(0, TIOCLSET, (char *)&ioctlval);
	(void)ioctl(0, TIOCNXCL, (char *)0);
	(void)fcntl(0, F_SETFL, ioctlval);
	(void)ioctl(0, TIOCGETP, (char *)&sgttyb);

	/*
	 * If talking to an rlogin process, propagate the terminal type and
	 * baud rate across the network.
	 */

	if (rflag || kflag || Kflag || eflag || gflag)
		doremoteterm(&sgttyb);
	sgttyb.sg_erase = CERASE;
	sgttyb.sg_kill = CKILL;
	(void)ioctl(0, TIOCSLTC, (char *)&ltc);
	(void)ioctl(0, TIOCSETC, (char *)&tc);
	(void)ioctl(0, TIOCSETP, (char *)&sgttyb);

	for (cnt = getdtablesize(); cnt > 2; cnt--)
		(void) close(cnt);

	ttyn = ttyname(0);
	if (ttyn == NULL || *ttyn == '\0')
		ttyn = "/dev/tty??";
	if (tty = rindex(ttyn, '/'))
		++tty;
	else
		tty = ttyn;

	for (cnt = 0;; username = NULL) {
		ioctlval = 0;
		(void)ioctl(0, TIOCSETD, (char *)&ioctlval);

		if (username == NULL) {
			fflag = 0;
			getloginname();
		}
		if (pwd = getpwnam(username))
			salt = pwd->pw_passwd;
		else
			salt = "xx";

		/* if user not super-user, check for disabled logins */
		if (pwd == NULL || pwd->pw_uid)
			checknologin();

		/*
		 * Disallow automatic login to root; if not invoked by
		 * root, disallow if the uid's differ.
		 */
		if (fflag && pwd) {
			int uid = (int) getuid();

			passwd_req = pwd->pw_uid == 0 ||
			    (uid && uid != pwd->pw_uid);
		}

		/*
		 * If no remote login authentication and a password exists
		 * for this user, prompt for one and verify it.
		 */
		if (!passwd_req || pwd && !*pwd->pw_passwd)
			break;

		(void) setpriority(PRIO_PROCESS, 0, -4);
		p = crypt(getpass("password:"), salt);
		(void) setpriority(PRIO_PROCESS, 0, 0);
		if (pwd && !strcmp(p, pwd->pw_passwd))
			break;

		printf("Login incorrect\n");
		if (++cnt >= 5) {
			if (hostname)
			    syslog(LOG_ERR,
				"REPEATED LOGIN FAILURES ON %s FROM %.*s, %.*s",
				tty, UT_HOSTSIZE, hostname, UT_NAMESIZE,
				username);
			else
			    syslog(LOG_ERR,
				"REPEATED LOGIN FAILURES ON %s, %.*s",
				tty, UT_NAMESIZE, username);
			(void)ioctl(0, TIOCHPCL, (char *)0);
			sleepexit(1);
		}
	}

	/* committed to login -- turn off timeout */
	(void)alarm((u_int)0);

	/*
	 * If valid so far and root is logging in, see if root logins on
	 * this terminal are permitted.
	 */
#ifndef SPX_CHALLENGE
	if (pwd->pw_uid == 0 && !rootterm(tty)) {
		if (hostname)
			syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s FROM %.*s",
			    tty, UT_HOSTSIZE, hostname);
		else
			syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s", tty);
		printf("Login incorrect\n");
		sleepexit(1);
	}
#else
	if (pwd->pw_uid == 0) {
	  syslog(LOG_INFO, "%s (%s)", userfullname, userlocalname);
	}

#endif  /*  SPX_CHALLENGE  */

#ifndef VFS
	if (quota(Q_SETUID, pwd->pw_uid, 0, 0) < 0 && errno != EINVAL) {
		switch(errno) {
		case EUSERS:
			fprintf(stderr,
		"Too many users logged on already.\nTry again later.\n");
			break;
		case EPROCLIM:
			fprintf(stderr,
			    "You have too many processes running.\n");
			break;
		default:
			perror("quota (Q_SETUID)");
		}
		sleepexit(0);
	}
#endif /* !VFS */

	if (chdir(pwd->pw_dir) < 0) {
		printf("No directory %s!\n", pwd->pw_dir);
		if (chdir("/"))
			exit(0);
		pwd->pw_dir = "/";
		printf("Logging in with home = \"/\".\n");
	}

	/* nothing else left to fail -- really log in */
	{
		struct utmp utmp;

		(void)time(&utmp.ut_time);
		(void) strncpy(utmp.ut_name, username, sizeof(utmp.ut_name));
		if (hostname)
		    (void) strncpy(utmp.ut_host, hostname,
				   sizeof(utmp.ut_host));
		else
		    bzero(utmp.ut_host, sizeof(utmp.ut_host));
		(void) strncpy(utmp.ut_line, tty, sizeof(utmp.ut_line));
		login(&utmp);
	}

	quietlog = access(HUSHLOGIN, F_OK) == 0;
	dolastlog(quietlog, tty);

	if (!hflag && !rflag && !kflag && !Kflag && !eflag && !gflag) {	/* XXX */
		static struct winsize win = { 0, 0, 0, 0 };

		(void)ioctl(0, TIOCSWINSZ, (char *)&win);
	}

	(void)chown(ttyn, pwd->pw_uid,
	    (gr = getgrnam(TTYGRPNAME)) ? gr->gr_gid : pwd->pw_gid);
	(void)chmod(ttyn, 0620);
	(void)setgid((gid_type) pwd->pw_gid);

	(void) initgroups(username, pwd->pw_gid);

#ifndef VFS
	quota(Q_DOWARN, pwd->pw_uid, (dev_t)-1, 0);
#endif
	(void)setuid((uid_type) pwd->pw_uid);

	if (*pwd->pw_shell == '\0')
		pwd->pw_shell = BSHELL;
	/* turn on new line discipline for the csh */
	else if (!strcmp(pwd->pw_shell, "/bin/csh")) {
		ioctlval = NTTYDISC;
		(void)ioctl(0, TIOCSETD, (char *)&ioctlval);
	}

	/* destroy environment unless user has requested preservation */
	if (!pflag)
		environ = envinit;
	(void)setenv("HOME", pwd->pw_dir, 1);
	(void)setenv("SHELL", pwd->pw_shell, 1);
	if (term[0] == '\0')
		(void) strncpy(term, stypeof(tty), sizeof(term));
	(void)setenv("TERM", term, 0);
	(void)setenv("USER", pwd->pw_name, 1);
	(void)setenv("PATH", "/usr/ucb:/bin:/usr/bin:/usr/local/bin:", 0);
	major_status = gss__stash_default_cred(&minor_status,
					       gss_delegated_cred_handle);

	if (tty[sizeof("tty")-1] == 'd')
		syslog(LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
	if (pwd->pw_uid == 0)
		if (hostname)
			syslog(LOG_NOTICE, "ROOT LOGIN %s FROM %.*s",
			    tty, UT_HOSTSIZE, hostname);
		else
			syslog(LOG_NOTICE, "ROOT LOGIN %s", tty);

	if (!quietlog) {
		struct stat st;

		motd();
		(void)sprintf(tbuf, "%s/%s", MAILDIR, pwd->pw_name);
		if (stat(tbuf, &st) == 0 && st.st_size != 0)
			printf("You have %smail.\n",
			    (st.st_mtime > st.st_atime) ? "new " : "");
	}

#ifdef VFS
	if (! access( QUOTAWARN, X_OK)) (void) system(QUOTAWARN);
#endif VFS
	(void)signal(SIGALRM, SIG_DFL);
	(void)signal(SIGQUIT, SIG_DFL);
	(void)signal(SIGINT, SIG_DFL);
	(void)signal(SIGTSTP, SIG_IGN);

	tbuf[0] = '-';
	(void) strcpy(tbuf + 1, (p = rindex(pwd->pw_shell, '/')) ?
	    p + 1 : pwd->pw_shell);
	execlp(pwd->pw_shell, tbuf, 0);
	fprintf(stderr, "login: no shell: ");
	perror(pwd->pw_shell);
	exit(0);
}

getloginname()
{
	register int ch;
	register char *p;
	static char nbuf[UT_NAMESIZE + 1];

	for (;;) {
		printf("login: ");
		for (p = nbuf; (ch = getchar()) != '\n'; ) {
			if (ch == EOF)
				exit(0);
			if (p < nbuf + UT_NAMESIZE)
				*p++ = ch;
		}
		if (p > nbuf)
			if (nbuf[0] == '-')
				fprintf(stderr,
				    "login names may not start with '-'.\n");
			else {
				*p = '\0';
				username = nbuf;
				break;
			}
	}
}

sigtype
timedout()
{
	fprintf(stderr, "Login timed out after %d seconds\n", timeout);
	exit(0);
}

#ifdef NOTTYENT
int root_tty_security = 0;
#endif
rootterm(tty)
	char *tty;
{
#ifdef NOTTYENT
	return(root_tty_security);
#else
	struct ttyent *t;

	return((t = getttynam(tty)) && t->ty_status&TTY_SECURE);
#endif NOTTYENT
}

jmp_buf motdinterrupt;

motd()
{
	register int fd, nchars;
	sigtype (*oldint)(), sigint();
	char tbuf[8192];

	if ((fd = open(MOTDFILE, O_RDONLY, 0)) < 0)
		return;
	signal(SIGINT, sigint);

	if (setjmp(motdinterrupt) == 0)
		while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
	(void)close(fd);
}

sigtype
sigint()
{
	longjmp(motdinterrupt, 1);
}

checknologin()
{
	register int fd, nchars;
	char tbuf[8192];

	if ((fd = open(NOLOGIN, O_RDONLY, 0)) >= 0) {
		while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
			(void)write(fileno(stdout), tbuf, nchars);
		sleepexit(0);
	}
}

dolastlog(quiet, tty)
	int quiet;
	char *tty;
{
	struct lastlog ll;
	int fd;

	if ((fd = open(LASTLOG, O_RDWR, 0)) >= 0) {
		(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
		if (!quiet) {
			if (read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll) &&
			    ll.ll_time != 0) {
				printf("Last login: %.*s ",
				    24-5, (char *)ctime(&ll.ll_time));
				if (*ll.ll_host != '\0')
					printf("from %.*s\n",
					    sizeof(ll.ll_host), ll.ll_host);
				else
					printf("on %.*s\n",
					    sizeof(ll.ll_line), ll.ll_line);
			}
			(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), L_SET);
		}
		(void)time(&ll.ll_time);
		(void) strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
		if (hostname)
		    (void) strncpy(ll.ll_host, hostname, sizeof(ll.ll_host));
		else
		    (void) bzero(ll.ll_host, sizeof(ll.ll_host));
		(void)write(fd, (char *)&ll, sizeof(ll));
		(void)close(fd);
	}
}

#undef	UNKNOWN
#define	UNKNOWN	"su"

char *
stypeof(ttyid)
	char *ttyid;
{
#ifdef NOTTYENT
	return(UNKNOWN);
#else
	struct ttyent *t;

	return(ttyid && (t = getttynam(ttyid)) ? t->ty_type : UNKNOWN);
#endif
}

doremotelogin(host)
	char *host;
{
	static char lusername[UT_NAMESIZE+1];
	char rusername[UT_NAMESIZE+1];

	getstr(rusername, sizeof(rusername), "remuser");
	getstr(lusername, sizeof(lusername), "locuser");
	getstr(term, sizeof(term), "Terminal type");
	username = lusername;
	pwd = getpwnam(username);
	if (pwd == NULL)
		return(-1);
	return(ruserok(host, (pwd->pw_uid == 0), rusername, username));
}

do_gss_login(host)
	char *host;
{
        int j, tokenlen, partlen, numbuf, i, debugflag = 0, auth_valid;
	unsigned char token[GSS_C_MAX_TOKEN], *charp, *cp;
	unsigned char tokenheader[4], send_tokenheader[4];
	char targ_printable[GSS_C_MAX_PRINTABLE_NAME];
	char  lhostname[GSS_C_MAX_PRINTABLE_NAME];
	unsigned char chanbinding[8];
	int     chanbinding_len;
	static char lusername[UT_NAMESIZE+1], rusername[UT_NAMESIZE+1];
        int   hostlen, xcc, need_to_exit = 0;
/*
 * GSS API support
 */
	gss_OID_set   actual_mechs;
	gss_OID       actual_mech_type, output_name_type;
	int           major_status, status, msg_ctx = 0, new_status;
	int           req_flags = 0, ret_flags, lifetime_rec;
	gss_cred_id_t gss_cred_handle;
	gss_ctx_id_t  actual_ctxhandle;
	gss_buffer_desc  output_token, input_token, input_name_buffer;
	gss_buffer_desc  status_string;
	gss_name_t    desired_targname, src_name;
	gss_channel_bindings   input_chan_bindings;


	j = sphinx_net_read(3, tokenheader, 4);
	if ((tokenheader[0] != TOKEN_MAJIC_NUMBER_BYTE0) ||
(tokenheader[1] != TOKEN_MAJIC_NUMBER_BYTE1)) {
	  exit(0);
	}
	tokenlen = tokenheader[2] * 256 + tokenheader[3];

	if (tokenlen > sizeof(token)) {
	  syslog(LOG_INFO, "token is too large, size is %d, buffer size
is %d", tokenlen, sizeof(token));
	  exit(0);
	}

	charp = token;
	j = sphinx_net_read(3, token, tokenlen);
	if (j != tokenlen)
	  syslog(LOG_INFO,"%d = read(3, token, %d)",j, tokenlen);
	close(3);

	gethostname(lhostname, sizeof(lhostname));

	strcpy(targ_printable, "SERVICE:rlogin@");
	strcat(targ_printable, lhostname);
/*
	strcpy(targetname, lhostname);
        if ((cp = index(targetname, '.')) != 0)  *cp = '\0';
*/

	input_name_buffer.length = strlen(targ_printable);
	input_name_buffer.value = targ_printable;

	major_status = gss_import_name(&status,
				       &input_name_buffer,
				       GSS_C_NULL_OID,
				       &desired_targname);

	major_status = gss_acquire_cred(&status,
					desired_targname,
					0,
					GSS_C_NULL_OID_SET,
					GSS_C_ACCEPT,
					&gss_cred_handle,
					&actual_mechs,
					&lifetime_rec);

	major_status = gss_release_name(&status, desired_targname);

	if (major_status != GSS_S_COMPLETE) {
	  xcc = write(0, "AuthentError", 12);
	  if (xcc <= 0)
	    syslog(LOG_INFO, "write(0, resp, 12): %m");

	  gss_display_status(&new_status,
			     status,
			     GSS_C_MECH_CODE,
			     GSS_C_NULL_OID,
			     &msg_ctx,
			     &status_string);
	  fprintf(stderr, "%s - ", status_string.value);
	  return(0);
	}

	getstr(rusername, sizeof (rusername), "remuser");
	getstr(lusername, sizeof (lusername), "locuser");
	getstr(term, sizeof(term), "Terminal type");

	username = lusername;

	pwd = getpwnam(lusername);
	if (pwd == NULL) {
	  syslog(LOG_INFO,"passwd entry for '%s' is NULL",lusername);
/*
	  xcc = write(0, "Auth Error  ", 12);
	  if (xcc <= 0)
	    syslog(LOG_INFO, "write(0, resp, 12): %m");
	  fprintf(stderr, "SPX : user account '%s' doesn't exist - ", lusername);
*/
	}

	if (major_status != GSS_S_COMPLETE) {
	  xcc = write(0, "AuthentError", 12);
	  if (xcc <= 0)
	    syslog(LOG_INFO, "write(0, resp, 12): %m");

	  gss_display_status(&new_status,
			     status,
			     GSS_C_MECH_CODE,
			     GSS_C_NULL_OID,
			     &msg_ctx,
			     &status_string);
	  fprintf(stderr, "%s - ", status_string.value);
	  return(0);
	}

	if (pwd != NULL) seteuid(pwd->pw_uid);

	{
	  char myhost[32];
	  int  from_addr=0, to_addr=0, myhostlen, j;
	  struct hostent *my_hp, *from_hp;
	  struct sockaddr_in sin, sin2;

	  from_hp=gethostbyname(host);
	  if (from_hp != 0) {
	    bcopy(from_hp->h_addr_list[0],
		  (caddr_t)&sin.sin_addr, from_hp->h_length);
#ifdef ultrix
	    from_addr = sin.sin_addr.S_un.S_addr;
#else
	    from_addr = sin.sin_addr.s_addr;
#endif
	  } else {
	    from_addr = inet_addr(host);
	  }
	  from_addr = htonl(from_addr);
	  j=gethostname(myhost, sizeof(myhost));
	  my_hp=gethostbyname(myhost);
	  if (my_hp != 0) {
	    bcopy(my_hp->h_addr_list[0],
		  (caddr_t)&sin2.sin_addr, my_hp->h_length);
#ifdef ultrix
	    to_addr = sin2.sin_addr.S_un.S_addr;
#else
	    to_addr = sin2.sin_addr.s_addr;
#endif
	    to_addr = htonl(to_addr);
	  }

	  input_chan_bindings = (gss_channel_bindings)
	    malloc(sizeof(gss_channel_bindings_desc));

	  input_chan_bindings->initiator_addrtype = GSS_C_AF_INET;
	  input_chan_bindings->initiator_address.length = 4;
	  input_chan_bindings->initiator_address.value = (char *) malloc(4);
	  input_chan_bindings->initiator_address.value[0] = ((from_addr
& 0xff000000) >> 24);
	  input_chan_bindings->initiator_address.value[1] = ((from_addr
& 0xff0000) >> 16);
	  input_chan_bindings->initiator_address.value[2] = ((from_addr
& 0xff00) >> 8);
	  input_chan_bindings->initiator_address.value[3] = (from_addr & 0xff);
	  input_chan_bindings->acceptor_addrtype = GSS_C_AF_INET;
	  input_chan_bindings->acceptor_address.length = 4;
	  input_chan_bindings->acceptor_address.value = (char *) malloc(4);
	  input_chan_bindings->acceptor_address.value[0] = ((to_addr &
0xff000000) >> 24);
	  input_chan_bindings->acceptor_address.value[1] = ((to_addr &
0xff0000) >> 16);
	  input_chan_bindings->acceptor_address.value[2] = ((to_addr &
0xff00) >> 8);
	  input_chan_bindings->acceptor_address.value[3] = (to_addr & 0xff);
	  input_chan_bindings->application_data.length = 0;
	}

	input_token.length = tokenlen;
	input_token.value = token;

	major_status = gss_accept_sec_context(&status,
					      &context_handle,
					      gss_cred_handle,
					      &input_token,
					      input_chan_bindings,
					      &src_name,
					      &actual_mech_type,
					      &output_token,
					      &ret_flags,
					      &lifetime_rec,
					      &gss_delegated_cred_handle);

	if (output_token.length != 0) {

	  send_tokenheader[0] = TOKEN_MAJIC_NUMBER_BYTE0;
	  send_tokenheader[1] = TOKEN_MAJIC_NUMBER_BYTE1;
	  send_tokenheader[2] = ((output_token.length & 0xff00) >> 8);
	  send_tokenheader[3] = (output_token.length & 0xff);

	  xcc = write(0, (char *) send_tokenheader, 4);
	  if (xcc != 4)
	    syslog(LOG_INFO, "write(0, send_tokenheader, 4): %m");

	  xcc = write(0, (char *) output_token.value, output_token.length);
	  if (xcc <= 0)
	    syslog(LOG_INFO, "write(0, resp, %d): %m",output_token.length);
	}

	if (pwd == NULL) {
	  fprintf(stderr, "SPX : user account '%s' doesn't exist - ", lusername);
	  return(-1);
	}
	if (getuid()) {
	        syslog(LOG_INFO,"getuid() is 0, so return nouser");
		return(0);
	}

	if (major_status != GSS_S_COMPLETE) {
	  syslog(LOG_INFO, "got error on accept\n");
	  gss_display_status(&new_status,
			     status,
			     GSS_C_MECH_CODE,
			     GSS_C_NULL_OID,
			     &msg_ctx,
			     &status_string);
	  fprintf(stderr, "%s - ", status_string.value);
	  return(-1);
	}

#ifdef SPX_CHALLENGE
	/*
	 * if trying to login to root account, then we need to verify response
	 * proving that the user is interactive.
	 *
	 */
	if (strcmp(lusername, "root")==0) {
	  j = sphinx_net_read(0, tokenheader, 4);
	  if (j != 4)
	    syslog(LOG_INFO,"%d = read(0, token, 4)",j);

	  if ((tokenheader[0] != TOKEN_MAJIC_NUMBER_BYTE0) ||
(tokenheader[1] != TOKEN_MAJIC_NUMBER_BYTE1)) {
	    exit(0);
	  }
	  tokenlen = tokenheader[2] * 256 + tokenheader[3];
	  if (tokenlen > sizeof(token)) {
	     syslog(LOG_INFO, "token too large, %d/%d",tokenlen,sizeof(token));
	    exit(0);
	  }

	  charp = token;
	  j = sphinx_net_read(0, token, tokenlen);
	  if (j != tokenlen)
	    syslog(LOG_INFO,"%d = read(0, token, %d)",j, tokenlen);
	  major_status = spx_verify_response(&status,
					     context_handle,
					     gss_cred_handle,
					     token,
					     tokenlen);
	  if (major_status != GSS_S_COMPLETE) {
	    gss_display_status(&new_status,
			       status,
			       GSS_C_MECH_CODE,
			       GSS_C_NULL_OID,
			       &msg_ctx,
			       &status_string);
	    fprintf(stderr, "%s - ", status_string.value);
	    return(0);
	  }
	}
#endif  /* SPX_CHALLENGE */

	seteuid(0);

	{
	  gss_buffer_desc  fullname_buffer, luser_buffer, acl_file_buffer;
	  gss_buffer_desc  service_buffer, resource_buffer;
	  gss_OID          fullname_type;
	  int              access_mode;
	  char             acl_file[160], service[60], resource[160];

	  major_status = gss_display_name(&status,
					  src_name,
					  &fullname_buffer,
					  &fullname_type);

	  luser_buffer.value = lusername;
	  luser_buffer.length = strlen(lusername);

	  strcpy(acl_file, pwd->pw_dir);
	  strcat(acl_file, "/.sphinx");
	  acl_file_buffer.value = acl_file;
	  acl_file_buffer.length = strlen(acl_file);

	  strcpy(service, "flogin");
	  service_buffer.value = service;
	  service_buffer.length = 6;
	  resource[0] = '\0';
	  resource_buffer.value = resource;
	  resource_buffer.length = 0;
	  access_mode = GSS_C_READ | GSS_C_WRITE;

	  major_status = gss__check_authorization(&status,
						  &fullname_buffer,
						  &luser_buffer,
						  &acl_file_buffer,
						  &service_buffer,
						  access_mode,
						  &resource_buffer);

	  if (major_status != GSS_S_COMPLETE) {
	    if (strcmp(lusername, "root")==0)
	      syslog(LOG_INFO, "root authorization denied - '%s'", src_name);
	    fprintf(stderr, "SPX : authorization denied to user account
'%s' - ", lusername);
	    return(-1);
	  } else {
	    strcpy(userfullname, src_name);
	    strcpy(userlocalname, rusername);
	  }
	  major_status = gss_release_buffer(&status, &fullname_buffer);
	  return(1);
	}
}

getstr(buf, cnt, err)
	char *buf, *err;
	int cnt;
{
	char ch;

	do {
		if (read(0, &ch, sizeof(ch)) != sizeof(ch))
			exit(1);
		if (--cnt < 0) {
			fprintf(stderr, "%s too long\r\n", err);
			sleepexit(1);
		}
		*buf++ = ch;
	} while (ch);
}

char *speeds[] = {
	"0", "50", "75", "110", "134", "150", "200", "300", "600",
	"1200", "1800", "2400", "4800", "9600", "19200", "38400",
};
#define	NSPEEDS	(sizeof(speeds) / sizeof(speeds[0]))

doremoteterm(tp)
	struct sgttyb *tp;
{
	register char *cp = index(term, '/'), **cpp;
	char *speed;

	if (cp) {
		*cp++ = '\0';
		speed = cp;
		cp = index(speed, '/');
		if (cp)
			*cp++ = '\0';
		for (cpp = speeds; cpp < &speeds[NSPEEDS]; cpp++)
			if (strcmp(*cpp, speed) == 0) {
				tp->sg_ispeed = tp->sg_ospeed = cpp-speeds;
				break;
			}
	}
	tp->sg_flags = ECHO|CRMOD|ANYP|XTABS;
}

sleepexitnew(eval, interval)
	int eval, interval;
{
	sleep((u_int)interval);
	exit(eval);
}


sleepexit(eval)
	int eval;
{
	sleep((u_int)5);
	exit(eval);
}
