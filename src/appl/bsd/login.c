/*
 *	$Source$
 *	$Author$
 *	$Id$
 */

#ifndef lint
static char rcsid_login_c[] = "$Id$";
#endif lint

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

#define KERBEROS
     
     /*
      * login -f name	(for pre-authenticated login)
      * login name           (for non-authenticated/non-authorized login)
      */
     
#define VFS
#define BYPASS_ROOT_CHK
     
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
int timeout = 300;

struct passwd *pwd;
char term[64], *hostname, *username = NULL;

struct sgttyb sgttyb;
struct tchars tc = {
    CINTR, CQUIT, CSTART, CSTOP, CEOT, CBRK
  };
struct ltchars ltc = {
    CSUSP, CDSUSP, CRPRNT, CFLUSH, CWERASE, CLNEXT
  };

extern int errno;

char *getenv();
int putenv();
void setenv();
void dofork();

#ifdef POSIX
typedef void sigtype;
#else
typedef int sigtype;
#endif /* POSIX */

#ifdef CRAY
char    user[32] = "LOGNAME=";
#include <tmpdir.h>
char tmpdir[64] = "TMPDIR=";
#else
char	user[20] = "USER=";
#endif

char	homedir[64] = "HOME=";
char	shell[64] = "SHELL=";


#ifdef KERBEROS
char    *envinit[] =
#ifdef CRAY
    {homedir, shell, PATH, user, "TZ=GMT0", tmpdir, 0};
#define TZENV   4
#define TMPDIRENV 5
char    *getenv();
extern
#else
    {homedir, shell, "PATH=:/usr/ucb:/bin:/usr/bin:/usr/bin/kerberos",
   user, 0};
#endif /* CRAY */
#else /* !KERBEROS */
char	*envinit[] =
#ifdef CRAY
    {homedir, shell, PATH, user, "TZ=GMT0", tmpdir, 0};
#define TZENV   4
#define TMPDIRENV 5
char    *getenv();
extern
#else
    {homedir, shell, "PATH=:/usr/ucb:/bin:/usr/bin:/usr/bin/kerberos",
   user, 0};
#endif /* CRAY */
#endif /* KERBEROS */
char **environ;

main(argc, argv)
     int argc;
     char **argv;
{
    extern int optind;
    extern char *optarg;
    struct group *gr;
    register int ch;
    register char *p;
    int fflag, pflag, cnt;
    int quietlog, ioctlval;
    sigtype timedout();
    char *domain, *salt, *ttyn, *tty;
    char tbuf[MAXPATHLEN + 2];
    char *ttyname(), *stypeof(), *crypt(), *getpass();
    time_t time();
    off_t lseek();
    int passwd_req = 1, preserve_env = 0;
    
    (void)signal(SIGALRM, timedout);
    (void)alarm((u_int)timeout);
    (void)signal(SIGQUIT, SIG_IGN);
    (void)signal(SIGINT, SIG_IGN);
    (void)setpriority(PRIO_PROCESS, 0, 0);
#ifndef VFS
    (void)quota(Q_SETUID, 0, 0, 0);
#endif VFS
    
    (void)gethostname(tbuf, sizeof(tbuf));
    domain = index(tbuf, '.');
    
    passwd_req = 1;
    while ((ch = getopt(argc, argv, "fp")) != EOF)
      switch (ch) {
	case 'f':
	  passwd_req = 0;
	  break;
	case 'p':
	  preserve_env = 1;
	  break;
	case '?':
	default:
	  fprintf(stderr, "usage: login [-fp] [username]\n");
	  exit(1);
	  break;
      }
    argc -= optind;
    argv += optind;
    if (*argv)
      hostname = *argv;
    
    ioctlval = 0;
    (void)ioctl(0, TIOCLSET, (char *)&ioctlval);
    (void)ioctl(0, TIOCNXCL, (char *)0);
    (void)fcntl(0, F_SETFL, ioctlval);
    (void)ioctl(0, TIOCGETP, (char *)&sgttyb);
    
    doremotelogin();
    
    /*
     * If talking to an rlogin process, propagate the terminal type and
     * baud rate across the network.
     */
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
    
#ifndef LOG_ODELAY /* 4.2 syslog ... */                      
    openlog("login", 0);
#else
    openlog("login", LOG_ODELAY, LOG_AUTH);
#endif /* 4.2 syslog */
    
    for (cnt = 0;; username = NULL) {
	ioctlval = 0;
	(void)ioctl(0, TIOCSETD, (char *)&ioctlval);
	
	if (username == NULL) 
	  getloginname();
	
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
	if (!passwd_req && pwd) {
	    int uid = (int) getuid();
	    
	    passwd_req = (uid && uid != pwd->pw_uid)
#ifndef BYPASS_ROOT_CHK
	      || (pwd->pw_uid == 0);
#else
	    ;
#endif
	}
	
	/*
	 * If no remote login authentication and a password exists
	 * for this user, prompt for one and verify it.
	 */
	if (!passwd_req || pwd && !*pwd->pw_passwd)
	  break;
	
	(void) setpriority(PRIO_PROCESS, 0, -4);
	p = crypt(getpass("Password:"), salt);
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
#ifndef BYPASS_ROOT_CHK
    if (pwd->pw_uid == 0 && !rootterm(tty)) {
	if (hostname)
	  syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s FROM %.*s",
		 tty, UT_HOSTSIZE, hostname);
	else
	  syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s", tty);
	printf("Login incorrect\n");
	sleepexit(1);
    }
#endif
    
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
    
    {
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
    /* Destroy old environment unless requested. */ 
    if (!preserve_env)
      environ = envinit;
    
    setenv("HOME", pwd->pw_dir);
    setenv("SHELL", pwd->pw_shell);
    if (term[0] == '\0')
      (void) strncpy(term, stypeof(tty), sizeof(term));
    setenv("TERM", term);
    setenv("USER", pwd->pw_name);
    setenv("PATH", "/usr/ucb:/bin:/usr/bin:");
    
    if (tty[sizeof("tty")-1] == 'd')
      syslog(LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
    
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
    oldint = (sigtype (*)()) signal(SIGINT, sigint);
    if (setjmp(motdinterrupt) == 0)
      while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
	(void)write(fileno(stdout), tbuf, nchars);
    (void)signal(SIGINT, oldint);
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

char *stypeof(ttyid)
     char *ttyid;
{
#ifdef NOTTYENT
    return(UNKNOWN);
#else
    struct ttyent *t;
    
    return(ttyid && (t = getttynam(ttyid)) ? t->ty_type : UNKNOWN);
#endif
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



doremotelogin()
{
    static char lusername[UT_NAMESIZE+1];
    char rusername[UT_NAMESIZE+1];
    
    getstr(rusername, sizeof(rusername), "remuser");
    getstr(lusername, sizeof(lusername), "locuser");
    if (username == NULL)
      username = lusername;
    getstr(term, sizeof(term), "Terminal type");
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



sleepexit(eval)
     int eval;
{
    sleep((u_int)5);
    exit(eval);
}



void setenv(var, value)
     char *var, *value;
{
    char *env_str;
    int retval, str_size = strlen(var) + strlen(value) + strlen("=") + 1;
    
    env_str = (char *) malloc(str_size);
    
    strcpy(env_str, var);
    strcat(env_str, "=");
    strcat(env_str, value);
    env_str[str_size-1] = '\0';
    
    if (retval = putenv(env_str)) {
	syslog(LOG_ERR, "Not enough memory\n");
	exit(1);
    }
}
