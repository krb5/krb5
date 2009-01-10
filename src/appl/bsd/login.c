/*
 *	appl/bsd/login.c
 */

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

/* based on @(#)login.c	5.25 (Berkeley) 1/6/89 */

/* The configuration, with defaults as listed, is of the form:
   [login]
   # login stanza
   krb5_get_tickets = 1
   # use password to get v5 tickets
   krb_run_aklog = 0
   # attempt to run aklog
   aklog_path = $(prefix)/bin/aklog
   # where to find it [not yet implemented]
   accept_passwd = 0
   # don't accept plaintext passwords [not yet implemented]
*/
#define KRB5_GET_TICKETS
int login_krb5_get_tickets = 1;

#define KRB_RUN_AKLOG
int login_krb_run_aklog = 0;

int login_accept_passwd = 0;

/*
 * login [ name ]
 * login -r hostname	(for rlogind)
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.,
 *			 does allow preauthenticated login as root)
 * login -F name	(for pre-authenticated login: datakit, xterm, etc.,
 *			 allows preauthenticated login as root)
 * login -e name	(for pre-authenticated encrypted, must do term
 *			 negotiation)
 *
 * only one of: -r -f -e -k -K -F
 * only one of: -r -h -k -K
 */

#include <libpty.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#ifdef OQUOTA
#include <sys/quota.h>
#endif
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <utmp.h>
#include <signal.h>

#include <assert.h>

#ifdef HAVE_LASTLOG_H
#include <lastlog.h>
#endif

#ifdef linux
/* linux has V* but not C* in headers. Perhaps we shouldn't be
 * initializing these values anyway -- tcgetattr *should* give
 * them reasonable defaults... */
#define NO_INIT_CC
#endif

#include <errno.h>
#ifdef HAVE_TTYENT_H
#include <ttyent.h>
#endif
#include <syslog.h>
#include <stdio.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>

#include <setjmp.h>
#ifndef POSIX_SETJMP
#undef sigjmp_buf
#undef sigsetjmp
#undef siglongjmp
#define sigjmp_buf	jmp_buf
#define sigsetjmp(j,s)	setjmp(j)
#define siglongjmp	longjmp
#endif

#ifdef POSIX_SIGNALS
typedef struct sigaction handler;
#define handler_init(H,F)		(sigemptyset(&(H).sa_mask), \
					 (H).sa_flags=0, \
					 (H).sa_handler=(F))
#define handler_swap(S,NEW,OLD)		sigaction(S, &NEW, &OLD)
#define handler_set(S,OLD)		sigaction(S, &OLD, NULL)
#else
typedef sigtype (*handler)();
#define handler_init(H,F)		((H) = (F))
#define handler_swap(S,NEW,OLD)		((OLD) = signal ((S), (NEW)))
#define handler_set(S,OLD)		(signal ((S), (OLD)))
#endif


#ifdef HAVE_SHADOW
#include <shadow.h>
#endif

#ifdef KRB5_GET_TICKETS
/* #include "krb5.h" */
/* need k5-int.h to get ->profile from krb5_context */
#include "k5-int.h"
#include "com_err.h"
#include "osconf.h"
#endif /* KRB5_GET_TICKETS */

#ifndef __STDC__
#ifndef volatile
#define volatile
#endif
#endif

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "loginpaths.h"

#ifdef POSIX_TERMIOS
#include <termios.h>
#ifndef CNUL
#define CNUL (char) 0
#endif

#endif

#ifdef _IBMR2
#include <usersec.h>
#include <sys/id.h>
#endif

#if defined(_AIX)
#define PRIO_OFFSET 20
#else
#define PRIO_OFFSET 0
#endif

#if !defined(TAB3)
#define TAB3 0
#endif

#define	TTYGRPNAME	"tty"		/* name of group to own ttys */

#if defined(_PATH_MAILDIR)
#define MAILDIR		_PATH_MAILDIR
#else
#define MAILDIR		"/usr/spool/mail"
#endif
#if defined(_PATH_NOLOGIN)
#define NOLOGIN		_PATH_NOLOGIN
#else
#define NOLOGIN		"/etc/nologin"
#endif
#if defined(_PATH_LASTLOG)
#define LASTLOG		_PATH_LASTLOG
#else
#define LASTLOG		"/usr/adm/lastlog"
#endif
#if defined(_PATH_BSHELL)
#define BSHELL		_PATH_BSHELL
#else
#define BSHELL		"/bin/sh"
#endif

#if (defined(BSD) && (BSD >= 199103))	/* no /usr/ucb */
#define QUOTAWARN	"/usr/bin/quota"
#endif

#define	MOTDFILE	"/etc/motd"
#define	HUSHLOGIN	".hushlogin"

#if !defined(OQUOTA) && !defined(QUOTAWARN)
#define QUOTAWARN	"/usr/ucb/quota" /* warn user about quotas */
#endif

#ifndef NO_UT_HOST
#ifndef UT_HOSTSIZE
/* linux defines it directly in <utmp.h> */
#define	UT_HOSTSIZE	sizeof(((struct utmp *)0)->ut_host)
#endif /* UT_HOSTSIZE */
#endif
#ifndef UT_NAMESIZE
/* linux defines it directly in <utmp.h> */
#define	UT_NAMESIZE	sizeof(((struct utmp *)0)->ut_name)
#endif

#ifndef HAVE_SETPRIORITY
/* if we don't have it, punt it cleanly */
#define setpriority(which,who,prio)
#endif /* HAVE_SETPRIORITY */

#define MAXENVIRON	32

#ifdef NEED_SETENV
extern int setenv(char *, char *, int);
#endif

/*
 * This bounds the time given to login.  Not a define so it can
 * be patched on machines where it's too small.
 */
int	timeout = 300;

#if 0
char term[64], *hostname, *username;
#else
char term[64], *username;
#endif



#ifdef KRB5_GET_TICKETS
#define MAXPWSIZE	128		/* Biggest string accepted for KRB5
					   passsword */
#endif

#if defined(__SVR4) || defined(sgi)
#define NO_MOTD
#define NO_MAILCHECK
#endif

char *getenv();
void dofork(void);

char *stypeof(char *);
void term_init(int);
int doremotelogin(char *), do_krb_login(char *, int), rootterm(char *);
void lgetstr(char *, int, char *), getloginname(void), checknologin(void);
void dolastlog(char *, int, char *), motd(void), check_mail(void);
void sleepexit(int);

#ifndef HAVE_STRSAVE
char * strsave(char *);
#endif

typedef krb5_sigtype sigtype;

sigtype timedout(int);


#ifndef HAVE_INITGROUPS
static int initgroups(char* name, gid_t basegid) {
    gid_t others[NGROUPS_MAX+1];
    int ngrps;

    others[0] = basegid;
    ngrps = getgroups(NGROUPS_MAX, others+1);
    return setgroups(ngrps+1, others);
}
#endif

static struct login_confs {
    char *flagname;
    int *flag;
} login_conf_set[] = {
#ifdef KRB5_GET_TICKETS
    {"krb5_get_tickets", &login_krb5_get_tickets},
    {"krb_run_aklog", &login_krb_run_aklog},
#endif
};

static char *conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    0
};

static char *conf_no[] = {
    "n", "no", "false", "nil", "0", "off",
    0
};

/* 1 = true, 0 = false, -1 = ambiguous */
static int conf_affirmative(s)
     char *s;
{
    char **p;

    for(p=conf_yes; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 1;
    }

    for(p=conf_no; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 0;
    }

    /* ambiguous */
    return -1;
}

#ifdef KRB5_GET_TICKETS
krb5_data tgtname = {
    0,
    KRB5_TGS_NAME_SIZE,
    KRB5_TGS_NAME
};
#endif

/* get flags (listed above) from the profile */
static void login_get_kconf(k)
     krb5_context k;
{
    int i, max_i;
    const char* kconf_names[3];
    char **kconf_val;
    int retval;

    max_i = sizeof(login_conf_set)/sizeof(struct login_confs);
    for (i = 0; i<max_i; i++) {
	kconf_names[0] = "login";
	kconf_names[1] = login_conf_set[i].flagname;
	kconf_names[2] = 0;
	retval = profile_get_values(k->profile, 
				    kconf_names, &kconf_val);
	if (retval) {
	    /* ignore most (all?) errors */
	} else if (kconf_val && *kconf_val) {
	    switch(conf_affirmative(*kconf_val)) {
	    case 1:
		*login_conf_set[i].flag = 1;
		break;
	    case 0:
		*login_conf_set[i].flag = 0;
		break;
	    default:
	    case -1:
		com_err("login/kconf", 0,
			"invalid flag value %s for flag %s",
			*kconf_val, kconf_names[1]);
		break;
	    }
	}
    }
}

/* UNIX password support */

struct passwd *pwd;
static char *salt;

#ifdef HAVE_SHADOW
struct spwd *spwd;
#endif

static void lookup_user (name)
    char *name;
{
    pwd = getpwnam (name);
    salt = pwd ? pwd->pw_passwd : "xx";
#ifdef HAVE_SHADOW
    spwd = getspnam (name);
    if (spwd)
	salt = spwd->sp_pwdp;
#endif
}

static int unix_needs_passwd ()
{
#ifdef HAVE_SHADOW
    if (spwd)
	return spwd->sp_pwdp[0] != 0;
#endif
    if (pwd)
	return pwd->pw_passwd[0] != 0;
    return 1;
}

static int unix_passwd_okay (pass)
    char *pass;
{
    char user_pwcopy[9], *namep;
    char *crypt ();

    assert (pwd != 0);

    /* copy the first 8 chars of the password for unix crypt */
    strncpy(user_pwcopy, pass, sizeof(user_pwcopy));
    user_pwcopy[sizeof(user_pwcopy) - 1]='\0';
    namep = crypt(user_pwcopy, salt);
    memset (user_pwcopy, 0, sizeof(user_pwcopy));
    /* ... and wipe the copy now that we have the string */

    /* verify the local password string */
#ifdef HAVE_SHADOW
    if (spwd)
	return !strcmp(namep, spwd->sp_pwdp);
#endif
    return !strcmp (namep, pwd->pw_passwd);
}

/* Kerberos support */
#ifdef KRB5_GET_TICKETS
krb5_context kcontext;
krb5_ccache ccache;
krb5_creds my_creds;
static int got_v5_tickets, forwarded_v5_tickets;
char ccfile[MAXPATHLEN+6];	/* FILE:path+\0 */
int krbflag;			/* set if tickets have been obtained */
#endif /* KRB5_GET_TICKETS */

void k_init (ttyn)
    char *ttyn;
{
#ifdef KRB5_GET_TICKETS
    krb5_error_code retval;
    
    retval = krb5_init_secure_context(&kcontext);
    if (retval) {
	com_err("login", retval, "while initializing krb5");
	exit(1);
    }

    login_get_kconf(kcontext);

    /* Set up the credential cache environment variable */
    if (!getenv(KRB5_ENV_CCNAME)) {
	snprintf(ccfile, sizeof(ccfile), "FILE:/tmp/krb5cc_p%ld",
		 (long) getpid());
	setenv(KRB5_ENV_CCNAME, ccfile, 1);
	krb5_cc_set_default_name(kcontext, ccfile);
	unlink(ccfile+strlen("FILE:"));
    } else {
	/* note it correctly */
	strncpy(ccfile, getenv(KRB5_ENV_CCNAME), sizeof(ccfile));
	ccfile[sizeof(ccfile) - 1] = '\0';
    }
#endif

#ifdef BIND_HACK
    /* Set name server timeout to be reasonable,
       so that people don't take 5 minutes to
       log in.  Can you say abstraction violation? */
    _res.retrans = 1;
#endif /* BIND_HACK */
}

#ifdef KRB5_GET_TICKETS
static int k5_get_password (user_pwstring, pwsize)
    char *user_pwstring;
    unsigned int pwsize;
{
    krb5_error_code code;
    char prompt[255];			
    snprintf(prompt, sizeof(prompt), "Password for %s", username);

    /* reduce opportunities to be swapped out */
    code = krb5_read_password(kcontext, prompt, 0, user_pwstring, &pwsize);
    if (code || pwsize == 0) {
	fprintf(stderr, "Error while reading password for '%s'\n", username);
	/* reading password failed... */
	return 0;
    }
    if (pwsize == 0) {
	fprintf(stderr, "No password read\n");
	/* reading password failed... */
	return 0;
    }
    return 1;
}

static int try_krb5 (me_p, pass)
    krb5_principal *me_p;
    char *pass;
{
    krb5_error_code code;
    krb5_principal me;

    code = krb5_parse_name(kcontext, username, &me);
    if (code) {
	com_err ("login", code, "when parsing name %s",username);
	return 0;
    }

    *me_p = me;

    code = krb5_get_init_creds_password(kcontext, &my_creds, me, pass,
					krb5_prompter_posix, NULL,
					0, NULL, NULL);
    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    fprintf (stderr,
		     "%s: Kerberos password incorrect\n", 
		     username);
	else
	    com_err ("login", code,
		     "while getting initial credentials");
	return 0;
    }

    krbflag = got_v5_tickets = 1;

    return 1;
}

static int have_v5_tickets (me)
    krb5_principal *me;
{
    if (krb5_cc_default (kcontext, &ccache))
	return 0;
    if (krb5_cc_get_principal (kcontext, ccache, me)) {
	krb5_cc_close (kcontext, ccache);
	return 0;
    }
    krbflag = 1;
    return 1;
}
#endif /* KRB5_GET_TICKETS */

/* Kerberos ticket-handling routines */

static void destroy_tickets()
{
#ifdef KRB5_GET_TICKETS
    krb5_ccache cache;

    if (login_krb5_get_tickets) {
	if(!krb5_cc_default(kcontext, &cache))
	  krb5_cc_destroy (kcontext, cache);
    }
#endif
}

/* AFS support routines */
#ifdef SETPAG

int pagflag = 0;			/* true if setpag() has been called */

/* This doesn't seem to be declared in the AFS header files.  */
extern ktc_ForgetAllTokens (), setpag ();

#ifdef SIGSYS
static sigjmp_buf setpag_buf;

static sigtype sigsys ()
{
    siglongjmp(setpag_buf, 1);
}

static int try_afscall (scall)
	int (*scall)();
{
    handler sa, osa;
    volatile int retval = 0;

    (void) &retval;
    handler_init (sa, sigsys);
    handler_swap (SIGSYS, sa, osa);
    if (sigsetjmp(setpag_buf, 1) == 0) {
	(*scall)();
	retval = 1;
    }
    handler_set (SIGSYS, osa);
    return retval;
}

#define try_setpag()	try_afscall(setpag)
#define try_unlog()	try_afscall(ktc_ForgetAllTokens)
#else
#define try_setpag()	(setpag() == 0)
#define try_unlog()	(ktc_ForgetAllTokens() == 0)
#endif /* SIGSYS */
#endif /* SETPAG */

static void
afs_login ()
{
#if defined(SETPAG)
    if (login_krb5_get_tickets && pwd->pw_uid) {
	/* Only reset the pag for non-root users. */
	/* This allows root to become anything. */
	pagflag = try_setpag ();
    }
#endif
#ifdef KRB_RUN_AKLOG
    if (got_v5_tickets && login_krb_run_aklog) {
	/* KPROGDIR is $(prefix)/bin */
	char aklog_path[MAXPATHLEN];
	struct stat st;
	/* construct the name */
	/* get this from profile later */
	aklog_path[sizeof(aklog_path) - 1] = '\0';
	strncpy (aklog_path, KPROGDIR, sizeof(aklog_path) - 1);
	strncat (aklog_path, "/aklog", sizeof(aklog_path) - 1 - strlen(aklog_path));
	/* only run it if we can find it */
	if (stat (aklog_path, &st) == 0) {
	    system(aklog_path);
	}
    }
#endif /* KRB_RUN_AKLOG */
}

static void
afs_cleanup ()
{
#ifdef SETPAG
    if (pagflag)
      try_unlog ();
#endif
}

/* Main routines */
#define EXCL_AUTH_TEST if (rflag || kflag || Kflag || eflag || fflag ) { \
    fprintf(stderr, \
	    "login: only one of -r, -k, -K, -e, -F, and -f allowed.\n"); \
    exit(1); \
}

#define EXCL_HOST_TEST if (rflag || kflag || Kflag || hflag) { \
    fprintf(stderr, \
	    "login: only one of -r, -k, -K, and -h allowed.\n"); \
    exit(1); \
}

#if defined(HAVE_ETC_ENVIRONMENT) || defined(HAVE_ETC_TIMEZONE)
static void
read_env_vars_from_file (filename)
    char *filename;
{
    FILE *fp;
    char *p, *eq;
    char tbuf[MAXPATHLEN+2];

    if ((fp = fopen(filename, "r")) != NULL) {
	while (fgets(tbuf, sizeof(tbuf), fp)) {
	    if (tbuf[0] == '#')
		continue;
	    eq = strchr(tbuf, '=');
	    if (eq == 0)
		continue;
	    p = strchr (tbuf, '\n');
	    if (p)
		*p = 0;
	    *eq++ = 0;
	    /* Don't override, in case -p was used.  */
	    setenv (tbuf, eq, 0);
	}
	fclose(fp);
    }
}
#endif

static void
log_repeated_failures (tty, hostname)
    char *tty, *hostname;
{
    if (hostname) {
#ifdef UT_HOSTSIZE
	syslog(LOG_ERR,
	       "REPEATED LOGIN FAILURES ON %s FROM %.*s, %.*s",
	       tty, UT_HOSTSIZE, hostname, UT_NAMESIZE,
	       username);
#else
	syslog(LOG_ERR,
	       "REPEATED LOGIN FAILURES ON %s FROM %s, %.*s",
	       tty, hostname, UT_NAMESIZE,
	       username);
#endif
    } else {
	syslog(LOG_ERR,
	       "REPEATED LOGIN FAILURES ON %s, %.*s",
	       tty, UT_NAMESIZE, username);
    }
}

int main(argc, argv)
     int argc;
     char **argv;
{
    extern int optind;
    extern char *optarg, **environ;
    struct group *gr;
    int ch;
    char *p;
    int fflag, hflag, pflag, rflag, cnt;
    int kflag, Kflag, eflag;
    int quietlog, passwd_req, ioctlval;
    char *domain, **envinit, *ttyn, *tty;
    char tbuf[MAXPATHLEN + 2];
    char *ttyname(), *crypt(), *getpass();
    time_t login_time;
    int retval;
    int rewrite_ccache = 1; /*try to write out ccache*/
#ifdef KRB5_GET_TICKETS
    krb5_principal me;
    krb5_creds save_v5creds;
    krb5_ccache xtra_creds = NULL;
#endif
    char *ccname = 0;   /* name of forwarded cache */
    char *tz = 0;
    char *hostname = 0;

    off_t lseek();
    handler sa;

    handler_init (sa, timedout);
    handler_set (SIGALRM, sa);
    (void)alarm((u_int)timeout);

    handler_init (sa, SIG_IGN);
    handler_set (SIGQUIT, sa);
    handler_set (SIGINT, sa);
    setpriority(PRIO_PROCESS, 0, 0 + PRIO_OFFSET);
#ifdef OQUOTA
    (void)quota(Q_SETUID, 0, 0, 0);
#endif

    /*
     * -p is used by getty to tell login not to destroy the environment
     * -r is used by rlogind to cause the autologin protocol;
     * -f is used to skip a second login authentication 
     * -F is used to skip a second login authentication, allows login as root 
     * -e is used to skip a second login authentication, but allows
     * 	login as root.
     * -h is used by other servers to pass the name of the
     * remote host to login so that it may be placed in utmp and wtmp
     */
    (void)gethostname(tbuf, sizeof(tbuf));
    domain = strchr(tbuf, '.');

    fflag = hflag = pflag = rflag = kflag = Kflag = eflag = 0;
    passwd_req = 1;
    while ((ch = getopt(argc, argv, "Ffeh:pr:k:K:")) != -1)
	switch (ch) {
	case 'f':
	    EXCL_AUTH_TEST;
	    fflag = 1;
	    break;
	case 'F':
	    EXCL_AUTH_TEST;
	    fflag = 1;
	    break;
	case 'h':
	    EXCL_HOST_TEST;
	    if (getuid()) {
		fprintf(stderr,
			"login: -h for super-user only.\n");
		exit(1);
	    }
	    hflag = 1;
	    if (domain && (p = strchr(optarg, '.')) && strcmp(p, domain) == 0)
		*p = 0;
	    hostname = optarg;
	    break;
	case 'p':
	    pflag = 1;
	    break;
	case 'r':
	    EXCL_AUTH_TEST;
	    EXCL_HOST_TEST;
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
	    if (domain && (p = strchr(optarg, '.')) && !strcmp(p, domain))
		*p = '\0';
	    hostname = optarg;
	    break;
	case 'e':
	    EXCL_AUTH_TEST;
	    if (getuid()) {
		fprintf(stderr,
			"login: -e for super-user only.\n");
		exit(1);
	    }
	    eflag = 1;
	    passwd_req = 0;
	    break;
	case '?':
	default:
	    fprintf(stderr, "usage: login [-fp] [username]\n");
	    exit(1);
	}
    argc -= optind;
    argv += optind;
    /* Throw away too-long names, they can't be usernames.  */
    if (*argv) {
	if (strlen (*argv) <= UT_NAMESIZE)
	    username = *argv;
	else
	    fprintf (stderr, "login name '%s' too long\n", *argv);
    }

#if !defined(POSIX_TERMIOS) && defined(TIOCLSET)
    ioctlval = 0;
    /* Only do this we we're not using POSIX_TERMIOS */
    (void)ioctl(0, TIOCLSET, (char *)&ioctlval);
#endif
	
#ifdef TIOCNXCL
    (void)ioctl(0, TIOCNXCL, (char *)0);
#endif
	
    ioctlval = fcntl(0, F_GETFL);
#ifdef O_NONBLOCK
    ioctlval &= ~O_NONBLOCK;
#endif
#ifdef O_NDELAY
    ioctlval &= ~O_NDELAY;
#endif
    (void)fcntl(0, F_SETFL, ioctlval);

	/*
	 * If talking to an rlogin process, propagate the terminal type and
	 * baud rate across the network.
	 */
    if (eflag) {
	lgetstr(term, sizeof(term), "Terminal type");
    } else if (!(kflag || Kflag)) {/* Preserve terminal if not read over net */
	if (getenv("TERM")) {
	    strncpy(term, getenv("TERM"), sizeof(term));
	    term[sizeof(term) - 1] = '\0';
	}
    }
	
    term_init (rflag || kflag || Kflag || eflag);

    for (cnt = getdtablesize(); cnt > 2; cnt--)
	(void) close(cnt);

    ttyn = ttyname(0);
    if (ttyn == NULL || *ttyn == '\0')
	ttyn = "/dev/tty??";

    /* This allows for tty names of the form /dev/pts/4 as well */
    if ((tty = strchr(ttyn, '/')) && (tty = strchr(tty+1, '/')))
	++tty;
    else
	tty = ttyn;

#ifndef LOG_ODELAY /* 4.2 syslog ... */                      
    openlog("login", 0);
#else
    openlog("login", LOG_ODELAY, LOG_AUTH);
#endif /* 4.2 syslog */

/******* begin askpw *******/
    /* overall:
       ask for username if we don't have it already
       look it up in local pw or shadow file (to get crypt string)
       ask for password
       try and get v5 tickets with it
       try and use the tickets against the local srvtab
       if the password matches, always let them in
       if the ticket decrypts, let them in.
    */

    k_init (ttyn);

    for (cnt = 0;; username = NULL) {
#ifdef KRB5_GET_TICKETS
	int kpass_ok, lpass_ok;
	char user_pwstring[MAXPWSIZE];
#endif /* KRB5_GET_TICKETS */

	if (username == NULL) {
	    fflag = 0;
	    getloginname();
	}

	lookup_user(username);	/* sets pwd */

	/* if user not super-user, check for disabled logins */
	if (pwd == NULL || pwd->pw_uid)
	    checknologin();

	/*
	 * Allows automatic login by root.
	 * If not invoked by root, disallow if the uid's differ.
	 */

	if (fflag && pwd) {
	    int uid = (int) getuid();
	    passwd_req = (uid && uid != pwd->pw_uid);
	}

	/*
	 * If no remote login authentication and a password exists
	 * for this user, prompt for one and verify it.
	 */
	if (!passwd_req)
	    break;

	if (!unix_needs_passwd())
	    break;

#ifdef KRB5_GET_TICKETS
	if (login_krb5_get_tickets) {
	    /* rename these to something more verbose */
	    kpass_ok = 0;
	    lpass_ok = 0;

	    setpriority(PRIO_PROCESS, 0, -4 + PRIO_OFFSET);
	    if (! k5_get_password(user_pwstring, sizeof (user_pwstring))) {
		goto bad_login;
	    }

	    /* now that we have the password, we've obscured things
	       sufficiently, and can avoid trying tickets */
	    if (!pwd)
		goto bad_login;

	    lpass_ok = unix_passwd_okay(user_pwstring);

	    if (pwd->pw_uid != 0) { /* Don't get tickets for root */
		try_krb5(&me, user_pwstring);

		krbflag = got_v5_tickets;
		memset (user_pwstring, 0, sizeof(user_pwstring));
		/* password wiped, so we can relax */
		setpriority(PRIO_PROCESS, 0, 0 + PRIO_OFFSET);
	    } else {
		memset(user_pwstring, 0, sizeof(user_pwstring));
		setpriority(PRIO_PROCESS, 0, 0 + PRIO_OFFSET);
	    }

	    /* Policy: If local password is good, user is good.
	       We really can't trust the Kerberos password,
	       because somebody on the net could spoof the
	       Kerberos server (not easy, but possible).
	       Some sites might want to use it anyways, in
	       which case they should change this line
	       to:
	       if (kpass_ok)
	    */

	    if (lpass_ok)
		break;

	    if (got_v5_tickets) {
		retval = krb5_verify_init_creds(kcontext, &my_creds, NULL,
						NULL, &xtra_creds,
						NULL);
		if (retval) {
		    com_err("login", retval, "while verifying initial ticket");
#ifndef SYSLOG42
		    syslog(LOG_NOTICE|LOG_AUTH,
			   "can't verify v5 ticket: %s\n",
			   error_message(retval));
#endif
		} else {
		    break;	/* we're ok */
		}
	    }

	bad_login:
	    setpriority(PRIO_PROCESS, 0, 0 + PRIO_OFFSET);

	    if (krbflag)
		destroy_tickets(); /* clean up tickets if login fails */
	}
#endif /* KRB5_GET_TICKETS */

#ifdef OLD_PASSWD
	p = getpass ("Password:");
	/* conventional password only */
	if (unix_passwd_okay (p))
	    break;
#endif /* OLD_PASSWD */
	printf("Login incorrect\n");
	if (++cnt >= 5) {
	    log_repeated_failures (tty, hostname);
	    /* irix has no tichpcl */
#ifdef TIOCHPCL
	    (void)ioctl(0, TIOCHPCL, (char *)0);
#endif
	    sleepexit(1);
	}
    } /* end of password retry loop */

    /* committed to login -- turn off timeout */
    (void) alarm((u_int) 0);

    /*
     * If valid so far and root is logging in, see if root logins on
     * this terminal are permitted.
     *
     * We allow authenticated remote root logins (except -r style)
     */

    if (pwd->pw_uid == 0 && !rootterm(tty) && (passwd_req || rflag)) {
	if (hostname) {
#ifdef UT_HOSTSIZE
	    syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s FROM %.*s",
		   tty, UT_HOSTSIZE, hostname);
#else
	    syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s FROM %s",
		   tty, hostname);
#endif
	} else {
	    syslog(LOG_ERR, "ROOT LOGIN REFUSED ON %s", tty);
	}
	printf("Login incorrect\n");
	sleepexit(1);
    }

#ifdef OQUOTA
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
#endif

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

	login_time = time(&utmp.ut_time);
	if ((retval = pty_update_utmp(PTY_USER_PROCESS, getpid(), username,
				      ttyn, hostname,
				      PTY_TTYSLOT_USABLE)) < 0)
	    com_err (argv[0], retval, "while updating utmp");
    }

    quietlog = access(HUSHLOGIN, F_OK) == 0;
    dolastlog(hostname, quietlog, tty);

    (void)chown(ttyn, pwd->pw_uid,
		(gr = getgrnam(TTYGRPNAME)) ? gr->gr_gid : pwd->pw_gid);

    (void)chmod(ttyn, 0620);

#ifdef KRB5_GET_TICKETS
    /* Maybe telnetd got tickets for us?  */
    if (!got_v5_tickets && have_v5_tickets (&me))
	forwarded_v5_tickets = 1;
#endif /* KRB5_GET_TICKETS */

#ifdef KRB5_GET_TICKETS
    if (login_krb5_get_tickets)
	dofork();
#endif

/* If the user's shell does not do job control we should put it in a
   different process group than than us, and set the tty process group
   to match, otherwise stray signals may be delivered to login.krb5 or
   telnetd or rlogind if they don't properly detach from their
   controlling tty, which is the case (under SunOS at least.) */

    {
	int pid = getpid(); 
	struct sigaction sa2, osa;

	/* this will set the PGID to the PID. */
#ifdef HAVE_SETPGID
	if (setpgid(pid,pid) < 0)
	    perror("login.krb5: setpgid");
#elif defined(SETPGRP_TWOARG)
	if (setpgrp(pid,pid) < 0)
	    perror("login.krb5: setpgrp");
#else
	if (setpgrp() < 0)
	    perror("login.krb5: setpgrp");
#endif

	/* This will cause SIGTTOU to be ignored for the duration
	   of the TIOCSPGRP.  If this is not done, and the parent's
	   process group is the foreground pgrp of the tty, then
	   this will suspend the child, which is bad. */

	sa2.sa_flags = 0;
	sa2.sa_handler = SIG_IGN;
	sigemptyset(&(sa2.sa_mask));

	if (sigaction(SIGTTOU, &sa2, &osa))
	    perror("login.krb5: sigaction(SIGTTOU, SIG_IGN)");

	/* This will set the foreground process group of the
	   controlling terminal to this process group (containing
	   only this process). */
#ifdef HAVE_TCSETPGRP
	if (tcsetpgrp(0, pid) < 0)
	    perror("login.krb5: tcsetpgrp");
#else
	if (ioctl(0, TIOCSPGRP, &pid) < 0)
	    perror("login.krb5: tiocspgrp");
#endif

	/* This will reset the SIGTTOU handler */

	if (sigaction(SIGTTOU, &osa, NULL))
	    perror("login.krb5: sigaction(SIGTTOU, [old handler])");
    }

    (void) setgid((gid_t) pwd->pw_gid);
    (void) initgroups(username, pwd->pw_gid);

    /*
     * The V5 ccache is created as root.  It needs to be owned by the
     * user, and chown (a) assumes they are stored in a file and (b)
     * allows a race condition in which a user can delete the file (if
     * the directory sticky bit is not set) and make it a symlink to
     * somewhere else; on some platforms, chown() on a symlink
     * actually changes the owner of the pointed-to file.  This is
     * Bad.
     *
     * So, we suck the V5 krbtgt into memory here, destroy the
     * ccache/ticket file, and recreate them later after the setuid.
     *
     * With the new v5 api, v5 tickets are kept in memory until written
     * out after the setuid.  However, forwarded tickets still
     * need to be read in and recreated later
     */
#ifdef KRB5_GET_TICKETS
    if (forwarded_v5_tickets) {
	krb5_creds mcreds;

	memset(&mcreds, 0, sizeof(mcreds));
	memset(&save_v5creds, 0, sizeof(save_v5creds));

	mcreds.client = me;
	retval =
	    krb5_build_principal_ext(kcontext, &mcreds.server,
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     tgtname.length, tgtname.data,
				     krb5_princ_realm(kcontext, me)->length,
				     krb5_princ_realm(kcontext, me)->data,
				     0);
	if (retval) {
	    syslog(LOG_ERR,
		   "%s while creating V5 krbtgt principal",
		   error_message(retval));
	    rewrite_ccache = 0;
	} else {
	    mcreds.ticket_flags = 0;

	    retval = krb5_cc_retrieve_cred(kcontext, ccache, 0,
					   &mcreds, &save_v5creds);
	    if (retval) {
		syslog(LOG_ERR,
		       "%s while retrieiving V5 initial ticket for copy",
		       error_message(retval));
		rewrite_ccache = 0;
	    }
	}

	krb5_free_principal(kcontext, mcreds.server);
    }
#endif /* KRB5_GET_TICKETS */

#ifdef KRB5_GET_TICKETS
    if (forwarded_v5_tickets)
	destroy_tickets();
#endif

#ifdef OQUOTA
    quota(Q_DOWARN, pwd->pw_uid, (dev_t)-1, 0);
#endif
#ifdef HAVE_SETLOGIN
    if (setlogin(pwd->pw_name) < 0)
	syslog(LOG_ERR, "setlogin() failure %d",errno);
#endif

#ifdef	HAVE_SETLUID
  	/*
  	 * If we're on a system which keeps track of login uids, then
 	 * set the login uid. If this fails this opens up a problem on DEC OSF
 	 * with C2 enabled.
	 */
 	if (setluid((uid_t) pwd->pw_uid) < 0) {
	    perror("setuid");
	    sleepexit(1);
	}
#endif	/* HAVE_SETLUID */
#ifdef _IBMR2
    if (setuidx(ID_LOGIN, pwd->pw_uid) < 0) {
	perror("setuidx");
	sleepexit(1);
    };
#endif

    /* This call MUST succeed */
    if (setuid((uid_t) pwd->pw_uid) < 0) {
	perror("setuid");
	sleepexit(1);
    }

    /*
     * We are the user now.  Re-create the destroyed ccache and
     * ticket file.
     */

#ifdef KRB5_GET_TICKETS
    if (got_v5_tickets) {
	/* set up credential cache -- obeying KRB5_ENV_CCNAME 
	   set earlier */
	/* (KRB5_ENV_CCNAME == "KRB5CCNAME" via osconf.h) */
	if ((retval = krb5_cc_default(kcontext, &ccache))) {
	    com_err(argv[0], retval, "while getting default ccache");
	} else if ((retval = krb5_cc_initialize(kcontext, ccache, me))) {
	    com_err(argv[0], retval, "when initializing cache");
	} else if ((retval = krb5_cc_store_cred(kcontext, ccache, 
						&my_creds))) {
	    com_err(argv[0], retval, "while storing credentials");
	} else if (xtra_creds &&
		   (retval = krb5_cc_copy_creds(kcontext, xtra_creds,
						ccache))) {
	    com_err(argv[0], retval, "while storing credentials");
	}

	if (xtra_creds)
	    krb5_cc_destroy(kcontext, xtra_creds);
    } else if (forwarded_v5_tickets && rewrite_ccache) {
	if ((retval = krb5_cc_initialize (kcontext, ccache, me))) {
	    syslog(LOG_ERR,
		   "%s while re-initializing V5 ccache as user",
		   error_message(retval));
	} else if ((retval = krb5_cc_store_cred(kcontext, ccache,
						&save_v5creds))) {
	    syslog(LOG_ERR,
		   "%s while re-storing V5 credentials as user",
		   error_message(retval));
	    
	}
	krb5_free_cred_contents(kcontext, &save_v5creds);
    }
#endif /* KRB5_GET_TICKETS */

    if (*pwd->pw_shell == '\0')
	pwd->pw_shell = BSHELL;

#if defined(NTTYDISC) && defined(TIOCSETD)
    /* turn on new line discipline for all shells */
    ioctlval = NTTYDISC;
    (void)ioctl(0, TIOCSETD, (char *)&ioctlval);
#endif

    ccname = getenv("KRB5CCNAME");  /* save cache */
    tz = getenv("TZ");	/* and time zone */

    /* destroy environment unless user has requested preservation */
    if (!pflag) {
	envinit = (char **) malloc(MAXENVIRON * sizeof(char *));
	if (envinit == 0) {
	    fprintf(stderr, "Can't malloc empty environment.\n");
	    sleepexit(1);
	}
	envinit[0] = NULL;
	environ = envinit;
    }

    setenv ("LOGNAME", pwd->pw_name, 1);
    setenv ("LOGIN", pwd->pw_name, 1);

    /* read the /etc/environment file on AIX */
#ifdef HAVE_ETC_ENVIRONMENT
    read_env_vars_from_file ("/etc/environment");
#endif

    /* Set login timezone for date information (sgi PDG) */
#ifdef HAVE_ETC_TIMEZONE
    read_env_vars_from_file ("/etc/TIMEZONE");
#else
    if (tz)
	setenv ("TZ", tz, 1);
#endif

    if (ccname)
	setenv("KRB5CCNAME", ccname, 1);

    setenv("HOME", pwd->pw_dir, 1);
    setenv("PATH", LPATH, 0);
    setenv("USER", pwd->pw_name, 1);
    setenv("SHELL", pwd->pw_shell, 1);

    if (term[0] == '\0') {
	(void) strncpy(term, stypeof(tty), sizeof(term));
	term[sizeof(term) - 1] = '\0';
    }
    if (term[0])
	(void)setenv("TERM", term, 0);

#ifdef KRB5_GET_TICKETS
    /* ccfile[0] is only set if we got tickets above */
    if (login_krb5_get_tickets && ccfile[0]) {
	(void) setenv(KRB5_ENV_CCNAME, ccfile, 1);
	krb5_cc_set_default_name(kcontext, ccfile);
    }
#endif /* KRB5_GET_TICKETS */

    if (tty[sizeof("tty")-1] == 'd')
	syslog(LOG_INFO, "DIALUP %s, %s", tty, pwd->pw_name);
    if (pwd->pw_uid == 0)
	    {
		if (hostname) {
#ifdef UT_HOSTSIZE
		    syslog(LOG_NOTICE, "ROOT LOGIN %s FROM %.*s",
			   tty, UT_HOSTSIZE, hostname);
#else
		    syslog(LOG_NOTICE, "ROOT LOGIN %s FROM %s",
			   tty, hostname);
#endif
		} else {
		    syslog(LOG_NOTICE, "ROOT LOGIN %s", tty);
		}
	    }

    afs_login();

    if (!quietlog) {
	motd();
	check_mail();
    }

#ifndef OQUOTA
    if (! access( QUOTAWARN, X_OK))
	(void) system(QUOTAWARN);
#endif

    handler_init (sa, SIG_DFL);
    handler_set (SIGALRM, sa);
    handler_set (SIGQUIT, sa);
    handler_set (SIGINT, sa);
    handler_init (sa, SIG_IGN);
    handler_set (SIGTSTP, sa);

    tbuf[0] = '-';
    p = strrchr(pwd->pw_shell, '/');
    (void) strncpy(tbuf+1, p?(p+1):pwd->pw_shell, sizeof(tbuf) - 1);
    tbuf[sizeof(tbuf) - 1] = '\0';

    execlp(pwd->pw_shell, tbuf, (char *)NULL);
    fprintf(stderr, "login: no shell: ");
    perror(pwd->pw_shell);
    exit(0);
}

char *speeds[] = {
	"0", "50", "75", "110", "134", "150", "200", "300", "600",
	"1200", "1800", "2400", "4800", "9600", "19200", "38400",
};
#define	NSPEEDS	(sizeof(speeds) / sizeof(speeds[0]))

#ifdef POSIX_TERMIOS
/* this must be in sync with the list above */
speed_t b_speeds[] = {
	B0, B50, B75, B110, B134, B150, B200, B300, B600,
	B1200, B1800, B2400, B4800, B9600, B19200, B38400,
};
#endif

void
term_init (do_rlogin)
int do_rlogin;
{
    int line_speed = -1;

    if (do_rlogin) {
	register char *cp = strchr(term, '/'), **cpp;
	char *speed;

	if (cp) {
	    *cp++ = '\0';
	    speed = cp;
	    cp = strchr(speed, '/');
	    if (cp)
		*cp++ = '\0';
	    for (cpp = speeds; cpp < &speeds[NSPEEDS]; cpp++)
		if (strcmp(*cpp, speed) == 0) {
		    line_speed = cpp-speeds;
		    break;
		}
	}
    }
#ifdef POSIX_TERMIOS
    {
	struct termios tc;

	(void)tcgetattr(0, &tc);
	if (line_speed != -1) {
	    cfsetispeed(&tc, b_speeds[line_speed]);
	    cfsetospeed(&tc, b_speeds[line_speed]);
	}
	tc.c_cc[VMIN] = 1;
	tc.c_cc[VTIME] = 0;
#ifndef NO_INIT_CC
	tc.c_cc[VERASE] = CERASE;
	tc.c_cc[VKILL] = CKILL;
	tc.c_cc[VEOF] = CEOF;
	tc.c_cc[VINTR] = CINTR;
	tc.c_cc[VQUIT] = CQUIT;
	tc.c_cc[VSTART] = CSTART;
	tc.c_cc[VSTOP] = CSTOP;
#ifndef CNUL
#define CNUL CEOL
#endif
	tc.c_cc[VEOL] = CNUL;
	/* The following are common extensions to POSIX */
#ifdef VEOL2
	tc.c_cc[VEOL2] = CNUL;
#endif
#ifdef VSUSP
#if !defined(CSUSP) && defined(CSWTCH)
#define CSUSP CSWTCH
#endif
	tc.c_cc[VSUSP] = CSUSP;
#endif
#ifdef VDSUSP
	tc.c_cc[VDSUSP] = CDSUSP;
#endif
#ifdef VLNEXT
	tc.c_cc[VLNEXT] = CLNEXT;
#endif
#ifdef VREPRINT
	tc.c_cc[VREPRINT] = CRPRNT;
#endif
#ifdef VDISCRD
	tc.c_cc[VDISCRD] = CFLUSH;
#endif
#ifdef VDISCARD
#ifndef CDISCARD
#define CDISCARD CFLUSH
#endif
	tc.c_cc[VDISCARD] = CDISCARD;
#endif
#ifdef VWERSE
	tc.c_cc[VWERSE] = CWERASE;
#endif
#ifdef VWERASE
	tc.c_cc[VWERASE] = CWERASE;
#endif
#if defined (VSTATUS) && defined (CSTATUS)
	tc.c_cc[VSTATUS] = CSTATUS;
#endif /* VSTATUS && CSTATUS */
#endif /* NO_INIT_CC */
	/* set all standard echo, edit, and job control options */
	/* but leave any extensions */
	tc.c_lflag |= ECHO|ECHOE|ECHOK|ICANON|ISIG|IEXTEN;
	tc.c_lflag &= ~(NOFLSH|TOSTOP);
#ifdef ECHOCTL
	/* Not POSIX, but if we have it, we probably want it */
	tc.c_lflag |= ECHOCTL;
#endif
#ifdef ECHOKE
	/* Not POSIX, but if we have it, we probably want it */
	tc.c_lflag |= ECHOKE;
#endif
	tc.c_iflag |= ICRNL|BRKINT;
	tc.c_oflag |= ONLCR|OPOST|TAB3;
	tcsetattr(0, TCSANOW, &tc);
    }

#else /* not POSIX_TERMIOS */

    {
	struct sgttyb sgttyb;
	static struct tchars tc = {
	    CINTR, CQUIT, CSTART, CSTOP, CEOT, CBRK
	};
	static struct ltchars ltc = {
	    CSUSP, CDSUSP, CRPRNT, CFLUSH, CWERASE, CLNEXT
	};

	(void) ioctl(0, TIOCGETP, (char *)&sgttyb);
	if (line_speed != -1)
	    sgttyb.sg_ispeed = sgttyb.sg_ospeed = line_speed;
	sgttyb.sg_flags = ECHO|CRMOD|ANYP|XTABS;
	sgttyb.sg_erase = CERASE;
	sgttyb.sg_kill = CKILL;
	(void)ioctl(0, TIOCSLTC, (char *)&ltc);
	(void)ioctl(0, TIOCSETC, (char *)&tc);
	(void)ioctl(0, TIOCSETP, (char *)&sgttyb);
#if defined(TIOCSETD)
	{
	    int ioctlval;
	    ioctlval = 0;
	    (void)ioctl(0, TIOCSETD, (char *)&ioctlval);
	}
#endif
    }
#endif
}

void getloginname()
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
	if (p > nbuf) {
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
}

sigtype
timedout(signumber)
    int signumber;
{
    fprintf(stderr, "Login timed out after %d seconds\n", timeout);
    exit(0);
}

#ifndef HAVE_TTYENT_H
int root_tty_security = 1;
#endif

int rootterm(tty)
	char *tty;
{
#ifndef HAVE_TTYENT_H
    return(root_tty_security);
#else
    struct ttyent *t;

    return((t = getttynam(tty)) && t->ty_status&TTY_SECURE);
#endif /* HAVE_TTYENT_H */
}

#ifndef NO_MOTD
sigjmp_buf motdinterrupt;

static sigtype
sigint(signum)
    int signum;
{
    siglongjmp(motdinterrupt, 1);
}

void motd()
{
    register int fd, nchars;
    char tbuf[8192];
    handler sa, osa;

    if ((fd = open(MOTDFILE, O_RDONLY, 0)) < 0)
	return;
    handler_init (sa, sigint);
    handler_swap (SIGINT, sa, osa);
    if (sigsetjmp(motdinterrupt, 1) == 0)
	while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
	    (void)write(fileno(stdout), tbuf, nchars);
    handler_set (SIGINT, osa);
    (void)close(fd);
}
#else
void motd()
{
}
#endif

#ifndef NO_MAILCHECK
void check_mail()
{
    char tbuf[MAXPATHLEN+2];
    struct stat st;
    (void)snprintf(tbuf, sizeof(tbuf), "%s/%s", MAILDIR, pwd->pw_name);
    if (stat(tbuf, &st) == 0 && st.st_size != 0)
	printf("You have %smail.\n",
	       (st.st_mtime > st.st_atime) ? "new " : "");
}
#else
void check_mail()
{
}
#endif

void checknologin()
{
    register int fd, nchars;
    char tbuf[8192];

    if ((fd = open(NOLOGIN, O_RDONLY, 0)) >= 0) {
	while ((nchars = read(fd, tbuf, sizeof(tbuf))) > 0)
	    (void)write(fileno(stdout), tbuf, (unsigned) nchars);
	sleepexit(0);
    }
}

void dolastlog(hostname, quiet, tty)
     char *hostname;
     int quiet;
     char *tty;
{
#if defined(HAVE_LASTLOG_H) || (defined(BSD) && (BSD >= 199103))
    struct lastlog ll;
    time_t lltime;
    int fd;

    if ((fd = open(LASTLOG, O_RDWR, 0)) >= 0) {
	(void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), SEEK_SET);
	if (!quiet) {
	    if ((read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll)) &&
		(ll.ll_time != 0)) {

		/* .ll_time may not be a time_t.  */
		lltime = ll.ll_time;
		printf("Last login: %.*s ", 24-5, (char *)ctime(&lltime));

		if (*ll.ll_host != '\0')
		    printf("from %.*s\n", (int) sizeof(ll.ll_host), 
			   ll.ll_host);
		else
		    printf("on %.*s\n", (int) sizeof(ll.ll_line), ll.ll_line);
	    }
	    (void)lseek(fd, (off_t)pwd->pw_uid * sizeof(ll), SEEK_SET);
	}
	(void) time(&lltime);
	ll.ll_time = lltime;

	(void) strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
	ll.ll_line[sizeof(ll.ll_line) - 1] = '\0';

	if (hostname) {
	    (void) strncpy(ll.ll_host, hostname, sizeof(ll.ll_host));
	    ll.ll_host[sizeof(ll.ll_host) - 1] = '\0';
	} else {
	    (void) memset(ll.ll_host, 0, sizeof(ll.ll_host));
	}

	(void)write(fd, (char *)&ll, sizeof(ll));
	(void)close(fd);
    }
#endif
}

#undef	UNKNOWN
#ifdef __hpux
#define UNKNOWN 0
#else
#define	UNKNOWN	"su"
#endif

char *
stypeof(ttyid)
     char *ttyid;
{
    char *cp = getenv("term");

#ifndef HAVE_TTYENT_H
    if (cp)
	return cp;
    else
	return(UNKNOWN);
#else
    struct ttyent *t;
    if (cp)
	return cp;
    else
	return(ttyid && (t = getttynam(ttyid)) ? t->ty_type : UNKNOWN);
#endif
}

int doremotelogin(host)
     char *host;
{
    static char lusername[UT_NAMESIZE+1];
    char rusername[UT_NAMESIZE+1];

    lgetstr(rusername, sizeof(rusername), "Remote user");
    lgetstr(lusername, sizeof(lusername), "Local user");
    lgetstr(term, sizeof(term), "Terminal type");
    username = lusername;
    pwd = getpwnam(username);
    if (pwd == NULL)
	return(-1);
    return(ruserok(host, (pwd->pw_uid == 0), rusername, username));
}

void lgetstr(buf, cnt, err)
     char *buf, *err;
     int cnt;
{
    int ocnt = cnt;
    char *obuf = buf;
    char ch;

    do {
	if (read(0, &ch, sizeof(ch)) != sizeof(ch))
	    exit(1);
	if (--cnt < 0) {
	    fprintf(stderr,"%s '%.*s' too long, %d characters maximum.\r\n",
		    err, ocnt, obuf, ocnt-1);
	    sleepexit(1);
	}
	*buf++ = ch;
    } while (ch);
}

void sleepexit(eval)
     int eval;
{
    sleep((u_int)5);
    exit(eval);
}

#ifdef KRB5_GET_TICKETS
static int hungup = 0;

static sigtype
sighup() {
    hungup = 1;
}

/* call already conditionalized on login_krb5_get_tickets */
/*
 * This routine handles cleanup stuff, and the like.
 * It exits only in the child process.
 */
#include <sys/wait.h>
void
dofork()
{
    int child,pid;
    handler sa;
    int syncpipe[2];
    char c;
    int n;
    
#ifdef _IBMR2
    update_ref_count(1);
#endif
    if (pipe(syncpipe) < 0) {
	perror("login: dofork: setting up syncpipe");
	exit(1);
    }
    if (!(child=fork())) {
	close(syncpipe[1]);
	while ((n = read(syncpipe[0], &c, 1)) < 0) {
	    if (errno != EINTR) {
		perror("login: dofork: waiting for sync from parent");
		exit(1);
	    }
	}
	if (n == 0) {
	    fprintf(stderr, "login: dofork: unexpected EOF waiting for sync\n");
	    exit(1);
	}
	close(syncpipe[0]);
	return; /* Child process returns */
    }

    /* The parent continues here */

    /* On receipt of SIGHUP, pass that along to child's process group. */
    handler_init (sa, sighup);
    handler_set (SIGHUP, sa);
    /* Tell child we're ready. */
    close(syncpipe[0]);
    write(syncpipe[1], "", 1);
    close(syncpipe[1]);

    /* Setup stuff?  This would be things we could do in parallel with login */
    (void) chdir("/");	/* Let's not keep the fs busy... */
    
    /* If we're the parent, watch the child until it dies */

    while (1) {
#ifdef HAVE_WAITPID
        pid = waitpid(child, 0, 0);
#elif defined(WAIT_USES_INT)
        pid = wait((int *)0);
#else
        pid = wait((union wait *)0);
#endif

	if (hungup) {
#ifdef HAVE_KILLPG
	    killpg(child, SIGHUP);
#else
	    kill(-child, SIGHUP);
#endif
	}

	if (pid == child)
	    break;
    }
    
    /* Cleanup stuff */
    /* Run destroy_tickets to destroy tickets */
    (void) destroy_tickets();		/* If this fails, we lose quietly */
    afs_cleanup ();
#ifdef _IBMR2
    update_ref_count(-1);
#endif

    /* Leave */
    exit(0);
}
#endif /* KRB5_GET_TICKETS */


#ifndef HAVE_STRSAVE
/* Strsave was a routine in the version 4 krb library: we put it here
   for compatablilty with version 5 krb library, since kcmd.o is linked
   into all programs. */

char *strsave(sp)
     char *sp;
{
    register char *ret;
    
    if ((ret = strdup(sp)) == NULL) {
	fprintf(stderr, "no memory for saving args\n");
	exit(1);
    }
    return(ret);
}
#endif

#ifdef _IBMR2
update_ref_count(int adj)
{
    struct passwd *save_pwd;
    static char *empty = "\0";
    char *grp;
    int i;

    /* save pwd before calling getuserattr() */
    save_pwd = (struct passwd *)malloc(sizeof(struct passwd));
    save_pwd->pw_name = strdup(pwd->pw_name);
    save_pwd->pw_passwd = strdup(pwd->pw_passwd);
    save_pwd->pw_uid = pwd->pw_uid;
    save_pwd->pw_gid = pwd->pw_gid;
    save_pwd->pw_gecos = strdup(pwd->pw_gecos);
    save_pwd->pw_dir = strdup(pwd->pw_dir);
    save_pwd->pw_shell = strdup(pwd->pw_shell);
    pwd = save_pwd;

    /* Update reference count on all user's temporary groups */
    setuserdb(S_READ|S_WRITE);
    if (getuserattr(username, S_GROUPS, (void *)&grp, SEC_LIST) == 0) {
	while (*grp) {
	    if (getgroupattr(grp, "athena_temp", (void *)&i, SEC_INT) == 0) {
		i += adj;
		if (i > 0) {
		    putgroupattr(grp, "athena_temp", (void *)i, SEC_INT);
		    putgroupattr(grp, (char *)0, (void *)0, SEC_COMMIT);
		} else {
		    putgroupattr(grp, S_USERS, (void *)empty, SEC_LIST);
#ifdef HAVE_RMUFILE /* pre-4.3.0 AIX */
		    putgroupattr(grp, (char *)0, (void *)0, SEC_COMMIT);
		    rmufile(grp, 0, GROUP_TABLE);
#else
		    putgroupattr(grp, (char *)0, (void *)0, SEC_DELETE);
		    putgroupattr(grp, (char *)0, (void *)0, SEC_COMMIT);
#endif
		}
	    }
	    while (*grp) grp++;
	    grp++;
	}
    }
    enduserdb();
}
#endif
