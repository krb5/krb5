/*
 *	appl/bsd/krshd.c
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

/* based on @(#)rshd.c	5.12 (Berkeley) 9/12/88 */

     /*
      * remote shell server:
      *	remuser\0
      *	locuser\0
      *	command\0
      *	data
      */
     
/*
 * This is the rshell daemon. The very basic protocol for checking 
 * authentication and authorization is:
 * 1) Check authentication.
 * 2) Check authorization via the access-control files: 
 *    ~/.k5login (using krb5_kuserok) and/or
 * Execute command if configured authoriztion checks pass, else deny 
 * permission.
 *
 * The configuration is done either by command-line arguments passed by inetd, 
 * or by the name of the daemon. If command-line arguments are present, they 
 * take priority. The options are:
 * -k means trust krb4 or krb5
 * -5 means trust krb5
 * -4 means trust krb4 (using .klogin)
 * 
 */
     
/* DEFINES:
 *   KERBEROS - Define this if application is to be kerberised.
 *   KRB5_KRB4_COMPAT - Define this if v4 rlogin clients are also to be served.
 *   ALWAYS_V5_KUSEROK - Define this if you want .k5login to be
 *              checked even for v4 clients (instead of .klogin).
 *   LOG_ALL_LOGINS - Define this if you want to log all logins.
 *   LOG_OTHER_USERS - Define this if you want to log all principals that do
 *              not map onto the local user.
 *   LOG_REMOTE_REALM - Define this if you want to log all principals from 
 *              remote realms.
 *   LOG_CMD - Define this if you want to log not only the user but also the
 *             command executed. This only decides the type of information
 *             logged. Whether or not to log is still decided by the above 
 *             three DEFINES.
 *       Note:  Root account access is always logged.
 */
     
#define SERVE_NON_KRB     
#define LOG_REMOTE_REALM
#define LOG_CMD
   
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef __SCO__
#include <sys/unistd.h>
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#if !defined(KERBEROS) || !defined(KRB5_KRB4_COMPAT)
/* Ultrix doesn't protect it vs multiple inclusion, and krb.h includes it */
#include <sys/socket.h>
#endif
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <fcntl.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
     
#include <netinet/in.h>
#include <arpa/inet.h>
     
#include <stdio.h>
#include <grp.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <string.h>
#include <libpty.h>
#include <sys/wait.h>
     
#ifdef HAVE_SYS_LABEL_H
/* only SunOS 4? */
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
     
#include <signal.h>
#if !defined(KERBEROS) || !defined(KRB5_KRB4_COMPAT)
/* Ultrix doesn't protect it vs multiple inclusion, and krb.h includes it */
#include <netdb.h>
#endif

#ifdef CRAY
#ifndef NO_UDB
#include <udb.h>
#endif  /* !NO_UDB */
#include <sys/category.h>
#include <netinet/ip.h>
#include <sys/tfm.h>
#include <sys/nal.h>
#include <sys/secparm.h>
#include <sys/usrv.h>
#include <sys/utsname.h>
#include <sys/sysv.h>
#include <sys/slrec.h>
#include <sys/unistd.h>
#include <path.h>
#endif /* CRAY */
     
#include <syslog.h>

#ifdef POSIX_TERMIOS
#include <termios.h>
#endif
     
#ifdef HAVE_SYS_FILIO_H
/* get FIONBIO from sys/filio.h, so what if it is a compatibility feature */
#include <sys/filio.h>
#endif

#ifdef KERBEROS
#include <krb5.h>
#include <com_err.h>
#include "loginpaths.h"
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
Key_schedule v4_schedule;
#endif
#include <k5-util.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#if defined(_PATH_NOLOGIN)
#define NOLOGIN		_PATH_NOLOGIN
#else
#define NOLOGIN		"/etc/nologin"
#endif

#include "defines.h"

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#ifndef MAXDNAME
#define MAXDNAME 256 /*per the rfc*/
#endif

#define ARGSTR	"ek54ciD:S:M:AP:?L:w:"




#define MAXRETRIES 4

krb5_context bsd_context;
char *srvtab = NULL;
krb5_keytab keytab = NULL;
krb5_ccache ccache = NULL;

void fatal(int, const char *);

int require_encrypt = 0;
int do_encrypt = 0;
int anyport = 0;
char *kprogdir = KPROGDIR;
int netf;
int maxhostlen = 0;
int stripdomain = 1;
int always_ip = 0;

static krb5_error_code recvauth(int netfd, struct sockaddr *peersin,
				int *valid_checksum);

#else /* !KERBEROS */

#define ARGSTR	"RD:?"
     
#endif /* KERBEROS */

     
#ifndef HAVE_KILLPG
#define killpg(pid, sig) kill(-(pid), (sig))
#endif

/* There are two authentication related masks:
   * auth_ok and auth_sent.
* The auth_ok mask is the oring of authentication systems any one
* of which can be used.  
* The auth_sent mask is the oring of one or more authentication/authorization
* systems that succeeded.  If the anding
* of these two masks is true, then authorization is successful.
*/
#define AUTH_KRB4 (0x1)
#define AUTH_KRB5 (0x2)
int auth_ok = 0, auth_sent = 0;
int checksum_required = 0, checksum_ignored = 0;
char *progname;

#define MAX_PROG_NAME 10

/* Leave room for 4 environment variables to be passed */
#define MAXENV 4
#define SAVEENVPAD 0,0,0,0 /* padding for envinit slots */
char *save_env[MAXENV];
int num_env = 0;

#ifdef CRAY
int     secflag;
extern
#endif /* CRAY */

void 	error (char *fmt, ...)
#if !defined (__cplusplus) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7))
       __attribute__ ((__format__ (__printf__, 1, 2)))
#endif
     ;

void usage(void), getstr(int, char *, int, char *), 
    doit(int, struct sockaddr *);

#ifndef HAVE_INITGROUPS
int initgroups(char* name, gid_t basegid) {
  gid_t others[NGROUPS_MAX+1];
  int ngrps;

  others[0] = basegid;
  ngrps = getgroups(NGROUPS_MAX, others+1);
  return setgroups(ngrps+1, others);
}
#endif


int main(argc, argv)
     int argc;
     char **argv;
{
#if defined(BSD) && BSD+0 >= 43
    struct linger linger;
#endif
    int on = 1;
    socklen_t fromlen;
    struct sockaddr_storage from;
    extern int opterr, optind;
    extern char *optarg;
    int ch;
    int fd;
    int debug_port = 0;
#ifdef KERBEROS
    krb5_error_code status;
#endif

#ifdef CRAY
    secflag = sysconf(_SC_CRAY_SECURE_SYS);
#endif
    
    progname = strrchr (*argv, '/');
    progname = progname ? progname + 1 : *argv;
    
#ifndef LOG_ODELAY /* 4.2 syslog */
    openlog(progname, LOG_PID);
#else
#ifndef LOG_AUTH
#define LOG_AUTH 0
#endif
    openlog(progname, LOG_PID | LOG_ODELAY, LOG_AUTH);
#endif /* 4.2 syslog */
    
#ifdef KERBEROS
    status = krb5_init_context(&bsd_context);
    if (status) {
	    syslog(LOG_ERR, "Error initializing krb5: %s",
		   error_message(status));
	    exit(1);
    }
#endif
    
    /* Analyze parameters. */
    opterr = 0;
    while ((ch = getopt(argc, argv, ARGSTR)) != -1)
      switch (ch) {
#ifdef KERBEROS
	case 'k':
#ifdef KRB5_KRB4_COMPAT
	auth_ok |= (AUTH_KRB5|AUTH_KRB4);
#else
	auth_ok |= AUTH_KRB5;
#endif /* KRB5_KRB4_COMPAT*/
	break;
	
      case '5':
	  auth_ok |= AUTH_KRB5;
	break;
      case 'c':
	checksum_required = 1;
	break;
      case 'i':
	checksum_ignored = 1;
	break;
	
#ifdef KRB5_KRB4_COMPAT
      case '4':
	auth_ok |= AUTH_KRB4;
	break;
#endif
	  
        case 'e':
	require_encrypt = 1;
	  break;

	case 'S':
	  if ((status = krb5_kt_resolve(bsd_context, optarg, &keytab))) {
	      com_err(progname, status, "while resolving srvtab file %s",
		      optarg);
	      exit(2);
	  }
	  break;

	case 'M':
	  krb5_set_default_realm(bsd_context, optarg);
	  break;

	case 'A':
	  anyport = 1;
	  break;

	case 'P':
	  kprogdir = optarg;
	  break;

        case 'L':
	  if (num_env < MAXENV) {
		  save_env[num_env] = strdup(optarg);
		  if(!save_env[num_env++]) {
			  com_err(progname, ENOMEM, "in saving environment");
			  exit(2);
		  }		  
	  } else  {
		  fprintf(stderr, "%s: Only %d -L arguments allowed\n",
			  progname, MAXENV);
		  exit(2);
	  }
	  break;
#endif
	case 'D':
	  debug_port = atoi(optarg);
	  break;
      case 'w':
	  if (!strcmp(optarg, "ip"))
	      always_ip = 1;
	  else {
	      char *cp;
	      cp = strchr(optarg, ',');
	      if (cp == NULL)
		  maxhostlen = atoi(optarg);
	      else if (*(++cp)) {
		  if (!strcmp(cp, "striplocal"))
		      stripdomain = 1;
		  else if (!strcmp(cp, "nostriplocal"))
		      stripdomain = 0;
		  else {
		      usage();
		      exit(1);
		  }
		  *(--cp) = '\0';
		  maxhostlen = atoi(optarg);
	      }
	  }
	  break;
      case '?':
      default:
	  usage();
	  exit(1);
	  break;
      }

    if (optind == 0) {
	usage();
	exit(1);
    }
    
    argc -= optind;
    argv += optind;
    
    fromlen = sizeof (from);

    if (debug_port)
	fd = accept_a_connection(debug_port, (struct sockaddr *)&from,
				 &fromlen);
    else {
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
	    fprintf(stderr, "%s: ", progname);
	    perror("getpeername");
	    _exit(1);
	}

	fd = 0;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
		   sizeof (on)) < 0)
	syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
#if defined(BSD) && BSD+0 >= 43
    linger.l_onoff = 1;
    linger.l_linger = 60;			/* XXX */
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&linger,
		   sizeof (linger)) < 0)
	syslog(LOG_WARNING , "setsockopt (SO_LINGER): %m");
#endif

    if (checksum_required&&checksum_ignored) {
	syslog(LOG_CRIT, "Checksums are required and ignored; these options are mutually exclusive--check the documentation.");
	fatal(fd, "Configuration error: mutually exclusive options specified");
    }

    doit(dup(fd), (struct sockaddr *) &from);
    return 0;
}

#ifdef CRAY
char    username[32] = "LOGNAME=";
#include <tmpdir.h>
char tmpdir[64] = "TMPDIR=";
#else
char	username[20] = "USER=";
#endif

char	homedir[64] = "HOME=";
char	shell[64] = "SHELL=";
char    term[64] = "TERM=network";
char	path_rest[] = RPATH;

char	remote_addr[64+NI_MAXHOST]; /* = "KRB5REMOTEADDR=" */
char	remote_port[64+NI_MAXSERV]; /* = "KRB5REMOTEPORT=" */
char	local_addr[64+NI_MAXHOST]; /* = "KRB5LOCALADDR=" */
char	local_port[64+NI_MAXSERV]; /* = "KRB5LOCALPORT=" */
#define ADDRPAD 0,0,0,0
#define KRBPAD 0		/* KRB5CCNAME, optional */

/* The following include extra space for TZ and MAXENV pointers... */
#define COMMONVARS homedir, shell, 0/*path*/, username, term
#ifdef CRAY
char    *envinit[] = 
{COMMONVARS, "TZ=GMT0", tmpdir, SAVEENVPAD, KRBPAD, ADDRPAD, 0};
#define TMPDIRENV 6
char    *getenv();
#else /* CRAY */
#ifdef KERBEROS
char    *envinit[] = 
{COMMONVARS, 0/*tz*/, SAVEENVPAD, KRBPAD, ADDRPAD, 0};
#else /* KERBEROS */
char	*envinit[] = 
{COMMONVARS, 0/*tz*/, SAVEENVPAD, ADDRPAD, 0};
#endif /* KERBEROS */
#endif /* CRAY */

#define TZENV 5
#define PATHENV 2

extern char	**environ;
char ttyn[12];		/* Line string for wtmp entries */

#ifdef CRAY
#define SIZEOF_INADDR  SIZEOF_in_addr
int maxlogs;
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

#ifndef NCARGS
/* linux doesn't seem to have it... */
#define NCARGS 1024
#endif

#define NMAX   16 

int pid;
char locuser[NMAX+1];
char remuser[NMAX +1];
char cmdbuf[NCARGS+1];
char *kremuser;
krb5_principal client;
krb5_authenticator *kdata;

#ifdef KRB5_KRB4_COMPAT
AUTH_DAT	*v4_kdata;
KTEXT		v4_ticket;
#endif

int auth_sys = 0;	/* Which version of Kerberos used to authenticate */

#define KRB5_RECVAUTH_V4	4
#define KRB5_RECVAUTH_V5	5

static void
ignore_signals()
{
#ifdef POSIX_SIGNALS
    struct sigaction sa;

    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGINT, &sa, (struct sigaction *)0);
    (void)sigaction(SIGQUIT, &sa, (struct sigaction *)0);
    (void)sigaction(SIGTERM, &sa, (struct sigaction *)0);
    (void)sigaction(SIGPIPE, &sa, (struct sigaction *)0);
    (void)sigaction(SIGHUP, &sa, (struct sigaction *)0);

    (void)kill(-pid, SIGTERM);
#else
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    killpg(pid, SIGTERM);
#endif
}

static krb5_sigtype
cleanup(signumber)
     int signumber;
{
    ignore_signals();
    wait(0);
    
    pty_logwtmp(ttyn,"","");
    syslog(LOG_INFO ,"Daemon terminated via signal %d.", signumber);
    if (ccache)
	krb5_cc_destroy(bsd_context, ccache);
    exit(0);
}


void doit(f, fromp)
     int f;
     struct sockaddr *fromp;
{
    char *cp;
#ifdef KERBEROS
    krb5_error_code status;
#endif
    int valid_checksum;
    int cnt;
    char *crypt();
    struct passwd *pwd;
    char *path;
#ifdef CRAY
#ifndef NO_UDB
    struct udb    *ue;
    struct udb ue_static;
    extern struct udb *getudbnam();
#endif
    extern struct passwd *getpwnam(), *getpwuid();
    static int      jid;
    int error();
    int paddr;
    struct  nal nal;
    int     nal_error;
    struct usrv usrv;
    struct  sysv sysv;
    char    *makejtmp(), *jtmpnam = 0;
    int packet_level;               /* Packet classification level */
    long packet_compart;            /* Packet compartments */
#endif  /* CRAY */
    
    int s = -1;
    char hostname[NI_MAXHOST];
    char *sane_host;
    char hostaddra[NI_MAXHOST];
    int aierr;
    short port;
    int pv[2], pw[2], px[2], cc;
    fd_set ready, readfrom;
    char buf[RCMD_BUFSIZ], sig;
    struct sockaddr_storage localaddr;
#ifdef POSIX_SIGNALS
    struct sigaction sa;
#endif

#ifdef IP_TOS
/* solaris has IP_TOS, but only IPTOS_* values */
#ifdef HAVE_GETTOSBYNAME
    struct tosent *tp;


    if ((tp = gettosbyname("interactive", "tcp")) &&
	(setsockopt(f, IPPROTO_IP, IP_TOS, &tp->t_tos, sizeof(int)) < 0))
#ifdef  TOS_WARN
      syslog(LOG_NOTICE, "setsockopt (IP_TOS): %m");
#else
    ;       /* silently ignore TOS errors in 6E */
#endif
#endif
#endif /* IP_TOS */
    
    { 
	socklen_t sin_len = sizeof (localaddr);
	if (getsockname(f, (struct sockaddr*)&localaddr, &sin_len) < 0) {
	    perror("getsockname");
	    exit(1);
	}
    }

#ifdef POSIX_SIGNALS
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGINT, &sa, (struct sigaction *)0);
    (void)sigaction(SIGQUIT, &sa, (struct sigaction *)0);
    (void)sigaction(SIGTERM, &sa, (struct sigaction *)0);
#else
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
#endif
#ifdef DEBUG
    { int t = open("/dev/tty", 2);
      if (t >= 0) {
	  ioctl(t, TIOCNOTTY, (char *)0);
	  (void) close(t);
      }
  }
#endif
    if (fromp->sa_family != AF_INET
#if defined(KRB5_USE_INET6) && defined(KERBEROS)
	&& fromp->sa_family != AF_INET6
#endif
	) {
	syslog(LOG_ERR , "malformed from address\n");
	exit(1);
    }
#ifdef KERBEROS
    netf = f;
#else
    {
	struct sockaddr_in *frompin = sa2sin(fromp);
	frompin->sin_port = ntohs((u_short)frompin->sin_port);
	if (frompin->sin_port >= IPPORT_RESERVED ||
	    frompin->sin_port < IPPORT_RESERVED/2) {
	    syslog(LOG_ERR , "connection from bad port\n");
	    exit(1);
	}
    }
#endif /* KERBEROS */
    
#ifdef CRAY
    
    /* If this is a secure system then get the packet classification
       of f.  ( Note IP_SECURITY is checked in get_packet_classification:
       if it's not set then the user's (root) default
       classification level and compartments are returned. )
       Then set this process to that level/compart so that the stderr
       connection will be labeled appropriately.
       */
    if (secflag) {
	if (get_packet_classification(f,getuid(),
				      &packet_level,&packet_compart) < 0) {
	    syslog(LOG_ERR, "cannot get ip packet level\n");
	    exit(1);
	}
	if(secflag == TFM_UDB_5) {
	    if(setucmp(packet_compart, C_PROC) != 0) {
		error("Unable to setucmp.\n");
		exit(1);
	    }
	} else if(secflag == TFM_UDB_6) {
	    if(setulvl(packet_level,C_PROC) != 0) {
		error("Unable to setulvl.\n");
		exit(1);
	    }
	    if(setucmp(packet_compart, C_PROC) != 0) {
		error("Unable to setucmp.\n");
		exit(1);
	    }
	}
	
    }
#endif /* CRAY */
    
    (void) alarm(60);
    port = 0;
    for (;;) {
	char c;
	if ((cc = read(f, &c, 1)) != 1) {
	    if (cc < 0)
	      syslog(LOG_NOTICE , "read: %m");
	    shutdown(f, 1+1);
	    exit(1);
	}
	if (c == 0)
	  break;
	port = port * 10 + c - '0';
    }
    (void) alarm(0);
    if (port != 0) {
	if (anyport) {
	    int addrfamily = fromp->sa_family;
	    s = getport(0, &addrfamily);
	} else {
	    int lport = IPPORT_RESERVED - 1;
#ifdef HAVE_RRESVPORT_AF
	    s = rresvport_af(&lport, fromp->sa_family);
#else
	    s = rresvport(&lport);
#endif
	}
	if (s < 0) {
	    syslog(LOG_ERR ,
		   "can't get stderr port: %m");
	    exit(1);
	}
#ifndef KERBEROS
	if (port >= IPPORT_RESERVED) {
	    syslog(LOG_ERR , "2nd port not reserved\n");
	    exit(1);
	}
#endif /* KERBEROS */
	switch (fromp->sa_family) {
	case AF_INET:
	    sa2sin(fromp)->sin_port = htons((u_short)port);
	    break;
#ifdef KRB5_USE_INET6
	case AF_INET6:
	    sa2sin6(fromp)->sin6_port = htons((u_short)port);
	    break;
#endif
	}
	if (connect(s, (struct sockaddr *)fromp, socklen(fromp)) < 0) {
	    syslog(LOG_INFO ,
		   "connect second port: %m");
	    exit(1);
	}
    }
    dup2(f, 0);
    dup2(f, 1);
    dup2(f, 2);
    aierr = getnameinfo(fromp, socklen(fromp), hostname, sizeof(hostname),
			0, 0, 0);
    if (aierr) {
	error("failed to get remote host address: %s", gai_strerror(aierr));
	exit(1);
    }
    aierr = getnameinfo(fromp, socklen(fromp), hostaddra, sizeof(hostaddra),
			0, 0, NI_NUMERICHOST);
    if (aierr) {
	error("failed to get remote host address: %s", gai_strerror(aierr));
	exit(1);
    }

#ifdef KERBEROS
    status = pty_make_sane_hostname((struct sockaddr *) fromp, maxhostlen,
				    stripdomain, always_ip, &sane_host);
    if (status) {
	error("failed make_sane_hostname: %s\n", error_message(status));
	exit(1);
    }

    if ((status = recvauth(f, fromp, &valid_checksum))) {
	error("Authentication failed: %s\n", error_message(status));
	exit(1);
    }
#else
    getstr(f, remuser, sizeof(remuser), "remuser");
    getstr(f, locuser, sizeof(locuser), "locuser");
    getstr(f, cmdbuf, sizeof(cmdbuf), "command");
    rcmd_stream_init_normal();
#endif /* KERBEROS */
    
#ifdef CRAY
    paddr = inet_addr(inet_ntoa(fromp->sin_addr));
    if(secflag){
	/*
	 *      check network authorization list
	 */
	if (fetchnal(paddr,&nal) < 0) {
	    /*
	     *      NAL file inaccessible, abort connection.
	     */
	    error("Permission denied.\n");
	    exit(1);
	}
    }
#endif /* CRAY */
    
    pwd = getpwnam(locuser);
    if (pwd == (struct passwd *) 0 ) {
	syslog(LOG_ERR ,
	       "Principal %s (%s@%s (%s)) for local user %s has no account.\n",
	       kremuser, remuser, hostaddra, hostname,
	       locuser); /* xxx sprintf buffer in syslog*/
	error("Login incorrect.\n");
	exit(1);
    }
    
#ifdef CRAY
    /* Setup job entry, and validate udb entry. 
       ( against packet level also ) */
    if ((jid = setjob(pwd->pw_uid, 0)) < 0) {
	error("Unable to create new job.\n");
	exit(1);
    }
    if ((jtmpnam = makejtmp(pwd->pw_uid, pwd->pw_gid, jid))) {
	register int pid, tpid;
	int status;
	switch(pid = fork()) {
	  case -1:
	    cleanjtmp(locuser, jtmpnam);
	    envinit[TMPDIRENV] = 0;
	    break;
	  case 0:
	    break;
	  default:
	    close(0);
	    close(1);
	    close(2);
	    close(f);
	    if (port)
	      close(s);
	    while ((tpid = wait(&status)) != pid) {
		if (tpid < 0)
		  break;
	    }
	    cleanjtmp(locuser, jtmpnam);
	    exit(status>>8);
	    /* NOTREACHED */
	}
    } else {
	envinit[TMPDIRENV] = 0;
    }
#ifndef NO_UDB
    (void)getsysudb();
    
    if ((ue = getudbnam(pwd->pw_name)) == (struct udb *)NULL) {
	error("Unable to fetch account id.\n");
	exit(1);
    }
    ue_static = *ue;                /* save from setlimits call */
    endudb();
    if (secflag) {
	if(getsysv(&sysv, sizeof(struct sysv)) != 0) {
	    loglogin(sane_host, SLG_LLERR, 0, ue);
	    error("Permission denied.\n");
	    exit(1);
	}
	if ((packet_level != ue->ue_deflvl) ||
	    ((packet_compart & ue->ue_comparts) != packet_compart )){
	    loglogin(sane_host, SLG_LLERR, 0, ue);
	    error("Permission denied.\n");
	    exit(1);
	}
	if (ue->ue_disabled != 0) {
	    loglogin(sane_host,SLG_LOCK,ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    exit(1);
	}
	maxlogs = sysv.sy_maxlogs;
    }
    if (acctid(getpid(), ue->ue_acids[0]) == -1) {
	error("Unable to set account id.\n");
	exit(1);
    }
    if (setshares(pwd->pw_uid, acctid(0, -1), error, 1, 0)) {
	error("Unable to set shares.\n");
	exit(1);
    }
    if (setlimits(pwd->pw_name, C_PROC, getpid(), UDBRC_INTER)) {
	error("Unable to set limits.\n");
	exit(1);
    }
    if (setlimits(pwd->pw_name, C_JOB, jid, UDBRC_INTER)) {
	error("Unable to set limits.\n");
	exit(1);
    }
    ue = &ue_static;                /* restore after setlimits call */
    endudb();			/* setlimits opens udb and leaves it
				   open so close it here. */
#endif  /* !NO_UDB */
#endif /*CRAY*/
    
    /* Setup wtmp entry : we do it here so that if this is a CRAY
       the Process Id is correct and we have not lost our trusted
       privileges. */
    if (port) {
	/* Place entry into wtmp */
	sprintf(ttyn,"krsh%ld",(long) (getpid() % 9999999));
	pty_logwtmp(ttyn,locuser,sane_host);
    }
    /*      We are simply execing a program over rshd : log entry into wtmp,
	    as kexe(pid), then finish out the session right after that.
	    Syslog should have the information as to what was exec'd */
    else {
	pty_logwtmp(ttyn,locuser,sane_host);
    }
    
#ifdef CRAY
    
    /* If  we are a secure system then we need to get rid of our
       trusted facility, so that MAC on the chdir we work. Before we
       do this make an entry into wtmp, and any other audit recording. */
    
    if (secflag) {
	if (getusrv(&usrv)){
	    syslog(LOG_ERR,"Cannot getusrv");
	    error("Permission denied.\n");
	    loglogin(sane_host, SLG_LVERR, ue->ue_logfails,ue);
	    goto signout_please;
	}
	/*
	 *      6.0 no longer allows any form ofTRUSTED_PROCESS logins.
	 */
	if((ue->ue_valcat & TFM_TRUSTED) ||
	   (sysv.sy_oldtfm &&
	    ((ue->ue_comparts & TRUSTED_SUBJECT) == TRUSTED_SUBJECT))) {
	    loglogin(sane_host, SLG_TRSUB, ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    goto signout_please;
	}
	
	loglogin(sane_host, SLG_OKLOG, ue->ue_logfails,ue);
	
	/*	Setup usrv structure with user udb info and 
		packet_level and packet_compart. */
	usrv.sv_actlvl = packet_level;
	usrv.sv_actcmp = packet_compart; /*Note get_packet_level sets
					   compartment to users default
					   compartments....*/
	usrv.sv_permit = ue->ue_permits;
	usrv.sv_intcls = ue->ue_intcls;
	usrv.sv_maxcls = ue->ue_maxcls;
	usrv.sv_intcat = ue->ue_intcat;
	usrv.sv_valcat = ue->ue_valcat;
	usrv.sv_savcmp = 0;
	usrv.sv_savlvl = 0;
	
	/*
	 *      Set user values to workstation boundaries
	 */
#ifdef MIN
#undef MIN
#endif
#ifdef MAX
#undef MAX
#endif
	
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
	
	nal_error = 0;
	
	if (nal.na_sort) {
	    if ((ue->ue_minlvl > nal.na_smax) ||
		(ue->ue_maxlvl < nal.na_smin))
	      nal_error++;
	    else {
		usrv.sv_minlvl=MAX(ue->ue_minlvl, nal.na_smin);
		usrv.sv_maxlvl=MIN(ue->ue_maxlvl, nal.na_smax);
		
#ifndef IP_SECURITY

		if (usrv.sv_actlvl < usrv.sv_minlvl)
		    usrv.sv_actlvl = usrv.sv_minlvl;
		if (usrv.sv_actlvl > usrv.sv_maxlvl)
		  usrv.sv_actlvl = usrv.sv_maxlvl;
		
#else /*IP_SECURITY*/
		if (usrv.sv_actlvl < usrv.sv_minlvl)
		  nal_error++;
		if (usrv.sv_actlvl > usrv.sv_maxlvl)
		  nal_error++;
		if (usrv.sv_actlvl != ue->ue_deflvl)
		  nal_error++;
		
		usrv.sv_valcmp = ue->ue_comparts & nal.na_scmp;
		usrv.sv_actcmp &= nal.na_scmp;
#endif /*IP_SECURITY*/
		usrv.sv_valcmp = ue->ue_comparts & nal.na_scmp;
		usrv.sv_actcmp = (usrv.sv_valcmp &
				  ue->ue_defcomps);
	    }
	} else {
	    /*
	     *      If the user's minimum level is greater than
	     *      zero, they cannot log on from this (ie. an
	     *      unclassified) host.
	     */
	    if (ue->ue_minlvl > 0)
	      nal_error++;
	    /*
	     *      Address not in NAL, if EXEMPT_NAL is not
	     *      true, then even an unclassified user is
	     *      not allowed.
	     */
	    if (!EXEMPT_NAL)
		nal_error++;
	    else {
		usrv.sv_minlvl = 0;
		usrv.sv_maxlvl = 0;
		usrv.sv_valcmp = 0;
		usrv.sv_actcmp = 0;
		usrv.sv_actlvl = 0;
	    }
	}
	if (nal_error) {
	    loglogin(sane_host, SLG_LVERR, ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    goto signout_please;
	}
#undef  MIN
#undef  MAX
	/* Before the setusrv is done then do a sethost for paddr */
	sethost(paddr);
	
	if (setusrv(&usrv) == -1) {
	    loglogin(sane_host, SLG_LVERR, ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    goto signout_please;
	}
	if (getusrv(&usrv) == -1) {
	    error("Getusrv Permission denied.\n");
	    goto signout_please;
	}
	
    }
#endif /*CRAY*/
    
    if (chdir(pwd->pw_dir) < 0) {
      if(chdir("/") < 0) {
      	error("No remote directory.\n");
	goto signout_please;
      }
	   pwd->pw_dir = "/";
    }

#ifdef KERBEROS

#if defined(KRB5_KRB4_COMPAT) && !defined(ALWAYS_V5_KUSEROK)
	if (auth_sys == KRB5_RECVAUTH_V4) {
	    /* kuserok returns 0 if OK */
	    if (kuserok(v4_kdata, locuser)){
		syslog(LOG_ERR ,
		       "Principal %s (%s@%s (%s)) for local user %s failed kuserok.\n",
		       kremuser, remuser, hostaddra, hostname, locuser);
		}
	    else auth_sent |= AUTH_KRB4;
	} else
#endif
	{
	    /* krb5_kuserok returns 1 if OK */
	    if (!krb5_kuserok(bsd_context, client, locuser)){
		syslog(LOG_ERR ,
		       "Principal %s (%s@%s (%s)) for local user %s failed krb5_kuserok.\n",
		       kremuser, remuser, hostaddra, hostname, locuser);
	    }
	    else
		auth_sent |=
		    ((auth_sys == KRB5_RECVAUTH_V4) ? AUTH_KRB4 : AUTH_KRB5);
	}

	
#else
    if (pwd->pw_passwd != 0 && *pwd->pw_passwd != '\0' &&
	ruserok(hostname[0] ? hostname : hostaddra,
		pwd->pw_uid == 0, remuser, locuser) < 0) {
	error("Permission denied.\n");
	goto signout_please;
    }
#endif /* KERBEROS */


    if (checksum_required && !valid_checksum) {
	if (auth_sent & AUTH_KRB5) {
	    syslog(LOG_WARNING, "Client did not supply required checksum--connection rejected.");
	    error( "You are using an old Kerberos5 client without checksum support; only newer clients are authorized.\n");
	    goto signout_please;
	} else {
	    syslog(LOG_WARNING,
   "Configuration error: Requiring checksums with -c is inconsistent with allowing Kerberos V4 connections.");
	}
    }
    if (require_encrypt&&(!do_encrypt)) {
	error("You must use encryption.\n");
	goto signout_please;
    }
    if (!(auth_ok&auth_sent)) {
	if (auth_sent)
	    error("Another authentication mechanism must be used to access this host.\n");
	else
	    error("Permission denied.\n");
	goto signout_please;
    }
    
    if (pwd->pw_uid && !access(NOLOGIN, F_OK)) {
	error("Logins currently disabled.\n");
	goto signout_please;
    }
    
    /* Log access to account */
    pwd = (struct passwd *) getpwnam(locuser);
    if (pwd && (pwd->pw_uid == 0)) {
#ifdef LOG_CMD
	syslog(LOG_NOTICE, "Executing %s for principal %s (%s@%s (%s)) as ROOT", 
	       cmdbuf, kremuser, remuser, hostaddra, hostname);
#else
	syslog(LOG_NOTICE ,"Access as ROOT by principal %s (%s@%s (%s))",
	       kremuser, remuser, hostaddra, hostname);
#endif
    }
#if defined(KERBEROS) && defined(LOG_REMOTE_REALM) && !defined(LOG_OTHER_USERS) && !defined(LOG_ALL_LOGINS)
    /* Log if principal is from a remote realm */
    else if (client && !default_realm(client))
#endif
  
#if defined(KERBEROS) && defined(LOG_OTHER_USERS) && !defined(LOG_ALL_LOGINS) 
    /* Log if principal name does not map to local username */
    else if (client && !princ_maps_to_lname(client, locuser))
#endif /* LOG_OTHER_USERS */
  
#ifdef LOG_ALL_LOGINS /* Log everything */
    else 
#endif 
  
#if defined(LOG_REMOTE_REALM) || defined(LOG_OTHER_USERS) || defined(LOG_ALL_LOGINS)
      {
#ifdef LOG_CMD
	  syslog(LOG_NOTICE, "Executing %s for principal %s (%s@%s (%s)) as local user %s", 
		 cmdbuf, kremuser, remuser, hostaddra, hostname, locuser);
#else
	  syslog(LOG_NOTICE ,"Access as %s by principal %s (%s@%s (%s))",
		 locuser, kremuser, remuser, hostaddra, hostname);
#endif
      }
#endif
    
    (void) write(2, "", 1);
    
    if (port||do_encrypt) {
	if (port&&(pipe(pv) < 0)) {
	    error("Can't make pipe.\n");
	    goto signout_please;
	}
	if (pipe(pw) < 0) {
	    error("Can't make pipe 2.\n");
	    goto signout_please;
	}
	if (pipe(px) < 0) {
	    error("Can't make pipe 3.\n");
	    goto signout_please;
	}
	pid = fork();
	if (pid == -1)  {
	    error("Fork failed.\n");
	    goto signout_please;
	}
	if (pid) {
#ifdef POSIX_SIGNALS
	    sa.sa_handler = cleanup;
	    (void)sigaction(SIGINT, &sa, (struct sigaction *)0);
	    (void)sigaction(SIGQUIT, &sa, (struct sigaction *)0);
	    (void)sigaction(SIGTERM, &sa, (struct sigaction *)0);
	    (void)sigaction(SIGHUP, &sa, (struct sigaction *)0);

	    sa.sa_handler = SIG_IGN;
	    /* SIGPIPE is a crutch that we don't need if we check 
	       the exit status of write. */
	    (void)sigaction(SIGPIPE, &sa, (struct sigaction *)0);
	    (void)sigaction(SIGCHLD, &sa, (struct sigaction *)0);
#else
	    signal(SIGINT, cleanup);
	    signal(SIGQUIT, cleanup);
	    signal(SIGTERM, cleanup);
	    signal(SIGHUP, cleanup);
	    /* SIGPIPE is a crutch that we don't need if we check 
	       the exit status of write. */
	    signal(SIGPIPE, SIG_IGN);
	    signal(SIGCHLD,SIG_IGN);
#endif
	    
	    (void) close(0); (void) close(1); (void) close(2);
	    if(port)
		(void) close(pv[1]);
	    (void) close(pw[1]);
	    (void) close(px[0]);
	    
	    
	    
	    FD_ZERO(&readfrom);
	    FD_SET(f, &readfrom);
	    if(port) {
		FD_SET(s, &readfrom);
		FD_SET(pv[0], &readfrom);
	    }
	    FD_SET(pw[0], &readfrom);
	    
	    /* read from f, write to px[1] -- child stdin */
	    /* read from s, signal child */
	    /* read from pv[0], write to s -- child stderr */
	    /* read from pw[0], write to f -- child stdout */

	    do {
		ready = readfrom;
		if (select(8*sizeof(ready), &ready, (fd_set *)0,
			   (fd_set *)0, (struct timeval *)0) < 0) {
		    if (errno == EINTR) {
			continue;
		    } else {
			break;
		}
		}

		if (port&&FD_ISSET(pv[0], &ready)) {
		    /* read from the child stderr, write to the net */
		    errno = 0;
		    cc = read(pv[0], buf, sizeof (buf));
		    if (cc <= 0) {
			shutdown(s, 1+1);
			FD_CLR(pv[0], &readfrom);
		    } else {
			(void) rcmd_stream_write(s, buf, (unsigned) cc, 1);
		    }
		}
		if (FD_ISSET(pw[0], &ready)) {
		    /* read from the child stdout, write to the net */
		    errno = 0;
		    cc = read(pw[0], buf, sizeof (buf));
		    if (cc <= 0) {
			shutdown(f, 1+1);
			FD_CLR(pw[0], &readfrom);
		    } else {
			(void) rcmd_stream_write(f, buf, (unsigned) cc, 0);
		    }
		}
		if (port&&FD_ISSET(s, &ready)) {
		    /* read from the alternate channel, signal the child */
		    if (rcmd_stream_read(s, &sig, 1, 1) <= 0) {
			FD_CLR(s, &readfrom);
		    } else {
#ifdef POSIX_SIGNALS
			sa.sa_handler = cleanup;
			(void)sigaction(sig, &sa, (struct sigaction *)0);
			kill(-pid, sig);
#else
			signal(sig, cleanup);
			killpg(pid, sig);
#endif
		    }
		}
		if (FD_ISSET(f, &ready)) {
		    /* read from the net, write to child stdin */
		    errno = 0;
		    cc = rcmd_stream_read(f, buf, sizeof(buf), 0);
		    if (cc <= 0) {
			(void) close(px[1]);
			FD_CLR(f, &readfrom);
		    } else {
		        int wcc;
		        wcc = write(px[1], buf, (unsigned) cc);
			if (wcc == -1) {
			  /* pipe closed, don't read any more */
			  /* might check for EPIPE */
			  (void) close(px[1]);
			  FD_CLR(f, &readfrom);
			} else if (wcc != cc) {
			  syslog(LOG_INFO, "only wrote %d/%d to child", 
				 wcc, cc);
			}
		    }
		}
	    } while ((port&&FD_ISSET(s, &readfrom)) ||
		     FD_ISSET(f, &readfrom) ||
		     (port&&FD_ISSET(pv[0], &readfrom) )||
		     FD_ISSET(pw[0], &readfrom));
	    ignore_signals();
#ifdef KERBEROS
	    syslog(LOG_INFO ,
		   "Shell process completed.");
#endif
	    /* Finish session in wmtp */
	    pty_logwtmp(ttyn,"","");
	    if (ccache)
		krb5_cc_destroy(bsd_context, ccache);
	    exit(0);
	}
#if defined(HAVE_SETSID)&&(!defined(ULTRIX))
	setsid();
#else
#ifdef SETPGRP_TWOARG
	setpgrp(0, getpid());
#else
	setpgrp();
#endif /*setpgrp_twoarg*/
#endif /*HAVE_SETSID*/
	(void) close(s);
	(void) close(f);
	(void) close(pw[0]);
	if (port)
	    (void) close(pv[0]);
	(void) close(px[1]);

	(void) dup2(px[0], 0);
	(void) dup2(pw[1], 1);
	if(port)
	    (void) dup2(pv[1], 2);
	else dup2(pw[1], 2);

	(void) close(px[0]);
	(void) close(pw[1]);
	if(port)
	    (void) close(pv[1]);
    }
    
    /*      We are simply execing a program over rshd : log entry into wtmp, 
	    as kexe(pid), then finish out the session right after that.
	    Syslog should have the information as to what was exec'd */
    else {
	pty_logwtmp(ttyn,"","");
    }
    
    if (*pwd->pw_shell == '\0')
      pwd->pw_shell = "/bin/sh";
    (void) close(f);
    (void) setgid((gid_t)pwd->pw_gid);
#ifndef sgi
    if (getuid() == 0 || getuid() != pwd->pw_uid) {
        /* For testing purposes, we don't call initgroups if we
           already have the right uid, and it is not root.  This is
           because on some systems initgroups outputs an error message
           if not called by root.  */
        initgroups(pwd->pw_name, pwd->pw_gid);
    }
#endif
#ifdef	HAVE_SETLUID
    /*
     * If we're on a system which keeps track of login uids, then
     * set the login uid. 
     */
    setluid((uid_t) pwd->pw_uid);
#endif	/* HAVE_SETLUID */
    (void) setuid((uid_t)pwd->pw_uid);
    /* if TZ is set in the parent, drag it in */
    {
      char **findtz = environ;
      while(*findtz) {
	if(!strncmp(*findtz,"TZ=",3)) {
	  envinit[TZENV] = *findtz;
	  break;
	}
	findtz++;
      }
    }
    strncat(homedir, pwd->pw_dir, sizeof(homedir)-6);
    strncat(shell, pwd->pw_shell, sizeof(shell)-7);
    strncat(username, pwd->pw_name, sizeof(username)-6);
    path = (char *) malloc(strlen(kprogdir) + strlen(path_rest) + 7);
    if (path == NULL) {
        perror("malloc");
	_exit(1);
    }
    sprintf(path, "PATH=%s:%s", kprogdir, path_rest);
    envinit[PATHENV] = path;

    /* If we have KRB5CCNAME set, then copy into the
     * child's environment.  This can't really have
     * a fixed position because tz may or may not be set.
     */
    if (getenv("KRB5CCNAME")) {
	int i;
	char *buf2 = (char *)malloc(strlen(getenv("KRB5CCNAME"))
			 		   +strlen("KRB5CCNAME=")+1);
	if (buf2) {
	  sprintf(buf2, "KRB5CCNAME=%s",getenv("KRB5CCNAME"));

	  for (i = 0; envinit[i]; i++);
	  envinit[i] = buf2;
	}
    }

    {
      char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
      int i;
      /* these four are covered by ADDRPAD */

      for (i = 0; envinit[i]; i++);

      aierr = getnameinfo((struct sockaddr *)&localaddr,
			  socklen((struct sockaddr *)&localaddr),
			  hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
			  NI_NUMERICHOST | NI_NUMERICSERV);
      if (aierr)
	  goto skip_localaddr_env;
      sprintf(local_addr,  "KRB5LOCALADDR=%s", hbuf);
      envinit[i++] =local_addr;

      sprintf(local_port,  "KRB5LOCALPORT=%s", sbuf);
      envinit[i++] =local_port;
    skip_localaddr_env:

      aierr = getnameinfo(fromp, socklen(fromp),
			  hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
			  NI_NUMERICHOST | NI_NUMERICSERV);
      if (aierr)
	  goto skip_remoteaddr_env;
      sprintf(remote_addr, "KRB5REMOTEADDR=%s", hbuf);
      envinit[i++] =remote_addr;

      sprintf(remote_port, "KRB5REMOTEPORT=%s", sbuf);
      envinit[i++] =remote_port;

    skip_remoteaddr_env:
      ;
    }

    /* If we do anything else, make sure there is space in the array. */

    for(cnt=0; cnt < num_env; cnt++) {
	    int i;
	    char *buf2;

	    if(getenv(save_env[cnt])) {
		    buf2 = (char *)malloc(strlen(getenv(save_env[cnt]))
					 +strlen(save_env[cnt]+2));
		    if (buf2) {
			    sprintf(buf2, "%s=%s", save_env[cnt], 
				    getenv(save_env[cnt]));
			    for (i = 0; envinit[i]; i++);
			    envinit[i] = buf2;
		    }
	    }
    }

    /* XXX - If we do anything else, make sure there is space in the array. */

    environ = envinit;
    
#ifdef KERBEROS
    /* To make Kerberos rcp work correctly, we must ensure that we
       invoke Kerberos rcp on this end, not normal rcp, even if the
       shell startup files change PATH.  */
    if (!strncmp(cmdbuf, "rcp ", 4) ||
	(do_encrypt && !strncmp(cmdbuf, "-x rcp ", 7))) {
        char *copy;
	struct stat s2;
	int offst = 0;

	copy = malloc(strlen(cmdbuf) + 1);
	if (copy == NULL) {
	    perror("malloc");
	    _exit(1);
	}
	strcpy(copy, cmdbuf);
	if (do_encrypt && !strncmp(cmdbuf, "-x ", 3)) {
		offst = 3;
	}

        strcpy((char *) cmdbuf + offst, kprogdir);
	cp = copy + 3 + offst;

	cmdbuf[sizeof(cmdbuf) - 1] = '\0';
	if (auth_sys == KRB5_RECVAUTH_V4) {
	  strncat(cmdbuf, "/v4rcp", sizeof(cmdbuf) - 1 - strlen(cmdbuf));
	} else {
	  strncat(cmdbuf, "/rcp", sizeof(cmdbuf) - 1 - strlen(cmdbuf));
	}
	if (stat((char *)cmdbuf + offst, &s2) >= 0)
	  strncat(cmdbuf, cp, sizeof(cmdbuf) - 1 - strlen(cmdbuf));
	else
	  strncpy(cmdbuf, copy, sizeof(cmdbuf) - 1 - strlen(cmdbuf));
	free(copy);
    }
#endif

    cp = strrchr(pwd->pw_shell, '/');
    if (cp)
      cp++;
    else
      cp = pwd->pw_shell;
    
    if (do_encrypt && !strncmp(cmdbuf, "-x ", 3)) {
	execl(pwd->pw_shell, cp, "-c", (char *)cmdbuf + 3, (char *)NULL);
    }
    else {
	execl(pwd->pw_shell, cp, "-c", cmdbuf, (char *)NULL);
    }
    perror(pwd->pw_shell);
    perror(cp);
    exit(1);
    
  signout_please:
    if (ccache)
	krb5_cc_destroy(bsd_context, ccache);
    ccache = NULL;
    pty_logwtmp(ttyn,"","");
    exit(1);
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
    char buf[RCMD_BUFSIZ],  *cp = buf;
    
#ifdef HAVE_STDARG_H
    va_start(ap, fmt);
#else
    va_start(ap);
#endif

    *cp++ = 1;
    (void) sprintf(cp, "%s: ", progname);
    (void) vsprintf(buf+strlen(buf), fmt, ap);
    va_end(ap);
    (void) write(2, buf, strlen(buf));
    syslog(LOG_ERR ,"%s",buf+1);
}


void getstr(fd, buf, cnt, err)
    int fd;
    char *buf;
    int cnt;
    char *err;
{
    char c;
    
    do {
	if (read(fd, &c, 1) != 1)
	  exit(1);
	*buf++ = c;
	if (--cnt == 0) {
	    error("%s too long\n", err);
	    exit(1);
	}
    } while (c != 0);
}

#ifdef	CRAY
char *makejtmp(uid, gid, jid)
     register int uid, gid, jid;
{
    register char *endc, *tdp = &tmpdir[strlen(tmpdir)];
    register int i;
    
    sprintf(tdp, "%s/jtmp.%06d", JTMPDIR, jid);
    endc = &tmpdir[strlen(tmpdir)];
    
    endc[1] = '\0';
    for (i = 0; i < 26; i++) {
	endc[0] = 'a' + i;
	if (mkdir(tdp, JTMPMODE) != -1) {
	    chown(tdp, uid, gid);
	    return (tdp);
	} else if (errno != EEXIST)
	  break;
    }
    return(NULL);
}



cleanjtmp(user, tpath)
     register char *user, *tpath;
{
    switch(fork()) {
      case -1:
	break;
      case 0:
	if (secflag) {
	    execl("/bin/rm", "rm", "-rf", tpath, 0);
	    error("exec of %s failed; errno = %d\n",
		  "/bin/rm", errno);
	} else {
	    execl(CLEANTMPCMD, CLEANTMPCMD, user, tpath, 0);
	    error("exec of %s failed; errno = %d\n",
		  CLEANTMPCMD, errno);
	}
	exit(1);
	break;
      default:
	/*
	 * Just forget about the child, let init will pick it
	 * up after we exit.
	 */
	break;
    }
}



/***get_packet_classification
 *
 *
 *      int get_packet_classification():
 *      Obtain packet level and compartments from passed fd...
 *
 *      Returns:
 *             -1: If could not get user defaults.
 *              0: success
 */
#ifdef IP_SECURITY
static int get_packet_classification(fd,useruid,level,comp)
     int fd;
     uid_t useruid;
     int *level;
     long *comp;
{
    struct socket_security pkt_sec;
    struct udb *udb;
    int retval;
    int sockoptlen;
    
    retval = 0;
    getsysudb ();
    udb = getudbuid ((int) useruid);
    endudb ();
    if (udb == (struct udb *) 0) return(-1);
    /* Get packet IP packet label */
    sockoptlen = SIZEOF_sec;
    if ( getsockopt(fd,SOL_SOCKET,SO_SECURITY,
		    (char *) &pkt_sec,&sockoptlen)){  /* Failed */
	return(-2);
    }
    *level = pkt_sec.sec_level;
    *comp = udb->ue_defcomps;
    return(0);
}

#else  /* If no IP_SECURITY set level to users default */

static int get_packet_classification(fd,useruid,level,comp)
     int fd;
     uid_t useruid;
     int *level;
     long *comp;
{
    struct udb    *udb;
    getsysudb ();
    udb = getudbuid ((int) useruid);
    endudb ();
    if (udb == (struct udb *) 0) return(-1);
    *level = udb->ue_deflvl;
    *comp = udb->ue_defcomps;
    return(0);
}

#endif /* IP_SECURITY */
	
	

/*
 * Make a security log entry for the login attempt.
 *     host = pointer to host id
 *     flag = status of login
 *     failures = current losing streak in login attempts
 */
/* Make a security log entry for the login attempt.
 *  host = pointer to host id
 *  flag = status of login
 *  failures = current losing streak in login attempts
 */

loglogin(host, flag, failures, ue)
     char    *host;
     int     flag;
     int     failures;
     struct udb * ue;
{
    char   urec[sizeof(struct slghdr) + sizeof(struct slglogin)];
    struct slghdr   *uhdr = (struct slghdr *)urec;
    struct slglogin *ulogin=(struct slglogin *)&urec[sizeof(struct slghdr)];
    
    strncpy(ulogin->sl_line, ttyn, sizeof(ulogin->sl_line));
    strncpy(ulogin->sl_host, host, sizeof(ulogin->sl_host));
    ulogin->sl_failures = failures;
    if ( maxlogs && (failures >= maxlogs))
      flag |= SLG_DSABL;
    ulogin->sl_result = flag;
    uhdr->sl_uid = ue->ue_uid;
    uhdr->sl_ruid = ue->ue_uid;
    uhdr->sl_juid = ue->ue_uid;
    uhdr->sl_gid = ue->ue_gids[0];
    uhdr->sl_rgid = ue->ue_gids[0];
    uhdr->sl_slvl = ue->ue_deflvl;
    /*      uhdr->sl_scls = ue->ue_defcls;  enable for integrity policy */
    uhdr->sl_olvl = 0;
    uhdr->sl_len = sizeof(urec);
    
#ifdef  CRAY2
    slgentry(SLG_LOGN, (word *)urec);
#else /*        ! CRAY2 */
    slgentry(SLG_LOGN, (waddr_t)urec);
#endif
    return;
}

#endif /* CRAY */
	


void usage()
{
#ifdef KERBEROS
    syslog(LOG_ERR, "usage: kshd [-54ecikK]  ");
#else
    syslog(LOG_ERR, "usage: rshd");
#endif
}


#ifdef KERBEROS

#ifndef KRB_SENDAUTH_VLEN
#define	KRB_SENDAUTH_VLEN 8	    /* length for version strings */
#endif

#define	KRB_SENDAUTH_VERS	"AUTHV0.1" /* MUST be KRB_SENDAUTH_VLEN
					      chars */

static krb5_error_code
recvauth(netfd, peersin, valid_checksum)
     int netfd;
     struct sockaddr *peersin;
     int *valid_checksum;
{
    krb5_auth_context auth_context = NULL;
    krb5_error_code status;
    struct sockaddr_in laddr;
    socklen_t len;
    krb5_data inbuf;
#ifdef KRB5_KRB4_COMPAT
    char v4_instance[INST_SZ];	/* V4 Instance */
#endif
    krb5_authenticator *authenticator;
    krb5_ticket        *ticket;
    krb5_rcache		rcache;
    struct passwd *pwd;
    uid_t uid;
    gid_t gid;
    enum kcmd_proto kcmd_proto;
    krb5_data version;

    *valid_checksum = 0;
    len = sizeof(laddr);
    if (getsockname(netfd, (struct sockaddr *)&laddr, &len)) {
	    exit(1);
    }
	
#ifdef unicos61
#define SIZEOF_INADDR  SIZEOF_in_addr
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

#ifdef KRB5_KRB4_COMPAT
    strcpy(v4_instance, "*");
#endif

    status = krb5_auth_con_init(bsd_context, &auth_context);
    if (status)
	return status;

    status = krb5_auth_con_genaddrs(bsd_context, auth_context, netfd,
			        KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR);
    if (status)
	return status;

    status = krb5_auth_con_getrcache(bsd_context, auth_context, &rcache);
    if (status) return status;

    if (! rcache) {
	krb5_principal server;

	status = krb5_sname_to_principal(bsd_context, 0, 0,
					 KRB5_NT_SRV_HST, &server);
	if (status) return status;

	status = krb5_get_server_rcache(bsd_context,
				krb5_princ_component(bsd_context, server, 0),
				&rcache);
	krb5_free_principal(bsd_context, server);
	if (status) return status;

	status = krb5_auth_con_setrcache(bsd_context, auth_context, rcache);
	if (status) return status;
    }

#ifdef KRB5_KRB4_COMPAT
    status = krb5_compat_recvauth_version(bsd_context, &auth_context, &netfd,
				  NULL,		/* Specify daemon principal */
				  0, 		/* no flags */
				  keytab, /* normally NULL to use v5srvtab */
				  0, 		/* v4_opts */
				  "rcmd", 	/* v4_service */
				  v4_instance, 	/* v4_instance */
				  (struct sockaddr_in *)peersin, /* foreign address */
				  &laddr, 	/* our local address */
				  "", 		/* use default srvtab */

				  &ticket, 	/* return ticket */
				  &auth_sys, 	/* which authentication system*/
				  &v4_kdata, 0, &version);
#else
    status = krb5_recvauth_version(bsd_context, &auth_context, &netfd,
				   NULL,        /* daemon principal */
				   0,           /* no flags */
				   keytab,      /* normally NULL to use v5srvtab */
				   &ticket,    /* return ticket */
				   &version); /* application version string */
    auth_sys = KRB5_RECVAUTH_V5;
#endif
    if (status) {
	if (auth_sys == KRB5_RECVAUTH_V5) {
	    /*
	     * clean up before exiting
	     */
	    getstr(netfd, locuser, sizeof(locuser), "locuser");
	    getstr(netfd, cmdbuf, sizeof(cmdbuf), "command");
	    getstr(netfd, remuser, sizeof(locuser), "remuser");
	}
	return status;
    }

    getstr(netfd, locuser, sizeof(locuser), "locuser");
    getstr(netfd, cmdbuf, sizeof(cmdbuf), "command");

#ifdef KRB5_KRB4_COMPAT
    if (auth_sys == KRB5_RECVAUTH_V4) {
	rcmd_stream_init_normal();
	
	/* We do not really know the remote user's login name.
         * Assume it to be the same as the first component of the
	 * principal's name. 
         */
	strcpy(remuser, v4_kdata->pname);

	status = krb5_425_conv_principal(bsd_context, v4_kdata->pname,
					 v4_kdata->pinst, v4_kdata->prealm,
					 &client);
	if (status) return status;

	status = krb5_unparse_name(bsd_context, client, &kremuser);
	
	return status;
    }
#endif /* KRB5_KRB4_COMPAT */

    /* Must be V5  */
	
    kcmd_proto = KCMD_UNKNOWN_PROTOCOL;
    if (version.length != 9)
	fatal (netfd, "bad application version length");
    if (!memcmp (version.data, "KCMDV0.1", 9))
	kcmd_proto = KCMD_OLD_PROTOCOL;
    if (!memcmp (version.data, "KCMDV0.2", 9))
	kcmd_proto = KCMD_NEW_PROTOCOL;

    getstr(netfd, remuser, sizeof(locuser), "remuser");

    if ((status = krb5_unparse_name(bsd_context, ticket->enc_part2->client, 
				    &kremuser)))
	return status;
    
    if ((status = krb5_copy_principal(bsd_context, ticket->enc_part2->client, 
				      &client)))
	return status;
    if ((status = krb5_auth_con_getauthenticator(bsd_context, auth_context,
						 &authenticator)))
      return status;
    
    if (authenticator->checksum && !checksum_ignored) {
	struct sockaddr_storage adr;
	unsigned int adr_length = sizeof(adr);
	int e;
	unsigned int buflen = strlen(cmdbuf)+strlen(locuser)+32;
	char * chksumbuf = (char *) malloc(buflen);

	if (chksumbuf == 0)
	    goto error_cleanup;
	if (getsockname(netfd, (struct sockaddr *) &adr, &adr_length) != 0)
	    goto error_cleanup;

	e = getnameinfo((struct sockaddr *)&adr, adr_length, 0, 0,
			chksumbuf, buflen, NI_NUMERICSERV);
	if (e) {
	    free(chksumbuf);
	    fatal(netfd, "local error: can't examine port number");
	}
	if (strlen(chksumbuf) > 30) {
	    free(chksumbuf);
	    fatal(netfd, "wacky local port number?!");
	}
	strcat(chksumbuf, ":");
	strcat(chksumbuf,cmdbuf);
	strcat(chksumbuf,locuser);

	status = krb5_verify_checksum(bsd_context,
				      authenticator->checksum->checksum_type,
				      authenticator->checksum,
				      chksumbuf, strlen(chksumbuf),
				      ticket->enc_part2->session->contents, 
				      ticket->enc_part2->session->length);

    error_cleanup:
	if (chksumbuf)
	    free(chksumbuf);
	if (status) {
	    krb5_free_authenticator(bsd_context, authenticator);
	    return status;
	}
	*valid_checksum = 1;
    }
    krb5_free_authenticator(bsd_context, authenticator);


    if (!strncmp(cmdbuf, "-x ", 3))
	do_encrypt = 1;

    {
	krb5_keyblock *key;
	status = krb5_auth_con_getrecvsubkey (bsd_context, auth_context,
					      &key);
	if (status)
	    fatal (netfd, "Server can't get session subkey");
	if (!key && do_encrypt && kcmd_proto == KCMD_NEW_PROTOCOL)
	    fatal (netfd, "No session subkey sent");
	if (key && kcmd_proto == KCMD_OLD_PROTOCOL) {
#ifdef HEIMDAL_FRIENDLY
	    key = 0;
#else
	    fatal (netfd, "Session subkey not allowed in old kcmd protocol");
#endif
	}
	if (key == 0)
	    key = ticket->enc_part2->session;
	rcmd_stream_init_krb5 (key, do_encrypt, 0, 0, kcmd_proto);
    }

    /* Null out the "session" because kcmd.c references the session
     * key here, and we do not want krb5_free_ticket() to destroy it. */
    ticket->enc_part2->session = 0;

    if ((status = krb5_read_message(bsd_context, (krb5_pointer)&netfd,
				    &inbuf))) {
	error("Error reading message: %s\n", error_message(status));
	exit(1);
    }

    if (inbuf.length) { /* Forwarding being done, read creds */
	pwd = getpwnam(locuser);
	if (!pwd) {
	    error("Login incorrect.\n");
	    exit(1);
	}
	uid = pwd->pw_uid;
	gid = pwd->pw_gid;
	if ((status = rd_and_store_for_creds(bsd_context, auth_context, &inbuf,
					     ticket, &ccache))) {
	    error("Can't get forwarded credentials: %s\n",
		  error_message(status));
	    exit(1);
	}
	if (chown(krb5_cc_get_name(bsd_context, ccache), uid, gid) == -1) {
	    error("Can't chown forwarded credentials: %s\n",
		  error_message(errno));
	    exit(1);
	}
    }
    krb5_free_ticket(bsd_context, ticket);
    return 0;
}
#endif /* KERBEROS */



void fatal(f, msg)
     int f;
     const char *msg;
{
    char buf[512];
#ifndef POSIX_TERMIOS
    int out = 1 ;          /* Output queue of f */
#endif

    buf[0] = '\01';             /* error indicator */
    (void) sprintf(buf + 1, "%s: %s.\r\n",progname, msg);
    if ((f == netf) && (pid > 0))
      (void) rcmd_stream_write(f, buf, strlen(buf), 0);
    else
      (void) write(f, buf, strlen(buf));
    syslog(LOG_ERR,"%s\n",msg);
    if (pid > 0) {
        signal(SIGCHLD,SIG_IGN);
        kill(pid,SIGKILL);
#ifdef POSIX_TERMIOS
        (void) tcflush(1, TCOFLUSH);
#else
        (void) ioctl(f, TIOCFLUSH, (char *)&out);
#endif
        cleanup(-1);
    }
    exit(1);
}
