/*
 *	$Author$
 *	$Header$
 */

#ifndef lint
static char rcsid_rshd_c[] =
  "$Header$";
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
static char sccsid[] = "@(#)rshd.c	5.12 (Berkeley) 9/12/88";
#endif /* not lint */

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
 *    ~/.rhosts  (using ruserok).
 * Execute command if configured authoriztion checks pass, else deny 
 * permission.
 *
 * The configuration is done either by command-line arguments passed by inetd, 
 * or by the name of the daemon. If command-line arguments are present, they 
 * take priority. The options are:
 * -k and -K means check .k5login (using krb5_kuserok).
 * -r and -R means check .rhosts  (using ruserok).
 * The difference between upper and lower case is as follows:
 *    If lower case -r or -k, then as long as one of krb5_kuserok or ruserok 
 * passes, allow access. If both fail, no access. The program does not fall
 * back on password verification.
 *    If uppercase -R or -K, then those checks must be passed, regardless of 
 * other checks, else no access.
 * 
 *     If no command-line arguments are present, then the presence of the 
 * letters kKrR in the program-name before "shd" determine the 
 * behaviour of the program exactly as with the command-line arguments.
 */
     
/* DEFINES:
 *   KERBEROS - Define this if application is to be kerberised.
 *   SERVE_V4 - Define this if v4 rlogin clients are also to be served.
 *   ALWAYS_V5_KUSEROK - Define this if you want .k5login to be
 *              checked even for v4 clients (instead of .klogin).
 *   SERVE_NON_KRB - Define this is non-kerberized rlogin clients are 
 *              to be served. NOTE HOWEVER THAT THIS IS A SERIOUS
 *              SECURITY FLAW!
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
     
#define SERVE_V4
#define SERVE_NON_KRB     
#define LOG_REMOTE_REALM
#define LOG_CMD
     
#include <sys/ioctl.h>
#include <sys/param.h>
     
#if defined(CRAY) || defined(sysvimp) || defined(aux20)
#include <sys/types.h>
#ifndef _TYPES_
#define _TYPES_
#endif
#ifndef  F_OK
#define F_OK 0
#endif
#endif
     
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
     
#include <netinet/in.h>
     
#ifndef SYSV
#include <arpa/inet.h>
#endif
     
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
     
#ifdef sun
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif
     
#include <signal.h>
#include <netdb.h>
     
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
     
#ifdef KERBEROS
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/mit-des.h>

#include <com_err.h>

#define ARGSTR	"rRkKD:?"
#else /* !KERBEROS */
#define ARGSTR	"rRD:?"
     
char *strsave();
#endif /* KERBEROS */
     
int must_pass_rhosts = 0, must_pass_k5 = 0, must_pass_one = 0;
int failed_k5 = 0;
char *progname;

#define MAX_PROG_NAME 10

#ifdef CRAY
int     secflag;
extern
#endif /* CRAY */
int     errno;

char	*index(), *rindex(), *strncat();
/*VARARGS1*/
int	error();



main(argc, argv)
     int argc;
     char **argv;
{
#if defined(BSD) && BSD >= 43
    struct linger linger;
#endif
    int on = 1, fromlen;
    struct sockaddr_in from;
    extern int opterr, optind;
    extern char *optarg;
    char *options, ch;
    int i;
    int fd;
    int debug_port;

#ifdef CRAY
    secflag = sysconf(_SC_CRAY_SECURE_SYS);
#endif
    
    progname = *argv;
    
#ifndef LOG_ODELAY /* 4.2 syslog */
    openlog(progname, LOG_PID);
#else
#ifndef LOG_DAEMON
#define LOG_DAEMON 0
#endif
    openlog(progname, LOG_PID | LOG_ODELAY, LOG_DAEMON);	
#endif /* 4.2 syslog */
    
    if (argc == 1) { /* Get parameters from program name. */
	if (strlen(progname) > MAX_PROG_NAME) {
	    usage();
	    exit(1);
	}
	options = (char *) malloc(MAX_PROG_NAME+1);
	options[0] = '\0';
	for (i = 0; (progname[i] != '\0') && (i < MAX_PROG_NAME); i++)
	  if (!strcmp(progname+i, "shd")) {
	      strcpy(options, "-");
	      strncat(options, progname, i);
	      argc = 2;
	      argv[1] = options;
	      argv[2] = NULL;
	      break;
	  }
	if (options[0] == '\0') {
	    usage();
	    exit(1);
	}
    }
    
    /* Analyse parameters. */
    opterr = 0;
    while ((ch = getopt(argc, argv, ARGSTR)) != EOF)
      switch (ch) {
	case 'r':         
	  must_pass_one = 1; /* If just 'r', any one check must succeed */
	  break;
	case 'R':         /* If 'R', must pass .rhosts check*/
	  must_pass_rhosts = 1;
	  if (must_pass_one)
	    must_pass_one = 0;
	  break;
#ifdef KERBEROS
	case 'k':
	  must_pass_one = 1; /* If just 'k', any one check must succeed */
	  break;
	case 'K':         /* If 'K', must pass .k5login check*/
	  must_pass_k5 = 1;
	  if (must_pass_one)
	    must_pass_one = 0;
	  break;
#endif
	case 'D':
	  debug_port = atoi(optarg);
	  break;
	case '?':
	default:
	  usage();
	  exit(1);
	  break;
      }
    argc -= optind;
    argv += optind;
    
    fromlen = sizeof (from);

    if (debug_port) {
	int s;
	struct sockaddr_in sin;
	
	if ((s = socket(AF_INET, SOCK_STREAM, PF_UNSPEC)) < 0) {
	    fprintf(stderr, "Error in socket: %s\n", strerror(errno));
	    exit(2);
	}
	
	bzero((char *) &sin,sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(debug_port);
	sin.sin_addr.s_addr = INADDR_ANY;
	
	if ((bind(s, (struct sockaddr *) &sin, sizeof(sin))) < 0) {
	    fprintf(stderr, "Error in bind: %s\n", strerror(errno));
	    exit(2);
	}
	
	if ((listen(s, 5)) < 0) {
	    fprintf(stderr, "Error in listen: %s\n", strerror(errno));
	    exit(2);
	}
	
	if ((fd = accept(s, &from, &fromlen)) < 0) {
	    fprintf(stderr, "Error in accept: %s\n", strerror(errno));
	    exit(2);
	}
	
	close(s);
    } else {
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
	    fprintf(stderr, "%s: ", progname);
	    perror("getpeername");
	    _exit(1);
	}
	
	fd = 0;
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
		   sizeof (on)) < 0)
      syslog(LOG_WARNING,
	     "setsockopt (SO_KEEPALIVE): %m");
#if defined(BSD) && BSD >= 43
    linger.l_onoff = 1;
    linger.l_linger = 60;			/* XXX */
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&linger,
		   sizeof (linger)) < 0)
      syslog(LOG_WARNING , "setsockopt (SO_LINGER): %m");
#endif
    doit(dup(fd), &from);
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

#ifdef KERBEROS
char    *envinit[] =
#ifdef CRAY
{homedir, shell, PATH, username, "TZ=GMT0", tmpdir, term, 0};
#define TZENV   4
#define TMPDIRENV 5
char    *getenv();
extern
#else
{homedir, shell, "PATH=:/usr/ucb:/bin:/usr/bin:/usr/bin/kerberos",
   username, term, 0};
#endif /* CRAY */
#else /* !KERBEROS */
char	*envinit[] =
#ifdef CRAY
{homedir, shell, PATH, username, "TZ=GMT0", tmpdir, term, 0};
#define TZENV   4
#define TMPDIRENV 5
char    *getenv();
extern
#else
{homedir, shell, "PATH=:/usr/ucb:/bin:/usr/bin:/usr/bin/kerberos",
   username, term, 0};
#endif /* CRAY */
#endif /* KERBEROS */

extern char	**environ;
char ttyn[12];		/* Line string for wtmp entries */

#ifdef CRAY
#define SIZEOF_INADDR  SIZEOF_in_addr
int maxlogs;
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

#define NMAX   16 

int pid;
char locuser[NMAX+1];
char remuser[NMAX +1];
char cmdbuf[NCARGS+1];
char *kremuser;
krb5_principal client;
krb5_authenticator *kdata;
krb5_ticket        *ticket = 0;

#ifdef SERVE_V4
#include <kerberosIV/krb.h>
AUTH_DAT	*v4_kdata;
KTEXT		v4_ticket;
#endif

int V4 = 0;    /* Set when connection is seen to be from a V4 client */

doit(f, fromp)
     int f;
     struct sockaddr_in *fromp;
{
    char *cp;
    
#ifdef KERBEROS
    krb5_address peeraddr;
    krb5_error_code status;
#endif

    int tmpint;
    
    int ioctlval, cnt;
    char *salt, *ttynm, *tty;
    register char *p;
    char *crypt();
    
#ifndef CRAY
    struct passwd *pwd;
#else
    struct passwd *pwd;
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
    
    int s;
    struct hostent *hp;
    char *hostname;
    short port;
    int pv[2], cc;
    long ready, readfrom;
    char buf[BUFSIZ], sig;
    int one = 1;
    krb5_sigtype     cleanup();
    int fd;
    struct sockaddr_in fromaddr;
    int non_privileged = 0;

#ifdef IP_TOS
    struct tosent *tp;

    if ((tp = gettosbyname("interactive", "tcp")) &&
	(setsockopt(f, IPPROTO_IP, IP_TOS, &tp->t_tos, sizeof(int)) < 0))
#ifdef  TOS_WARN
      syslog(LOG_NOTICE, "setsockopt (IP_TOS): %m");
#else
    ;       /* silently ignore TOS errors in 6E */
#endif
#endif /* IP_TOS */
    
    fromaddr = *fromp;

    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
#ifdef DEBUG
    { int t = open("/dev/tty", 2);
      if (t >= 0) {
	  ioctl(t, TIOCNOTTY, (char *)0);
	  (void) close(t);
      }
  }
#endif
    fromp->sin_port = ntohs((u_short)fromp->sin_port);
    if (fromp->sin_family != AF_INET) {
	syslog(LOG_ERR , "malformed from address\n");
	exit(1);
    }
#ifdef KERBEROS
    if ((must_pass_rhosts || must_pass_one)
	&& (fromp->sin_port >= IPPORT_RESERVED ||
	    fromp->sin_port < IPPORT_RESERVED/2))
      non_privileged = 1;
#else
    if (fromp->sin_port >= IPPORT_RESERVED ||
	    fromp->sin_port < IPPORT_RESERVED/2) {
	syslog(LOG_ERR , "connection from bad port\n");
	exit(1);
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
	int lport = IPPORT_RESERVED - 1;
	s = rresvport(&lport);
	if (s < 0) {
	    syslog(LOG_ERR ,
		   "can't get stderr port: %m");
	    exit(1);
	}
#ifdef KERBEROS
	if ((must_pass_rhosts || must_pass_one)
	    && port >= IPPORT_RESERVED)
	  non_privileged = 1;
#else
	if (port >= IPPORT_RESERVED) {
	    syslog(LOG_ERR , "2nd port not reserved\n");
	    exit(1);
	}
#endif /* KERBEROS */
	fromp->sin_port = htons((u_short)port);
	if (connect(s, (struct sockaddr *)fromp, sizeof (*fromp)) < 0) {
	    syslog(LOG_INFO ,
		   "connect second port: %m");
	    exit(1);
	}
    }
    dup2(f, 0);
    dup2(f, 1);
    dup2(f, 2);
    hp = gethostbyaddr((char *)&fromp->sin_addr, sizeof (struct in_addr),
		       fromp->sin_family);
    if (hp){
	hostname = malloc(strlen(hp->h_name) + 1);
	strcpy(hostname,hp->h_name);
    }
    else {
	hostname = malloc(strlen((char *)inet_ntoa(fromp->sin_addr)) + 1);
	strcpy(hostname,(char *)inet_ntoa(fromp->sin_addr));
    }
    peeraddr.addrtype = fromp->sin_family;
    peeraddr.length = SIZEOF_INADDR;
    peeraddr.contents = (krb5_octet *)&fromp->sin_addr;


#ifdef KERBEROS
    if (status = recvauth(f, fromaddr, peeraddr)) {
	error("Authentication failed: %s\n", error_message(status));
	exit(1);
    }
#else
    getstr(f, remuser, sizeof(remuser), "remuser");
    getstr(f, locuser, sizeof(locuser), "locuser");
    getstr(f, cmdbuf, sizeof(cmdbuf), "command");
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
	       "Principal %s (%s@%s) for local user %s has no account.\n",
	       kremuser, remuser, hostname, locuser);
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
	    loglogin(hostname, SLG_LLERR, 0, ue);
	    error("Permission denied.\n");
	    exit(1);
	}
	if ((packet_level != ue->ue_deflvl) ||
	    ((packet_compart & ue->ue_comparts) != packet_compart )){
	    loglogin(hostname, SLG_LLERR, 0, ue);
	    error("Permission denied.\n");
	    exit(1);
	}
	if (ue->ue_disabled != 0) {
	    loglogin(hostname,SLG_LOCK,ue->ue_logfails,ue);
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
	sprintf(ttyn,"krsh%1d",getpid());
#ifdef SYSV
	logwtmp(ttyn,locuser,hostname,1,1); /*Leave wtmp open*/
#else
	logwtmp(ttyn,locuser,hostname,1);  /*Leave wtmp open*/
#endif
    }
    /*      We are simply execing a program over rshd : log entry into wtmp,
	    as kexe(pid), then finish out the session right after that.
	    Syslog should have the information as to what was exec'd */
    else {
	sprintf(ttyn,"kexe%1d",getpid());
#ifdef SYSV
	logwtmp(ttyn,locuser,hostname,1,1);  /* Leave open wtmp */
#else
	logwtmp(ttyn,locuser,hostname,1);       /* Leave open wtmp */
#endif
    }
    
#ifdef CRAY
    
    /* If  we are a secure system then we need to get rid of our
       trusted facility, so that MAC on the chdir we work. Before we
       do this make an entry into wtmp, and any other audit recording. */
    
    if (secflag) {
	if (getusrv(&usrv)){
	    syslog(LOG_ERR,"Cannot getusrv");
	    error("Permission denied.\n");
	    loglogin(hostname, SLG_LVERR, ue->ue_logfails,ue);
	    goto signout_please;
	}
	/*
	 *      6.0 no longer allows any form ofTRUSTED_PROCESS logins.
	 */
	if((ue->ue_valcat & TFM_TRUSTED) ||
	   (sysv.sy_oldtfm &&
	    ((ue->ue_comparts & TRUSTED_SUBJECT) == TRUSTED_SUBJECT))) {
	    loglogin(hostname, SLG_TRSUB, ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    goto signout_please;
	}
	
	loglogin(hostname, SLG_OKLOG, ue->ue_logfails,ue);
	
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
	    loglogin(hostname, SLG_LVERR, ue->ue_logfails,ue);
	    error("Permission denied.\n");
	    goto signout_please;
	}
#undef  MIN
#undef  MAX
	/* Before the setusrv is done then do a sethost for paddr */
	sethost(paddr);
	
	if (setusrv(&usrv) == -1) {
	    loglogin(hostname, SLG_LVERR, ue->ue_logfails,ue);
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
	syslog(LOG_ERR ,
	       "Principal %s  (%s@%s) for local user %s has no home directory.\n",
	       kremuser, remuser, hostname, locuser);
	error("No remote directory.\n");
	goto signout_please;
    }

#ifdef KERBEROS
    if (must_pass_k5 || must_pass_one) {
#ifdef ALWAYS_V5_KUSEROK
	if (!krb5_kuserok(client,locuser)) {
	    syslog(LOG_ERR ,
		   "Principal %s (%s@%s) for local user %s failed krb5_kuserok.\n",
		   kremuser, remuser, hostname, locuser);
	    if (must_pass_k5) {
		error("Permission denied.\n");
		goto signout_please;
	    }
	    failed_k5 = 1;
	}
#else
	if (V4) {
	    /* kuserok returns 0 if OK */
	    if (kuserok(v4_kdata, locuser)){
		syslog(LOG_ERR ,
		       "Principal %s (%s@%s) for local user %s failed kuserok.\n",
		       kremuser, remuser, hostname, locuser);
		if (must_pass_k5) {
		    error("Permission denied.\n");
		    goto signout_please;
		}
		failed_k5 = 1;
	    }
	}
	else {
	    /* krb5_kuserok returns 1 if OK */
	    if (!krb5_kuserok(client, locuser)){
		syslog(LOG_ERR ,
		       "Principal %s (%s@%s) for local user %s failed krb5_kuserok.\n",
		       kremuser, remuser, hostname, locuser);
		if (must_pass_k5) {
		    error("Permission denied.\n");
		    goto signout_please;
		}
		failed_k5 = 1;
	    }
	}
#endif
    }
	
    if (must_pass_rhosts || (failed_k5 && must_pass_one)) {
	/* Cannot check .rhosts unless connection from privileged port */
	if (non_privileged) {
	    syslog(LOG_ERR , "connection from bad port\n");
	    exit(1);
	}

	if (ruserok(hostname, pwd->pw_uid == 0,
		    remuser, locuser) < 0) {
	    syslog(LOG_ERR ,
		   "Principal %s (%s@%s) for local user %s failed ruserok.\n",
		   kremuser, remuser, hostname, locuser);
	    error("Permission denied.\n");
	    goto signout_please;
	}
    }
#else
    if (pwd->pw_passwd != 0 && *pwd->pw_passwd != '\0' &&
	ruserok(hostname, pwd->pw_uid == 0, remuser, locuser) < 0) {
	error("Permission denied.\n");
	goto signout_please;
    }
#endif /* KERBEROS */
    
    if (pwd->pw_uid && !access("/etc/nologin", F_OK)) {
	error("Logins currently disabled.\n");
	goto signout_please;
    }
    
    /* Log access to account */
    pwd = (struct passwd *) getpwnam(locuser);
    if (pwd && (pwd->pw_uid == 0)) {
#ifdef LOG_CMD
	syslog(LOG_NOTICE, "Executing %s for principal %s (%s@%s) as ROOT", 
	       cmdbuf, kremuser, remuser, hostname);
#else
	syslog(LOG_NOTICE ,"Access as ROOT by principal %s (%s@%s)",
	       kremuser, remuser, hostname);
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
	  syslog(LOG_NOTICE, "Executing %s for principal %s (%s@%s) as local user %s", 
		 cmdbuf, kremuser, remuser, hostname, locuser);
#else
	  syslog(LOG_NOTICE ,"Access as %s by principal %s (%s@%s)",
		 locuser, kremuser, remuser, hostname);
#endif
      }
#endif
    
    (void) write(2, "\0", 1);
    
    if (port) {
	if (pipe(pv) < 0) {
	    error("Can't make pipe.\n");
	    goto signout_please;
	}
	pid = fork();
	if (pid == -1)  {
	    error("Try again.\n");
	    goto signout_please;
	}
	if (pid) {
	    signal(SIGINT, cleanup);
	    signal(SIGQUIT, cleanup);
	    signal(SIGTERM, cleanup);
	    signal(SIGPIPE, cleanup);
	    signal(SIGHUP, cleanup);
	    signal(SIGCHLD,SIG_IGN);
	    
	    (void) close(0); (void) close(1); (void) close(2);
	    (void) close(f); (void) close(pv[1]);
	    readfrom = (1L<<s) | (1L<<pv[0]);
	    ioctl(pv[0], FIONBIO, (char *)&one);
	    /* should set s nbio! */
	    do {
		ready = readfrom;
		if (select(16, &ready, (fd_set *)0,
			   (fd_set *)0, (struct timeval *)0) < 0)
		  break;
		if (ready & (1L<<s)) {
		    if (read(s, &sig, 1) <= 0)
		      readfrom &= ~(1L<<s);
		    else {
			signal(sig, cleanup);
			killpg(pid, sig);
		    }
		}
		if (ready & (1L<<pv[0])) {
		    errno = 0;
		    cc = read(pv[0], buf, sizeof (buf));
		    if (cc <= 0) {
			shutdown(s, 1+1);
			readfrom &= ~(1L<<pv[0]);
		    } else
		      (void) write(s, buf, cc);
		}
	    } while (readfrom);
#ifdef KERBEROS
	    syslog(LOG_INFO ,
		   "Shell process completed.");
#endif
	    /* Finish session in wmtp */
#ifdef SYSV
	    logwtmp(ttyn,"","",0,0); /* Close wtmp */
#else
	    logwtmp(ttyn,"","",0);   /* Close wtmp */
#endif
	    exit(0);
	}
	setpgrp(0, getpid());
	(void) close(s); (void) close(pv[0]);
	dup2(pv[1], 2);
	(void) close(pv[1]);
    }
    
    /*      We are simply execing a program over rshd : log entry into wtmp, 
	    as kexe(pid), then finish out the session right after that.
	    Syslog should have the information as to what was exec'd */
    else {
#ifdef SYSV
	logwtmp(ttyn,"","",0,0);		/* Close wtmp */
#else
	logwtmp(ttyn,"","",0);	 /* Close wtmp */
#endif
    }
    
    if (*pwd->pw_shell == '\0')
      pwd->pw_shell = "/bin/sh";
    (void) close(f);
    (void) setgid((gid_t)pwd->pw_gid);
#ifndef sgi
    initgroups(pwd->pw_name, pwd->pw_gid);
#endif
    (void) setuid((uid_t)pwd->pw_uid);
    environ = envinit;
    strncat(homedir, pwd->pw_dir, sizeof(homedir)-6);
    strncat(shell, pwd->pw_shell, sizeof(shell)-7);
    strncat(username, pwd->pw_name, sizeof(username)-6);
    cp = rindex(pwd->pw_shell, '/');
    if (cp)
      cp++;
    else
      cp = pwd->pw_shell;
    
    execl(pwd->pw_shell, cp, "-c", cmdbuf, 0);
    perror(pwd->pw_shell);
    perror(cp);
    exit(1);
    
  signout_please:
#ifdef SYSV
    logwtmp(ttyn,"","",0,0);                /* Close wtmp */
#else
    logwtmp(ttyn,"","",0);   /* Close wtmp */
#endif
    exit(1);
}
    


/*VARARGS1*/
error(fmt, a1, a2, a3)
     char *fmt;
     int a1, a2, a3;
{
    char buf[BUFSIZ];
    
    buf[0] = 1;
    (void) sprintf(buf+1, "%s: ", progname);
    (void) sprintf(buf+strlen(buf), fmt, a1, a2, a3);
    (void) write(2, buf, strlen(buf));
    syslog(LOG_ERR ,"%s",buf+1);
}



getstr(fd, buf, cnt, err)
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



krb5_sigtype 
  cleanup()
{
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    killpg(pid, SIGTERM);
    wait(0);
    
#ifdef SYSV
    logwtmp(ttyn,"","",0,0); /* Close wtmp */
#else
    logwtmp(ttyn,"","",0);   /* Close wtmp */
#endif
    syslog(LOG_INFO ,"Shell process completed.");
    exit(0);
}



#ifdef	CRAY
char *makejtmp(uid, gid, jid)
     register int uid, gid, jid;
{
    extern int errno;
    
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

#endif	CRAY
	


usage()
{
#ifdef KERBEROS
    syslog(LOG_ERR, "usage: kshd [-rRkK] or [r/R][k/K]shd");
#else
    syslog(LOG_ERR, "usage: rshd");
#endif
}



int princ_maps_to_lname(principal, luser)	
     krb5_principal principal;
     char *luser;
{
    char kuser[10];
    if (!(krb5_aname_to_localname(principal,
				  sizeof(kuser), kuser))
	&& (strcmp(kuser, luser) == 0)) {
	return 1;
    }
    return 0;
}


int default_realm(principal)
     krb5_principal principal;
{
    char *def_realm;
    int realm_length;
    int retval;
    
    realm_length = krb5_princ_realm(principal)->length;
    
    if (retval = krb5_get_default_realm(&def_realm)) {
	return 0;
    }
    
    if ((realm_length != strlen(def_realm)) ||
	(memcmp(def_realm, krb5_princ_realm(principal)->data, realm_length))) {
	free(def_realm);
	return 0;
    }	
    free(def_realm);
    return 1;
}

#ifdef KERBEROS

#ifndef KRB_SENDAUTH_VLEN
#define	KRB_SENDAUTH_VLEN 8	    /* length for version strings */
#endif

#define	KRB_SENDAUTH_VERS	"AUTHV0.1" /* MUST be KRB_SENDAUTH_VLEN
					      chars */

krb5_error_code
recvauth(netf, peersin, peeraddr)
     int netf;
     struct sockaddr_in peersin;
     krb5_address peeraddr;
{
    char hostname[100];
    krb5_principal server;
    krb5_error_code status;
    char krb_vers[KRB_SENDAUTH_VLEN + 1];
    int len;

    len = sizeof(int);
    if ((status = krb5_net_read(netf, krb_vers, len)) != len)
      return((status < 0) ? errno : ECONNABORTED);

    krb_vers[len] = '\0';

    if (!strncmp(krb_vers, KRB_SENDAUTH_VERS, len)) {
	/* Must be V4 rlogin client */
#ifdef SERVE_V4
	char version[9];
	struct sockaddr_in faddr;
	char instance[INST_SZ];
	long authoptions;
	int len;
	
	V4 = 1;

	authoptions = 0L;
	
	len = sizeof(faddr);
	if (getsockname(0, (struct sockaddr *)&faddr, &len)) {
	    exit(1);
	}

	v4_kdata = (AUTH_DAT *)malloc( sizeof(AUTH_DAT) );
	v4_ticket = (KTEXT) malloc(sizeof(KTEXT_ST));

	strcpy(instance, "*");

	if (status = v4_recvauth(krb_vers, authoptions, netf,
				 v4_ticket, "rcmd",
				 instance, &peersin, &faddr,
				 v4_kdata, "", (bit_64 *)0, version)) {
	    return(status);
	}

	getstr(netf, locuser, sizeof (locuser), "locuser");
	getstr(netf, cmdbuf, sizeof(cmdbuf), "command");
	/* We do not really know the remote user's login name.
         * Assume it to be the same as the first component of the
	 * principal's name. 
         */
	strcpy(remuser, v4_kdata->pname);
	kremuser = (char *) malloc(strlen(v4_kdata->pname) + 1 +
				     strlen(v4_kdata->pinst) + 1 +
				     strlen(v4_kdata->prealm) + 1);
	sprintf(kremuser, "%s/%s@%s", v4_kdata->pname,
		v4_kdata->pinst, v4_kdata->prealm);

	if (status = krb5_parse_name(kremuser, &client))
	  return(status);
#else
	syslog(LOG_ERR, "Kerberos V4 authentication: rejected!");
	error("Permission denied");
#endif
    }
    else if (isprint(krb_vers[0])) { 
	/* Un-kerberized rlogin client */
#ifdef SERVE_NON_KRB
	strncpy(remuser, krb_vers, sizeof(int));
	getstr(netf, remuser+4, sizeof(remuser)-sizeof(int), "remuser");
	getstr(netf, locuser, sizeof(locuser), "locuser");
	getstr(netf, cmdbuf, sizeof(cmdbuf), "command");	
#else
	syslog(LOG_ERR, "Un-kerberized client: authentication rejected!");
	error( "Permission denied");
#endif
    }
    else {
	/* Must be V5 rlogin client */
	krb5_principal server;
	krb5_data inbuf;
	int len;

	/*
	 * First read the sendauth version string and check it.
	 */
	inbuf.length = ntohl(*((int *) krb_vers));

	if (inbuf.length < 0 || inbuf.length > 25)
	  return 255;
	
	if (!(inbuf.data = malloc(inbuf.length))) {
	    return(ENOMEM);
	}
	
	if ((len = krb5_net_read(netf, inbuf.data, inbuf.length)) !=
	    inbuf.length) {
	    xfree(inbuf.data);
	    return((len < 0) ? errno : ECONNABORTED);
	}

	if (strcmp(inbuf.data, "KRB5_SENDAUTH_V1.0")) {
	    xfree(inbuf.data);
	    status = KRB5_SENDAUTH_BADAUTHVERS;
	    return status;
	}
	xfree(inbuf.data);

#ifdef unicos61
#define SIZEOF_INADDR  SIZEOF_in_addr
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

	gethostname(hostname, 100);
	if (status = krb5_sname_to_principal(hostname,"host", KRB5_NT_SRV_HST,
					     &server)) {
	    syslog(LOG_ERR, "parse server name %s: %s", "host",
		   error_message(status));
	    exit(1);
	}
	krb5_princ_type(server) = KRB5_NT_SRV_HST;

	krb5_init_ets();
	
	if (status = v5_recvauth(&netf,
				 "KCMDV0.1",
				 server,    /* Specify daemon principal */
				 &peeraddr, /* We do want to match this
					       against caddrs in the
					       ticket. */
				 0,         /* use srv5tab */
				 0,         /* no keyproc */
				 0,         /* no keyproc arg */
				 0,         /* no rc_type */
				 0,         /* no seq number */
				 &client,   /* return client */
				 &ticket,   /* return ticket */
				 &kdata     /* return authenticator */
				 )) {
	    error("Kerberos rsh or rcp failed: %s\n",
		  error_message(status));
	    exit(1);
	}
	krb5_unparse_name(kdata->client,&kremuser);
	    
	getstr(netf, locuser, sizeof(locuser), "locuser");
	getstr(netf, cmdbuf, sizeof(cmdbuf), "command");
	getstr(netf, remuser, sizeof(locuser), "remuser");

	if (status = krb5_read_message((krb5_pointer)&netf, &inbuf)) {
	    error("Error reading message: %s\n",
		  error_message(status));
	    exit(1);
	}

	if (inbuf.length) {
	    if (status = rd_and_store_for_creds(&inbuf, ticket, locuser)) {
		error("Can't get forwarded credentials: %s\n",
		      error_message(status));
		exit(1);
	    }
	}
    }
    return 0;
}

#ifdef SERVE_V4

#ifndef max
#define	max(a,b) (((a) > (b)) ? (a) : (b))
#endif /* max */

krb5_error_code
v4_recvauth(krb_vers, options, fd, ticket, service, instance, faddr,
	    laddr, kdata, filename, schedule, version)
     char *krb_vers;
     long options;			 /* bit-pattern of options */
     int fd;				 /* file descr. to read from */
     KTEXT ticket;			 /* storage for client's ticket */
     char *service;			 /* service expected */
     char *instance;			 /* inst expected (may be filled in) */
     struct sockaddr_in *faddr;	 /* address of foreign host on fd */
     struct sockaddr_in *laddr;	 /* local address */
     AUTH_DAT *kdata;		 /* kerberos data (returned) */
     char *filename;			 /* name of file with service keys */
     Key_schedule schedule;		 /* key schedule (return) */
     char *version;			 /* version string (filled in) */
{
    
    int i, cc, old_vers = 0;
    char *cp;
    int rem;
    long tkt_len, priv_len;
    u_long cksum;
    u_char tmp_buf[MAX_KTXT_LEN+max(KRB_SENDAUTH_VLEN+1,21)];
    
    /* read the protocol version number */
    if (krb_net_read(fd, krb_vers+sizeof(int), 
		     KRB_SENDAUTH_VLEN-sizeof(int)) !=
	KRB_SENDAUTH_VLEN-sizeof(int))
      return(errno);
    krb_vers[KRB_SENDAUTH_VLEN] = '\0';
    
    /* check version string */
    if (strcmp(krb_vers,KRB_SENDAUTH_VERS)) {
	return(KFAILURE);
    } else {
	/* read the application version string */
	if (krb_net_read(fd, version, KRB_SENDAUTH_VLEN) !=
	    KRB_SENDAUTH_VLEN)
	  return(errno);
	version[KRB_SENDAUTH_VLEN] = '\0';
	
	/* get the length of the ticket */
	if (krb_net_read(fd, (char *)&tkt_len, sizeof(tkt_len)) !=
	    sizeof(tkt_len))
	  return(errno);
	
	/* sanity check */
	ticket->length = ntohl((unsigned long)tkt_len);
	if ((ticket->length <= 0) || (ticket->length > MAX_KTXT_LEN)) {
	    if (options & KOPT_DO_MUTUAL) {
		rem = KFAILURE;
		goto mutual_fail;
	    } else
	      return(KFAILURE); /* XXX there may still be junk on the fd? */
	}
	
	/* read the ticket */
	if (krb_net_read(fd, (char *) ticket->dat, ticket->length)
	    != ticket->length)
	  return(errno);
    }
    /*
     * now have the ticket.  decrypt it to get the authenticated
     * data.
     */
    rem = krb_rd_req(ticket,service,instance,faddr->sin_addr.s_addr,
		     kdata,filename);
    
    if (old_vers) return(rem);	 /* XXX can't do mutual with old client */
    
    /* if we are doing mutual auth (used by erlogin), compose a response */
    if (options & KOPT_DO_MUTUAL) {
	if (rem != KSUCCESS)
	  /* the krb_rd_req failed */
	  goto mutual_fail;
	
	/* add one to the (formerly) sealed checksum, and re-seal it
	   for return to the client */
	cksum = kdata->checksum + 1;
	cksum = htonl(cksum);
#ifdef CRYPT
	key_sched(kdata->session,schedule);
#endif
	priv_len = krb_mk_priv((unsigned char *)&cksum,
			       tmp_buf,
			       (unsigned long) sizeof(cksum),
			       schedule,
			       kdata->session,
			       laddr,
			       faddr);
	if (priv_len < 0) {
	    /* re-sealing failed; notify the client */
	    rem = KFAILURE;	 /* XXX */
	  mutual_fail:
	    priv_len = -1;
	    tkt_len = htonl((unsigned long) priv_len);
	    /* a length of -1 is interpreted as an authentication
	       failure by the client */
	    if ((cc = krb_net_write(fd, (char *)&tkt_len, sizeof(tkt_len)))
		!= sizeof(tkt_len))
	      return(cc);
	    return(rem);
	} else {
	    /* re-sealing succeeded, send the private message */
	    tkt_len = htonl((unsigned long)priv_len);
	    if ((cc = krb_net_write(fd, (char *)&tkt_len, sizeof(tkt_len)))
		!= sizeof(tkt_len))
	      return(cc);
	    if ((cc = krb_net_write(fd, (char *)tmp_buf, (int) priv_len))
		!= (int) priv_len)
	      return(cc);
	}
    }
    return(0);
}

#endif /* SERVE_V4 */

extern krb5_flags	krb5_kdc_default_options;

krb5_error_code
v5_recvauth(/* IN */
	    fd, appl_version, server, sender_addr, fetch_from,
	    keyproc, keyprocarg, rc_type, 
	    /* OUT */
	    seq_number, client, ticket, authent)
     krb5_pointer	fd;
     char	*appl_version;
     krb5_principal	server;
     krb5_address	*sender_addr;
     krb5_pointer	fetch_from;
     krb5_int32	*seq_number;
     char		*rc_type;
     krb5_rdreq_key_proc keyproc;
     krb5_pointer keyprocarg;
     krb5_principal	*client;
     krb5_ticket	**ticket;
     krb5_authenticator	**authent;
{
    krb5_error_code	retval, problem;
    krb5_data	inbuf;
    krb5_tkt_authent	*authdat;
    krb5_data		outbuf;
    krb5_rcache rcache;
    krb5_octet		response;
    krb5_data	*server_name;
    char *cachename;
    extern krb5_deltat krb5_clockskew;
    static char		*rc_base = "rc_";
    
    /*
     * Zero out problem variable.  If problem is set at the end of
     * the intial version negotiation section, it means that we
     * need to send an error code back to the client application
     * and exit.
     */
    problem = 0;
  
    /*
     * Read and check the application version string.
     */
    if (retval = krb5_read_message(fd, &inbuf))
      return(retval);
    if (strcmp(inbuf.data, appl_version)) {
	xfree(inbuf.data);
	if (!problem)
	  problem = KRB5_SENDAUTH_BADAPPLVERS;
    }
    xfree(inbuf.data);
    /*
     * OK, now check the problem variable.  If it's zero, we're
     * fine and we can continue.  Otherwise, we have to signal an
     * error to the client side and bail out.
     */
    switch (problem) {
      case 0:
	response = 0;
	break;
      case KRB5_SENDAUTH_BADAUTHVERS:
	response = 1;
	break;
      case KRB5_SENDAUTH_BADAPPLVERS:
	response = 2;
	break;
      default:
	/*
	 * Should never happen!
	 */
	response = 255;
#ifdef SENDAUTH_DEBUG
	fprintf(stderr, "Programming botch in recvauth!  problem = %d",
		problem);
	abort();
#endif
	break;
    }

    /*
     * Now we actually write the response.  If the response is non-zero,
     * exit with a return value of problem
     */
    if ((krb5_net_write(*((int *) fd), (char *)&response, 1)) < 0) {
	return(problem); /* We'll return the top-level problem */
    }
    if (problem)
      return(problem);
    rcache = NULL;
#ifdef WORKING_RCACHE
    /*
     * Setup the replay cache.
     */
    if (!(rcache = (krb5_rcache) malloc(sizeof(*rcache)))) 
      problem = ENOMEM;
    if (!problem) 
      problem = krb5_rc_resolve_type(&rcache,
				     rc_type ? rc_type : "dfl");
    cachename = NULL;
    server_name = krb5_princ_component(server, 0);
    if (!problem && !(cachename = malloc(server_name->length+1+strlen(rc_base))))
      problem = ENOMEM;
    if (!problem) {
	strcpy(cachename, rc_base ? rc_base : "rc_");
	strncat(cachename, server_name->data, server_name->length);
	cachename[server_name->length+strlen(rc_base)] = '\0';
	problem = krb5_rc_resolve(rcache, cachename);
    }
    if (!problem) {
	if (krb5_rc_recover(rcache))
	  /*
	   * If the rc_recover didn't work, then try
	   * initializing the replay cache.
	   */
	  problem = krb5_rc_initialize(rcache, krb5_clockskew);
	if (problem) {
	    krb5_rc_close(rcache);
	    rcache = NULL;
	}
    }
#endif

    /*
     * Now, let's read the AP_REQ message and decode it
     */
    if (retval = krb5_read_message(fd, &inbuf)) {
#ifdef WORKING_RCACHE		
	(void) krb5_rc_close(rcache);
	if (cachename)
	  free(cachename);
#endif
	return(retval);
    }
    authdat = 0;			/* so we can tell if we need to
					   free it later... */
    if (!problem)
      problem = krb5_rd_req(&inbuf, server, sender_addr, fetch_from,
			    keyproc, keyprocarg, rcache, &authdat);
    xfree(inbuf.data);
#ifdef WORKING_RCACHE
    if (rcache)
      retval = krb5_rc_close(rcache);
#endif
    if (!problem && retval)
      problem = retval;
#ifdef WORKING_RCACHE
    if (cachename)
      free(cachename);
#endif
    
    /*
     * If there was a problem, send back a krb5_error message,
     * preceeded by the length of the krb5_error message.  If
     * everything's ok, send back 0 for the length.
     */
    if (problem) {
	krb5_error	error;
	const	char *message;
	
	memset((char *)&error, 0, sizeof(error));
	krb5_us_timeofday(&error.stime, &error.susec);
	error.server = server;
	error.error = problem - ERROR_TABLE_BASE_krb5;
	if (error.error > 127)
	  error.error = KRB_ERR_GENERIC;
	message = error_message(problem);
	error.text.length  = strlen(message) + 1;
	if (!(error.text.data = malloc(error.text.length)))
	  return(ENOMEM);
	strcpy(error.text.data, message);
	if (retval = krb5_mk_error(&error, &outbuf)) {
	    free(error.text.data);
	    return(retval);
	}
	free(error.text.data);
    } else {
	outbuf.length = 0;
	outbuf.data = 0;
    }
    if (retval = krb5_write_message(fd, &outbuf)) {
	if (outbuf.data)
	  xfree(outbuf.data);
	if (!problem)
	  krb5_free_tkt_authent(authdat);
	return(retval);
    }
    if (problem) {
	/*
	 * We sent back an error, we need to return
	 */
	if (authdat) krb5_free_tkt_authent(authdat);
	return(problem);
    }

    /*
     * Here lies the mutual authentication stuff...
     *
     * We're going to compose and send a AP_REP message.
     */
    if ((authdat->ap_options & AP_OPTS_MUTUAL_REQUIRED)) {
	krb5_ap_rep_enc_part	repl;
	
	/*
	 * Generate a random sequence number
	 */
	if (seq_number &&
	    (retval = krb5_generate_seq_number(authdat->ticket->enc_part2->session,
					       seq_number))) {
	    krb5_free_tkt_authent(authdat);
	    return(retval);
	}
	
	repl.ctime = authdat->authenticator->ctime;
	repl.cusec = authdat->authenticator->cusec;
	repl.subkey = authdat->authenticator->subkey;
	if (seq_number)
	  repl.seq_number = *seq_number;
	else
	  repl.seq_number = 0;
	
	if (retval = krb5_mk_rep(&repl,
				 authdat->ticket->enc_part2->session,
				 &outbuf)) {
	    krb5_free_tkt_authent(authdat);
	    return(retval);
	}
	if (retval = krb5_write_message(fd, &outbuf)) {
	    xfree(outbuf.data);
	    krb5_free_tkt_authent(authdat);
	    return(retval);
	}
	xfree(outbuf.data);
    }
    
    /*
     * At this point, we've won.  We just need to copy whatever
     * parts of the authdat structure which the user wants, clean
     * up, and exit.
     */
    if (client)
      if (retval =
	  krb5_copy_principal(authdat->ticket->enc_part2->client,
			      client))
	return(retval);
    /*
     * The following efficiency hack assumes knowledge about the
     * structure of krb5_tkt_authent.  If we later add additional
     * allocated substructures to krb5_tkt_authent, they will have
     * to be reflected here; otherwise, we will probably have a
     * memory leak.
     *
     * If the user wants that part of the authdat structure,
     * return it; otherwise free it.
     */
    if (ticket)
      *ticket = authdat->ticket;
    else
      krb5_free_ticket(authdat->ticket);
    if (authent)
      *authent = authdat->authenticator;
    else
      krb5_free_authenticator(authdat->authenticator);
    xfree(authdat);
    return 0;
}

#endif /* KERBEROS */
