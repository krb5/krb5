/*
 * kadmin/v4server/admin_server.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Top-level loop of the kerberos Administration server
 */

#include <mit-copyright.h>
/*
  admin_server.c
  this holds the main loop and initialization and cleanup code for the server
*/

#ifdef _AIX
#include <sys/select.h>
#endif

/* define it for now */
#ifndef POSIX_SIGNALS
#define POSIX_SIGNALS
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef POSIX_SIGNALS
#ifndef sigmask
#define sigmask(m)	(1 <<((m)-1))
#endif
#endif /* POSIX_SIGNALS */
#include <sys/wait.h>
#include <errno.h>
#include <sys/time.h>
#include <syslog.h>

#ifdef KADM5
#include <kadm5/admin.h>
void *kadm5_handle;
kadm5_config_params paramsin, paramsout;
#endif

#include "k5-int.h"
#include <kadm.h>
#include <kadm_err.h>
#include <krb_db.h>
#include "com_err.h"
#include "kadm_server.h"

#ifdef POSIX_SIGTYPE
#define SIGNAL_RETURN return
#else
#define SIGNAL_RETURN return(0)
#endif

/* Almost all procs and such need this, so it is global */
admin_params prm;		/* The command line parameters struct */

char prog[32];			/* WHY IS THIS NEEDED??????? */
char *progname = prog;
char *acldir = DEFAULT_ACL_DIR;
char krbrlm[REALM_SZ];
extern Kadm_Server server_parm;
krb5_context kadm_context;
int debug;

static void cleanexit(int);
static int kadm_listen(void);
static void process_client(int, struct sockaddr_in *);
static void kill_children(void);
static krb5_sigtype do_child(int);


/* close the system log file */
static void close_syslog()
{
   syslog(LOG_INFO, "Shutting down V4 admin server");
}

static void byebye()			/* say goodnight gracie */
{
   printf("Admin Server (kadm server) has completed operation.\n");
}

/*
** Main does the logical thing, it sets up the database and RPC interface,
**  as well as handling the creation and maintenance of the syslog file...
*/
int
main(argc, argv)		/* admin_server main routine */
int argc;
char *argv[];
{
    int errval;
    int c;
    char *lrealm;
    extern char *optarg;
    extern int fascist_cpw;
    krb5_error_code retval;
    
#ifdef KADM5
    memset(&paramsin, 0, sizeof(paramsin));
#endif

    retval = krb5_init_context(&kadm_context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
	exit(1);
    }
    initialize_kadm_error_table();
    prog[sizeof(prog)-1]='\0';		/* Terminate... */
    (void) strncpy(prog, argv[0], sizeof(prog)-1);

    /* initialize the admin_params structure */
    prm.sysfile = KADM_SYSLOG;		/* default file name */
    prm.inter = 1;

    memset(krbrlm, 0, sizeof(krbrlm));

    fascist_cpw = 1;		/* by default, enable fascist mode */
    while ((c = getopt(argc, argv, "Df:hnd:a:r:FNk:")) != -1)
	switch(c) {
	case 'D':
	    debug++;
	    break;
	case 'f':			/* Syslog file name change */
	    prm.sysfile = optarg;
	    break;
	case 'n':
	    prm.inter = 0;
	    break;
	case 'a':			/* new acl directory */
	    acldir = optarg;
	    break;
	case 'd':
#ifdef KADM5
	    paramsin.dbname = optarg;
	    paramsin.mask |= KADM5_CONFIG_DBNAME;
#else
	    if (errval = krb5_db_set_name(kadm_context, optarg)) {
		com_err(argv[0], errval, "while setting dbname");
		exit(1);
	    }
#endif
	    break;
        case 'F':
	    fascist_cpw++;
	    break;
        case 'N':
	    fascist_cpw = 0;
	    break;
	case 'r':
	    if (strlen (optarg) + 1 > REALM_SZ) {
		com_err(argv[0], 0, "realm name `%s' too long", optarg);
		exit(1);
	    }
	    (void) strncpy(krbrlm, optarg, sizeof(krbrlm) - 1);
	    break;
        case 'k':
#ifdef KADM5
	    paramsin.admin_keytab = optarg;
	    paramsin.mask |= KADM5_CONFIG_ADMIN_KEYTAB;
#endif
	    break;
        case 'h':			/* get help on using admin_server */
	default:
	    printf("Usage: admin_server [-h] [-n] [-F] [-N] [-r realm] [-d dbname] [-f filename] [-a acldir]\n");
	    exit(-1);			/* failure */
	}

    if (krbrlm[0] == 0) {
	errval = krb5_get_default_realm(kadm_context, &lrealm);
	if (errval) {
	    com_err(argv[0], errval, "while attempting to get local realm");
	    exit(1);
	}
	(void) strncpy(krbrlm, lrealm, sizeof(krbrlm) - 1);
    }

#ifdef KADM5
    paramsin.realm = krbrlm;
    paramsin.mask |= KADM5_CONFIG_REALM;

    errval = kadm5_get_config_params(kadm_context, NULL, NULL,
				     &paramsin, &paramsout);
    if (errval) {
	 com_err(argv[0], errval, "while retrieving kadm5 params");
	 exit(1);
    }

    errval = krb5_db_set_name(kadm_context, paramsout.dbname);
    if (errval) {
	 com_err(argv[0], errval, "while setting dbname");
	 exit(1);
    }
#endif /* KADM5 */

    printf("KADM Server %s initializing\n",KADM_VERSTR);
    printf("Please do not use 'kill -9' to kill this job, use a\n");
    printf("regular kill instead\n\n");

#ifdef KADM5
    printf("KADM Server starting in the KADM5 mode (%sprocess id %ld).\n",
	   debug ? "" : "parent ", (long) getpid());
#else
    printf("KADM Server starting in %s mode for the purposes for password changing\n\n", fascist_cpw ? "fascist" : "NON-FASCIST");
#endif
    
    openlog(argv[0], LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6); /* XXX */
    syslog(LOG_INFO, "V4 admin server starting");

    errval = krb5_db_init(kadm_context);  /* Open the Kerberos database */
    if (errval) {
	fprintf(stderr, "error: krb5_db_init() failed");
	close_syslog();
	byebye();
	exit(1);
    }

    errval = krb5_db_set_lockmode(kadm_context, TRUE);
    if (errval) {
	com_err(argv[0], errval, "while setting db to nonblocking");
	close_syslog();
	krb5_db_fini(kadm_context);
	byebye();
	exit(1);
    }
    /* set up the server_parm struct */
    if ((errval = kadm_ser_init(prm.inter, krbrlm
#ifdef KADM5
				, &paramsout
#endif
				))==KADM_SUCCESS) {
	krb5_db_fini(kadm_context);	/* Close the Kerberos database--
					   will re-open later */
	errval = kadm_listen();		/* listen for calls to server from
					   clients */
    }
    if (errval != KADM_SUCCESS) {
	fprintf(stderr,"error:  %s\n",error_message(errval));
	krb5_db_fini(kadm_context);	/* Close if error */
    }
    close_syslog();			/* Close syslog file, print
					   closing note */
    byebye();				/* Say bye bye on the terminal
					   in use */
    return 0;
}					/* procedure main */


static void clear_secrets()
{
    memset((char *)server_parm.master_keyblock.contents, 0,
	   server_parm.master_keyblock.length);
    server_parm.mkvno = 0L;
    return;
}

static int exit_now = 0;

static krb5_sigtype
doexit(sig)
	int sig;
{
    exit_now = 1;
    SIGNAL_RETURN;
}
   
unsigned pidarraysize = 0;
int *pidarray = (int *)0;
int unknown_child = 0;

/*
kadm_listen
listen on the admin servers port for a request
*/
static int
kadm_listen()
{
    int found;
    int admin_fd;
    int peer_fd;
    fd_set mask, readfds;
    struct sockaddr_in peer;
    socklen_t addrlen;
    int pid;
#ifdef POSIX_SIGNALS
    struct sigaction new_act;

    new_act.sa_handler = doexit;
    new_act.sa_flags = 0;
    sigemptyset(&new_act.sa_mask);
    sigaction(SIGINT, &new_act, 0);
    sigaction(SIGTERM, &new_act, 0);
    sigaction(SIGHUP, &new_act, 0);
    sigaction(SIGQUIT, &new_act, 0);
    sigaction(SIGALRM, &new_act, 0);
    new_act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &new_act, 0);
    new_act.sa_handler = do_child;
    sigaction(SIGCHLD, &new_act, 0);
#else
    signal(SIGINT, doexit);
    signal(SIGTERM, doexit);
    signal(SIGHUP, doexit);
    signal(SIGQUIT, doexit);
    signal(SIGPIPE, SIG_IGN); /* get errors on write() */
    signal(SIGALRM, doexit);
    signal(SIGCHLD, do_child);
#endif

    if ((admin_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	return KADM_NO_SOCK;
    if (debug) {
	 int one = 1;
	 if (setsockopt(admin_fd, SOL_SOCKET, SO_REUSEADDR, &one,
			sizeof(int)) < 0) { 
	      syslog(LOG_ERR, "setsockopt: %m");
	      return KADM_NO_BIND;
	 }
    }
    if (bind(admin_fd, (struct sockaddr *)&server_parm.admin_addr,
	     sizeof(struct sockaddr_in)) < 0) {
	 syslog(LOG_ERR, "bind: %m");
	 return KADM_NO_BIND;
    }
    (void) listen(admin_fd, 1);
    FD_ZERO(&mask);
    FD_SET(admin_fd, &mask);

    for (;;) {				/* loop nearly forever */
	if (exit_now) {
	    clear_secrets();
	    kill_children();
	    return(0);
	}
	readfds = mask;
	if ((found = select(admin_fd+1,&readfds,(fd_set *)0,
			    (fd_set *)0, (struct timeval *)0)) == 0)
	    continue;			/* no things read */
	if (found < 0) {
	    if (errno != EINTR)
		syslog(LOG_ERR, "select: %s", error_message(errno));
	    continue;
	}      
	if (FD_ISSET(admin_fd, &readfds)) {
	    /* accept the conn */
	    addrlen = sizeof(peer);
	    if ((peer_fd = accept(admin_fd, (struct sockaddr *)&peer,
				  &addrlen)) < 0) {
		syslog(LOG_ERR, "accept: %s", error_message(errno));
		continue;
	    }

	    if (debug) {
		 process_client(peer_fd, &peer);
	    } else if ((pid = fork())) {
		/* parent */
		if (pid < 0) {
		    syslog(LOG_ERR, "fork: %s", error_message(errno));
		    (void) close(peer_fd);
		    continue;
		}
		/* fork succeeded: keep tabs on child */
		(void) close(peer_fd);
	  	if (unknown_child != pid) {
		    if (pidarray) {
			pidarray = (int *)realloc((char *)pidarray, 
					(++pidarraysize * sizeof(int)));
			pidarray[pidarraysize-1] = pid;
		    } else {
			pidarray = (int *)malloc((pidarraysize = 1) * sizeof(int));
			pidarray[0] = pid;
		    }
		}	/* End if unknown_child != pid.*/
	    } else {
		/* child */
		(void) close(admin_fd);
		 process_client(peer_fd, &peer);
	    }
        } else {
	    syslog(LOG_ERR, "something else woke me up!");
	    return(0);
	}
    }
    /*NOTREACHED*/
}

static void process_client(fd, who)
   int fd;
   struct sockaddr_in *who;
{
    u_char *dat;
    int dat_len;
    u_short dlen;
    int retval;
    int on = 1;
    int nentries = 1;
    krb5_db_entry sprinc_entries;
    krb5_boolean more;
    krb5_keyblock cpw_skey;
    krb5_key_data *kdatap;
    int status;

#ifdef KADM5
    char *service_name;

    service_name = (char *) malloc(strlen(server_parm.sname) +
				   strlen(server_parm.sinst) +
				   strlen(server_parm.krbrlm) + 3);
    if (service_name == NULL) {
	 syslog(LOG_ERR, "error: out of memory allocating service name");
	 cleanexit(1);
    }
    sprintf(service_name, "%s@%s", KADM5_ADMIN_SERVICE, paramsin.realm);

    retval = kadm5_init_with_skey(service_name,
				  paramsout.admin_keytab,
				  KADM5_ADMIN_SERVICE,
				  &paramsin,
				  KADM5_STRUCT_VERSION,
				  KADM5_API_VERSION_2,
				  &kadm5_handle);
    if (retval) {
	 syslog(LOG_ERR, "error: kadm5_init failed: %s",
		 error_message(retval));
	 cleanexit(1);
    }
    free(service_name);

    retval = krb5_db_set_name(kadm_context, paramsout.dbname);
    if (retval) {
	 syslog(LOG_ERR, "%s while setting dbname", error_message(retval));
	 cleanexit(1);
    }
#endif
    
#ifndef NOENCRYPTION
    /* Must do it here, since this is after the fork() call */
    des_init_random_number_generator(server_parm.master_keyblock.contents);
#endif /* NOENCRYPTION */
    
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (const char *) &on, sizeof(on)) < 0)
	syslog(LOG_ERR, "setsockopt keepalive: %d", errno);

    server_parm.recv_addr = *who;

    retval = krb5_db_init(kadm_context);
    if (retval) {	/* Open as client */
	syslog(LOG_ERR, "can't open krb db: %s", error_message(retval));
	cleanexit(1);
    }
    /* need to set service key to changepw.KRB_MASTER */

    status = krb5_db_get_principal(kadm_context, server_parm.sprinc,
				   &sprinc_entries,
				   &nentries, &more);
    /* ugh... clean this up later */
    if (status == KRB5_KDB_DB_INUSE) {
	/* db locked */
	krb5_ui_4 retcode;
	char *pdat;
	
	dat_len = KADM_VERSIZE + sizeof(krb5_ui_4);
	dat = (u_char *) malloc((unsigned)dat_len);
	pdat = (char *) dat;
	retcode = htonl((krb5_ui_4) KADM_DB_INUSE);
	(void) strncpy(pdat, KADM_ULOSE, KADM_VERSIZE);
	memcpy(&pdat[KADM_VERSIZE], (char *)&retcode, sizeof(krb5_ui_4));
	goto out;
    } else if (!nentries) {
	syslog(LOG_ERR, "no service %s.%s", server_parm.sname, server_parm.sinst);
	cleanexit(2);
    } else if (status) {
	syslog(LOG_ERR, error_message(status));
	cleanexit(2);
    }

    status = krb5_dbe_find_enctype(kadm_context,
				   &sprinc_entries,
				   ENCTYPE_DES_CBC_MD5,
				   -1,
				   -1,
				   &kdatap);
    if (status) {
	syslog(LOG_ERR, "find enctype failed: %s", error_message(status));
	cleanexit(1);
    }

    status = krb5_dbekd_decrypt_key_data(kadm_context,
					 &server_parm.master_keyblock,
					 kdatap,
					 &cpw_skey,
					 (krb5_keysalt *) NULL);
    if (status) {
	syslog(LOG_ERR, "decrypt_key failed: %s", error_message(status));
	cleanexit(1);
    }
    /* if error, will show up when rd_req fails */
    (void) krb_set_key((char *)cpw_skey.contents, 0); 
    while (1) {
	if ((retval = krb_net_read(fd, (char *)&dlen, sizeof(u_short))) !=
	    sizeof(u_short)) {
	    if (retval < 0)
		syslog(LOG_ERR, "dlen read: %s", error_message(errno));
	    else if (retval)
		syslog(LOG_ERR, "short dlen read: %d", retval);
	    (void) close(fd);
#ifdef KADM5
	    (void) kadm5_destroy(kadm5_handle);
#endif
	    cleanexit(retval ? 3 : 0);
	}
	if (exit_now) {
	    cleanexit(0);
	}
	dat_len = (int) ntohs(dlen);
	dat = (u_char *) malloc((unsigned)dat_len);
	if (!dat) {
	    syslog(LOG_ERR, "malloc: No memory");
	    (void) close(fd);
	    cleanexit(4);
	}
	if ((retval = krb_net_read(fd, (char *)dat, dat_len)) != dat_len) {
	    if (retval < 0)
		syslog(LOG_ERR, "data read: %s", error_message(errno));
	    else
		syslog(LOG_ERR, "short read: %d vs. %d", dat_len, retval);
	    (void) close(fd);
	    cleanexit(5);
	}
    	if (exit_now) {
	    cleanexit(0);
	}
	if ((retval = kadm_ser_in(&dat,&dat_len)) != KADM_SUCCESS)
	    syslog(LOG_ERR, "processing request: %s", error_message(retval));
    
	/* kadm_ser_in did the processing and returned stuff in
	   dat & dat_len , return the appropriate data */
    
    out:
	dlen = (u_short) dat_len;

	if (dat_len != (int)dlen) {
	    clear_secrets();
	    abort();			/* XXX */
	}
	dlen = htons(dlen);
    
	if (krb_net_write(fd, (char *)&dlen, sizeof(u_short)) < 0) {
	    syslog(LOG_ERR, "writing dlen to client: %s", error_message(errno));
	    (void) close(fd);
	    cleanexit(6);
	}
    
	if (krb_net_write(fd, (char *)dat, dat_len) < 0) {
	    syslog(LOG_ERR, "writing to client: %s", error_message(errno));
	    (void) close(fd);
	    cleanexit(7);
	}
	free((char *)dat);
    }
    /*NOTREACHED*/
}

static krb5_sigtype
do_child(sig)
	int sig;
{
    /* SIGCHLD brings us here */
    int pid;
    register int i, j;

#ifdef WAIT_USES_INT
    int status;
#else
    union wait status;
#endif

    pid = wait(&status);

    for (i = 0; i < pidarraysize; i++)
	if (pidarray[i] == pid) {
	    /* found it */
	    for (j = i; j < pidarraysize-1; j++)
		/* copy others down */
		pidarray[j] = pidarray[j+1];
	    pidarraysize--;
#ifdef WAIT_USES_INT
	    if (WIFEXITED(status) || WIFSIGNALED(status))
		if (WTERMSIG(status) || WEXITSTATUS(status))
		    syslog(LOG_ERR, "child %d: termsig %d, retcode %d", pid,
			   WTERMSIG(status), WEXITSTATUS(status));

#else
	    if (status.w_retcode || status.w_coredump || status.w_termsig)
		syslog(LOG_ERR, "child %d: termsig %d, coredump %d, retcode %d",
		       pid, status.w_termsig, status.w_coredump, status.w_retcode);

#endif
	    SIGNAL_RETURN;
	}
    unknown_child = pid;
#ifdef WAIT_USES_INT
    syslog(LOG_ERR, "child %d not in list: termsig %d, retcode %d", pid,
	   WTERMSIG(status), WEXITSTATUS(status));

#else
    syslog(LOG_ERR, "child %d not in list: termsig %d, coredump %d, retcode %d",
	   pid, status.w_termsig, status.w_coredump, status.w_retcode);

#endif
    SIGNAL_RETURN;
}

static
void cleanexit(val)
    int val;
{
    krb5_db_fini(kadm_context);
    clear_secrets();
    exit(val);
}

static void
kill_children()
{
    register int i;
#ifdef POSIX_SIGNALS
    sigset_t oldmask, igmask;
#else
    int osigmask;
#endif

#ifdef POSIX_SIGNALS
    sigemptyset(&igmask);
    sigaddset(&igmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &igmask, &oldmask);
#else
    osigmask = sigblock(sigmask(SIGCHLD));
#endif

    for (i = 0; i < pidarraysize; i++) {
	kill(pidarray[i], SIGINT);
	syslog(LOG_ERR, "killing child %d", pidarray[i]);
    }
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    sigsetmask(osigmask);
#endif
    return;
}

#ifdef KADM5
krb5_int32 convert_kadm5_to_kadm(val)
   krb5_int32 val;
{
     switch (val) {
     case KADM5_AUTH_GET:
     case KADM5_AUTH_ADD:
     case KADM5_AUTH_MODIFY:
     case KADM5_AUTH_DELETE:
     case KADM5_AUTH_INSUFFICIENT:
     case KADM5_AUTH_LIST:
     case KADM5_AUTH_CHANGEPW:
	  return KADM_UNAUTH;
     case KADM5_BAD_DB:
	  return KADM_UK_RERROR;
     case KADM5_DUP:
     case KADM5_POLICY_REF:
	  return KADM_INUSE;
     case KADM5_RPC_ERROR:
	  return KADM_NO_CONN;
     case KADM5_NO_SRV:
	  return KADM_NO_HOST;
     case KADM5_UNK_PRINC:
     case KADM5_UNK_POLICY:
	  return KADM_NOENTRY;
     case KADM5_PASS_Q_TOOSHORT:
     case KADM5_PASS_Q_CLASS:
     case KADM5_PASS_Q_DICT:
     case KADM5_PASS_REUSE:
     case KADM5_PASS_TOOSOON:
     case CHPASS_UTIL_PASSWORD_TOO_SOON:
	  return KADM_INSECURE_PW;
     case KADM5_BAD_PASSWORD:
	  return KADM_NO_CRED;
     case KADM5_PROTECT_PRINCIPAL:
	  return KADM_NO_OPCODE;
     case KADM5_NOT_INIT:
     case KADM5_BAD_HIST_KEY:
     case KADM5_BAD_MASK:
     case KADM5_BAD_CLASS:
     case KADM5_BAD_LENGTH:
     case KADM5_BAD_POLICY:
     case KADM5_BAD_PRINCIPAL:
     case KADM5_BAD_AUX_ATTR:
     case KADM5_BAD_HISTORY:
     case KADM5_BAD_MIN_PASS_LIFE:
	  return -1;
     }
     return val;
}
#endif
