/*
 * $Source$
 * $Author$
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

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>

#ifndef POSIX_SIGNALS
#ifndef sigmask
#define sigmask(m)	(1 <<((m)-1))
#endif
#endif /* POSIX_SIGNALS */
#ifdef _AIX
#include <sys/resource.h>
#endif /* _AIX */
#include <sys/wait.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/los-proto.h>
#include <krb5/config.h>

#ifdef OVSEC_KADM
#include <ovsec_admin/admin.h>
void *ovsec_handle;
#endif

#include <kadm.h>
#include <kadm_err.h>
#include <krb_db.h>
#include "kadm_server.h"

/* Almost all procs and such need this, so it is global */
admin_params prm;		/* The command line parameters struct */

char prog[32];			/* WHY IS THIS NEEDED??????? */
char *progname = prog;
char *acldir = DEFAULT_ACL_DIR;
char krbrlm[REALM_SZ];
extern Kadm_Server server_parm;
int des_debug; /* used by the des425 libraries */
int debug = 0;

/*
** Main does the logical thing, it sets up the database and RPC interface,
**  as well as handling the creation and maintenance of the syslog file...
*/
main(argc, argv)		/* admin_server main routine */
int argc;
char *argv[];
{
    int errval;
    int c;
    char *db_name, *lrealm;
    extern char *optarg;
    extern int fascist_cpw;

    krb5_init_ets();
    initialize_kadm_error_table();
    prog[sizeof(prog)-1]='\0';		/* Terminate... */
    (void) strncpy(prog, argv[0], sizeof(prog)-1);

    /* initialize the admin_params structure */
    prm.sysfile = KADM_SYSLOG;		/* default file name */
    prm.inter = 1;

    memset(krbrlm, 0, sizeof(krbrlm));

    fascist_cpw = 1;		/* by default, enable fascist mode */
    while ((c = getopt(argc, argv, "f:hnd:Da:r:FN")) != EOF)
	switch(c) {
	case 'd':
	    if (errval = krb5_db_set_name(optarg)) {
		com_err(argv[0], errval, "while setting dbname");
		exit(1);
	    }
	    break;
	case 'D':
	    debug++;
	    break;
#ifndef OVSEC_KADM
	case 'f':			/* Syslog file name change */
	    prm.sysfile = optarg;
	    break;
        case 'F':
	    fascist_cpw++;
	    break;
        case 'N':
	    fascist_cpw = 0;
	    break;
#endif
	case 'n':
	    prm.inter = 0;
	    break;
	case 'a':			/* new acl directory */
	    acldir = optarg;
	    break;
	case 'r':
	    (void) strncpy(krbrlm, optarg, sizeof(krbrlm) - 1);
	    break;
	case 'h':			/* get help on using admin_server */
	default:
#ifdef OVSEC_KADM
	    fprintf(stderr, "Usage: ovsec_v4adm_server [-D] [-h] [-n] [-r realm] [-d dbname] [-a acldir]\n");

#else
	    printf("Usage: admin_server [-D] [-h] [-n] [-F] [-N] [-r realm] [-d dbname] [-f filename] [-a acldir]\n");
#endif
	    exit(-1);			/* failure */
	}

    if (krbrlm[0] == 0) {
	if (errval = krb5_get_default_realm(&lrealm)) {
	    com_err(argv[0], errval, "while attempting to get local realm");
	    exit(1);
	}
	(void) strncpy(krbrlm, lrealm, sizeof(krbrlm) - 1);
    }
    printf("KADM Server %s initializing\n",KADM_VERSTR);
    printf("Please do not use 'kill -9' to kill this job, use a\n");
    printf("regular kill instead\n\n");

#ifdef OVSEC_KADM
    printf("KADM Server starting in the OVSEC_KADM mode (%sprocess id %d).\n",
	   debug ? "" : "parent ", getpid());
#else
    printf("KADM Server starting in %s mode for the purposes for password changing\n\n", fascist_cpw ? "fascist" : "NON-FASCIST");
#endif

    open_syslog(argv[0], "V4 admin server (parent) starting");

    errval = krb5_db_init();		/* Open the Kerberos database */
    if (errval) {
	fprintf(stderr, "error: krb5_db_init() failed");
	close_syslog();
	byebye();
	exit(1);
    }
    if (errval = krb5_db_set_lockmode(TRUE)) {
	com_err(argv[0], errval, "while setting db to nonblocking");
	close_syslog();
	byebye();
	exit(1);
    }
    
    /* set up the server_parm struct */
    if ((errval = kadm_ser_init(prm.inter, krbrlm)) != KADM_SUCCESS) {
	fprintf(stderr, "error initializing:  %s\n", error_message(errval));
	krb5_db_fini();
	close_syslog();
	byebye();
	exit(1);
    }

    /* detach from the terminal */
    if (!debug) {
	if (
#ifdef KRB5B4
	    daemon(0, 0)
#else
	    errval = krb5_detach_process()
#endif
	    ) {
#ifdef KRB5B4
	    errval = errno;
#endif
	    fprintf(stderr, "error detaching from terminal:  %s\n",
		    error_message(errval));
	    syslog(LOG_ERR, "error detaching from terminal: %s",
		   error_message(errval));
	    krb5_db_fini();
	    close_syslog();
	    byebye();
	    exit(1);
	}
	open_syslog(argv[0], "V4 admin server (child) starting");
    }

    krb5_db_fini();

    if (errval = kadm_listen()) {
	fprintf(stderr, "error while listening for requests:  %s\n",
		error_message(errval));
	syslog(LOG_ERR, "error while listening for requests: %s",
	       error_message(errval));
	krb5_db_fini();
	close_syslog();
	byebye();
	exit(1);
    }

    close_syslog();
    byebye();
    exit(0);
}					/* procedure main */


/* open the system log file */
open_syslog(whoami, message)
    char *whoami, *message;
{
    static int opened = 0;

    if (opened) {
	closelog();
    }
    openlog(whoami, LOG_CONS|LOG_NDELAY|LOG_PID, LOG_LOCAL6); /* XXX */
    syslog(LOG_INFO, message);
    opened++;
}

/* close the system log file */
close_syslog()
{
   syslog(LOG_INFO, "Shutting down V4 admin server");
}

byebye()			/* say goodnight gracie */
{
   printf("Admin Server (kadm server) has completed operation.\n");
}

static clear_secrets()
{
    krb5_finish_key(&server_parm.master_encblock);
    memset((char *)&server_parm.master_encblock, 0,
	   sizeof (server_parm.master_encblock));
    memset((char *)server_parm.master_keyblock.contents, 0,
	   server_parm.master_keyblock.length);
    server_parm.mkvno = 0L;
    return;
}

static exit_now = 0;

krb5_sigtype doexit()
{
    exit_now = 1;
}
   
unsigned pidarraysize = 0;
int *pidarray = (int *)0;
int unknown_child = 0;

/*
kadm_listen
listen on the admin servers port for a request
*/
kadm_listen()
{
    extern int errno;
    int found;
    int admin_fd;
    int peer_fd;
    fd_set mask, readfds;
    struct sockaddr_in peer;
    int addrlen;
    void process_client(), kill_children();
    int pid;
    krb5_sigtype do_child();

    (void) signal(SIGINT, doexit);
    (void) signal(SIGTERM, doexit);
    (void) signal(SIGHUP, doexit);
    (void) signal(SIGQUIT, doexit);
    (void) signal(SIGPIPE, SIG_IGN); /* get errors on write() */
    (void) signal(SIGALRM, doexit);
    (void) signal(SIGCHLD, do_child);

    if ((admin_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	return KADM_NO_SOCK;
    if (bind(admin_fd, (struct sockaddr *)&server_parm.admin_addr,
	     sizeof(struct sockaddr_in)) < 0)
	return KADM_NO_BIND;
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
	    } else if (pid = fork()) {
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
			pidarray = (int *)malloc((pidarraysize = 1) *
						 sizeof(int)); 
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

void process_client(fd, who)
   int fd;
   struct sockaddr_in *who;
{
    u_char *dat;
    int dat_len;
    u_short dlen;
    int retval;
    int on = 1;
    Principal service;
    des_cblock skey;
    int nentries = 1;
    krb5_db_entry sprinc_entries;
    krb5_boolean more;
    krb5_keyblock cpw_skey;
    int status;

#ifdef OVSEC_KADM
#define OVSEC_KADM_SRVTAB 		"FILE:/krb5/ovsec_adm.srvtab"
    char *service_name;

    service_name = (char *) malloc(strlen(server_parm.sname) +
				   strlen(server_parm.sinst) +
				   strlen(server_parm.krbrlm) + 3);
    if (service_name == NULL) {
	 syslog(LOG_ERR, "error: out of memory allocating service name");
    }
    sprintf(service_name, "%s/%s@%s", server_parm.sname,
	    server_parm.sinst, server_parm.krbrlm);

    retval = ovsec_kadm_init_with_skey(service_name,
				       OVSEC_KADM_SRVTAB,
				       OVSEC_KADM_ADMIN_SERVICE, krbrlm,
				       OVSEC_KADM_STRUCT_VERSION,
				       OVSEC_KADM_API_VERSION_1,
				       &ovsec_handle); 
    if (retval) {
	 syslog(LOG_ERR, "error: ovsec_kadm_init failed: %s",
		 error_message(retval));
	 cleanexit(1);
    }
    free(service_name);
    
#endif

#if !defined(NOENCRYPTION)
    /* Must do it here, since this is after the fork() call. */
    des_init_random_number_generator(server_parm.master_keyblock.contents);
#endif
    
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0)
	syslog(LOG_ERR, "setsockopt keepalive: %d", errno);

    server_parm.recv_addr = *who;

    if (krb5_db_init()) {	/* Open as client */
	syslog(LOG_ERR, "can't open krb db");
	cleanexit(1);
    }

    /* need to set service key to changepw.KRB_MASTER */

    status = krb5_db_get_principal(server_parm.sprinc,
				   &sprinc_entries,
				   &nentries, &more);
    /* ugh... clean this up later */
    if (status == KRB5_KDB_DB_INUSE) {
	/* db locked */
	krb5_ui_4 retcode = KADM_DB_INUSE;
	char *pdat;
	
	dat_len = KADM_VERSIZE + sizeof(u_int);
	dat = (u_char *) malloc((unsigned)dat_len);
	pdat = (char *) dat;
	/* This must be 32 bit integer due to the htonl */
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

    status = krb5_kdb_decrypt_key(&server_parm.master_encblock,
				  &sprinc_entries.key,
				  &cpw_skey);
    if (status) {
	syslog(LOG_ERR, "decrypt_key failed: %s", error_message(status));
	cleanexit(1);
    }
    /* if error, will show up when rd_req fails */
    (void) krb_set_key((char *)cpw_skey.contents, 0);
#ifdef KRB5_FREE_KEYBLOCK_CONTENTS_EXISTS
    krb5_free_keyblock_contents(&cpw_skey);
#else
    memset((char*)cpw_skey.contents, 0, cpw_skey.length);
    free(cpw_skey.contents);
#endif

    krb5_dbm_db_free_principal(&sprinc_entries, nentries);
	 
    while (1) {
	if ((retval = krb_net_read(fd, (char *)&dlen, sizeof(u_short))) !=
	    sizeof(u_short)) {
	    if (retval < 0)
		syslog(LOG_ERR, "dlen read: %s", error_message(errno));
	    else if (retval)
		syslog(LOG_ERR, "short dlen read: %d", retval);
	    (void) close(fd);
#ifdef OVSEC_KADM
	    (void) ovsec_kadm_destroy(ovsec_handle);
#endif
	    if (debug)
		 return;
	    else 
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

krb5_sigtype do_child()
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
	        syslog(LOG_ERR, "child %d: termsig %d, retcode %d", pid,
		       WTERMSIG(status), WEXITSTATUS(status));

#else
	    if (status.w_retcode || status.w_coredump || status.w_termsig)
		syslog(LOG_ERR, "child %d: termsig %d, coredump %d, retcode %d",
		       pid, status.w_termsig, status.w_coredump, status.w_retcode);

#endif
	    goto done; /* use goto to avoid figuring out whether to
			  return a value */
	}
    unknown_child = pid;
#ifdef WAIT_USES_INT
    syslog(LOG_ERR, "child %d not in list: termsig %d, retcode %d", pid,
	   WTERMSIG(status), WEXITSTATUS(status));
#else
    syslog(LOG_ERR, "child %d not in list: termsig %d, coredump %d, retcode %d",
	   pid, status.w_termsig, status.w_coredump, status.w_retcode);
#endif

  done:
}

cleanexit(val)
{
    krb5_db_fini();
    clear_secrets();
    exit(val);
}

void kill_children()
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

#ifdef OVSEC_KADM
krb5_ui_4 convert_ovsec_to_kadm(val)
   krb5_ui_4 val;
{
     switch (val) {
     case OVSEC_KADM_AUTH_GET:
     case OVSEC_KADM_AUTH_ADD:
     case OVSEC_KADM_AUTH_MODIFY:
     case OVSEC_KADM_AUTH_DELETE:
     case OVSEC_KADM_AUTH_INSUFFICIENT:
	  return KADM_UNAUTH;
     case OVSEC_KADM_BAD_DB:
	  return KADM_UK_RERROR;
     case OVSEC_KADM_DUP:
     case OVSEC_KADM_POLICY_REF:
	  return KADM_INUSE;
     case OVSEC_KADM_RPC_ERROR:
	  return KADM_NO_CONN;
     case OVSEC_KADM_NO_SRV:
	  return KADM_NO_HOST;
     case OVSEC_KADM_UNK_PRINC:
     case OVSEC_KADM_UNK_POLICY:
	  return KADM_NOENTRY;
     case OVSEC_KADM_PASS_Q_TOOSHORT:
     case OVSEC_KADM_PASS_Q_CLASS:
     case OVSEC_KADM_PASS_Q_DICT:
     case OVSEC_KADM_PASS_REUSE:
     case OVSEC_KADM_PASS_TOOSOON:
     case CHPASS_UTIL_PASSWORD_TOO_SOON:
	  return KADM_INSECURE_PW;
     case OVSEC_KADM_BAD_PASSWORD:
	  return KADM_NO_CRED;
     case OVSEC_KADM_PROTECT_PRINCIPAL:
	  return KADM_NO_OPCODE;
     case OVSEC_KADM_NOT_INIT:
     case OVSEC_KADM_BAD_HIST_KEY:
     case OVSEC_KADM_BAD_MASK:
     case OVSEC_KADM_BAD_CLASS:
     case OVSEC_KADM_BAD_LENGTH:
     case OVSEC_KADM_BAD_POLICY:
     case OVSEC_KADM_BAD_PRINCIPAL:
     case OVSEC_KADM_BAD_AUX_ATTR:
     case OVSEC_KADM_BAD_HISTORY:
     case OVSEC_KADM_BAD_MIN_PASS_LIFE:
	  return -1;
     }
     return val;
}
#endif
