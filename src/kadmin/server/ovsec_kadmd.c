/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <stdio.h>
#include    <signal.h>
#include    <syslog.h>
#include    <sys/types.h>
#ifdef _AIX
#include    <sys/select.h>
#endif
#include    <sys/time.h>
#include    <sys/socket.h>
#include    <unistd.h>
#include    <netinet/in.h>
#include    <arpa/inet.h>  /* inet_ntoa */
#include    <netdb.h>
#include    <rpc/rpc.h>
#include    <gssapi/gssapi_krb5.h>
#include    <rpc/auth_gssapi.h>
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#include    <string.h>

#ifdef PURIFY
#include    "purify.h"

int	signal_pure_report = 0;
int	signal_pure_clear = 0;
void	request_pure_report(int);
void	request_pure_clear(int);
#endif /* PURIFY */

int	signal_request_exit = 0;
int	signal_request_reset = 0;
void	request_exit(int);
void	request_reset_db(int);
void	reset_db(void);
void	sig_pipe(int);
void	kadm_svc_run(void);

#define	TIMEOUT	15

gss_name_t gss_changepw_name = NULL, gss_oldchangepw_name = NULL;
void *global_server_handle;

/*
 * This is a kludge, but the server needs these constants to be
 * compatible with old clients.  They are defined in <kadm5/admin.h>,
 * but only if USE_KADM5_API_VERSION == 1.
 */
#define OVSEC_KADM_ADMIN_SERVICE	"ovsec_adm/admin"
#define OVSEC_KADM_CHANGEPW_SERVICE	"ovsec_adm/changepw"

/*
 * This enables us to set the keytab that gss_acquire_cred uses, but
 * it also restricts us to linking against the Kv5 GSS-API library.
 * Since this is *k*admind, that shouldn't be a problem.
 */
extern 	char *krb5_defkeyname;

char *build_princ_name(char *name, char *realm);
void log_badauth(OM_uint32 major, OM_uint32 minor,
		 struct sockaddr_in *addr, char *data);
void log_badverf(gss_name_t client_name, gss_name_t server_name,
		 struct svc_req *rqst, struct rpc_msg *msg,
		 char *data);
void log_miscerr(struct svc_req *rqst, struct rpc_msg *msg, char
		 *error, char *data);
void log_badauth_display_status(char *msg, OM_uint32 major, OM_uint32 minor);
void log_badauth_display_status_1(char *m, OM_uint32 code, int type,
				  int rec);
	

/*
 * Function: usage
 * 
 * Purpose: print out the server usage message
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 */

void usage()
{
     fprintf(stderr, "Usage: kadmind [-r realm] [-m] [-nofork] "
	     "[-port port-number]\n");
     exit(1);
}

/* XXX yuck.  the signal handlers need this */
static krb5_context context;

int main(int argc, char *argv[])
{
     void	kadm_1(struct svc_req *, SVCXPRT *);
     register	SVCXPRT *transp;
     extern	char *optarg;
     extern	int optind, opterr;
     int ret, rlen, nofork, oldnames = 0;
     OM_uint32 OMret;
     char *whoami;
     FILE *acl_file;
     gss_buffer_desc in_buf;
     struct servent *srv;
     struct sockaddr_in addr;
     int s;
     short port = 0;
     auth_gssapi_name names[4];
     kadm5_config_params params;

     names[0].name = names[1].name = names[2].name = names[3].name = NULL;
     names[0].type = names[1].type = names[2].type = names[3].type =
	  gss_nt_krb5_name;

#ifdef PURIFY
     purify_start_batch();
#endif /* PURIFY */
     whoami = (strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0]);

     nofork = 0;

     memset((char *) &params, 0, sizeof(params));
     
     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-r") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       params.realm = *argv;
	       params.mask |= KADM5_CONFIG_REALM;
	       argc--; argv++;
	       continue;
	  } else if (strcmp(*argv, "-m") == 0) {
	       params.mkey_from_kbd = 1;
	       params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	  } else if (strcmp(*argv, "-nofork") == 0) {
	       nofork = 1;
	  } else if(strcmp(*argv, "-port") == 0) {
	    argc--; argv++;
	    if(!argc)
	      usage();
	    params.kadmind_port = atoi(*argv);
	    params.mask |= KADM5_CONFIG_KADMIND_PORT;
	  } else
	       break;
	  argc--; argv++;
     }
     
     if (argc != 0)
	  usage();

     if (ret = krb5_init_context(&context)) {
	  fprintf(stderr, "%s: %s while initializing context, aborting\n",
		  whoami, error_message(ret));
	  exit(1);
     }

     krb5_klog_init(context, "admin_server", whoami, 1);

     if((ret = kadm5_init("kadmind", NULL,
			  NULL, &params,
			  KADM5_STRUCT_VERSION,
			  KADM5_API_VERSION_2,
			  &global_server_handle)) != 
	KADM5_OK) {
	  krb5_klog_syslog(LOG_ERR, "%s while initializing, aborting",
		 error_message(ret));
	  fprintf(stderr, "%s: %s while initializing, aborting\n",
		  whoami, error_message(ret));
	  krb5_klog_close();
	  exit(1);
     }
     
     if (ret = kadm5_get_config_params(context, NULL, NULL, &params,
				       &params)) {
	  krb5_klog_syslog(LOG_ERR, "%s: %s while initializing, aborting",
			   whoami, error_message(ret));
	  fprintf(stderr, "%s: %s while initializing, aborting\n",
		  whoami, error_message(ret));
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();
	  exit(1);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | KADM5_CONFIG_ACL_FILE | \
			 KADM5_CONFIG_ADMIN_KEYTAB)

     if ((params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
	  krb5_klog_syslog(LOG_ERR, "%s: Missing required configuration values "
			   "while initializing, aborting", whoami,
			   (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  fprintf(stderr, "%s: Missing required configuration values "
		  "(%x) while initializing, aborting\n", whoami,
		  (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  krb5_klog_close();
	  kadm5_destroy(global_server_handle);
	  exit(1);
     }

     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = INADDR_ANY;
     addr.sin_port = htons(params.kadmind_port);

     if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	  krb5_klog_syslog(LOG_ERR, "Cannot create TCP socket: %s",
			   error_message(errno));
	  fprintf(stderr, "Cannot create TCP socket: %s",
		  error_message(errno));
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }

#ifdef SO_REUSEADDR
     /* the old admin server turned on SO_REUSEADDR for non-default
	port numbers.  this was necessary, on solaris, for the tests
	to work.  jhawk argues that the debug and production modes
	should be the same.  I think I agree, so I'm always going to set
	SO_REUSEADDR.  The other option is to have the unit tests wait
	until the port is useable, or use a different port each time.  
	--marc */

     {
	 int	allowed;

	 allowed = 1;
	 if (setsockopt(s,
			SOL_SOCKET,
			SO_REUSEADDR,
			(char *) &allowed,
			sizeof(allowed)) < 0) {
	     krb5_klog_syslog(LOG_ERR, "Cannot set SO_REUSEADDR: %s",
			      error_message(errno));
	     fprintf(stderr, "Cannot set SO_REUSEADDR: %s",
		     error_message(errno));
	     kadm5_destroy(global_server_handle);
	     krb5_klog_close();	  
	     exit(1);
	 }
     }
#endif /* SO_REUSEADDR */
     if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  int oerrno = errno;
	  fprintf(stderr, "%s: Cannot bind socket.\n", whoami);
	  fprintf(stderr, "bind: %s\n", error_message(oerrno));
	  errno = oerrno;
	  krb5_klog_syslog(LOG_ERR, "Cannot bind socket: %s",
			   error_message(errno));
	  if(oerrno == EADDRINUSE) {
	       char *w = strrchr(whoami, '/');
	       if (w) {
		    w++;
	       }
	       else {
		    w = whoami;
	       }
	       fprintf(stderr,
"This probably means that another %s process is already\n"
"running, or that another program is using the server port (number %d)\n"
"after being assigned it by the RPC portmap deamon.  If another\n"
"%s is already running, you should kill it before\n"
"restarting the server.  If, on the other hand, another program is\n"
"using the server port, you should kill it before running\n"
"%s, and ensure that the conflict does not occur in the\n"
"future by making sure that %s is started on reboot\n"
		       "before portmap.\n", w, ntohs(addr.sin_port), w, w, w);
	       krb5_klog_syslog(LOG_ERR, "Check for already-running %s or for "
		      "another process using port %d", w,
		      htons(addr.sin_port));
	  }
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }
     
     transp = svctcp_create(s, 0, 0);
     if(transp == NULL) {
	  fprintf(stderr, "%s: Cannot create RPC service.\n", whoami);
	  krb5_klog_syslog(LOG_ERR, "Cannot create RPC service: %m");
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }
     if(!svc_register(transp, KADM, KADMVERS, kadm_1, 0)) {
	  fprintf(stderr, "%s: Cannot register RPC service.\n", whoami);
	  krb5_klog_syslog(LOG_ERR, "Cannot register RPC service, failing.");
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }

     names[0].name = build_princ_name(KADM5_ADMIN_SERVICE, params.realm);
     names[1].name = build_princ_name(KADM5_CHANGEPW_SERVICE, params.realm);
     names[2].name = build_princ_name(OVSEC_KADM_ADMIN_SERVICE, params.realm);
     names[3].name = build_princ_name(OVSEC_KADM_CHANGEPW_SERVICE,
				      params.realm); 
     if (names[0].name == NULL || names[1].name == NULL ||
	 names[2].name == NULL || names[3].name == NULL) {
	  krb5_klog_syslog(LOG_ERR, "Cannot initialize GSS-API authentication, "
		 "failing.");
	  fprintf(stderr, "%s: Cannot initialize GSS-API authentication.\n",
		  whoami);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }

     /* XXX krb5_defkeyname is an internal library global and should
        go away */
     krb5_defkeyname = params.admin_keytab;

     /*
      * Try to acquire creds for the old OV services as well as the
      * new names, but if that fails just fall back on the new names.
      */
     if (_svcauth_gssapi_set_names(names, 4) == TRUE)
	  oldnames++;
     if (!oldnames && _svcauth_gssapi_set_names(names, 2) == FALSE) {
	  krb5_klog_syslog(LOG_ERR, "Cannot initialize GSS-API authentication, "
		 "failing.");
	  fprintf(stderr, "%s: Cannot initialize GSS-API authentication.\n",
		  whoami);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();	  
	  exit(1);
     }

     /* if set_names succeeded, this will too */
     in_buf.value = names[1].name;
     in_buf.length = strlen(names[1].name) + 1;
     (void) gss_import_name(&OMret, &in_buf, gss_nt_krb5_name,
			    &gss_changepw_name);
     if (oldnames) {
	  in_buf.value = names[3].name;
	  in_buf.length = strlen(names[3].name) + 1;
	  (void) gss_import_name(&OMret, &in_buf, gss_nt_krb5_name,
				 &gss_oldchangepw_name);
     }

     _svcauth_gssapi_set_log_badauth_func(log_badauth, NULL);
     _svcauth_gssapi_set_log_badverf_func(log_badverf, NULL);
     _svcauth_gssapi_set_log_miscerr_func(log_miscerr, NULL);
     
     if (ret = acl_init(context, 0, params.acl_file)) {
	  krb5_klog_syslog(LOG_ERR, "Cannot initialize acl file: %s",
		 error_message(ret));
	  fprintf(stderr, "%s: Cannot initialize acl file: %s\n",
		  whoami, error_message(ret));
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();
	  exit(1);
     }

     if (!nofork && (ret = daemon(0, 0))) {
	  ret = errno;
	  krb5_klog_syslog(LOG_ERR, "Cannot detach from tty: %s", error_message(ret));
	  fprintf(stderr, "%s: Cannot detach from tty: %s\n",
		  whoami, error_message(ret));
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close();
	  exit(1);
     }
     
     signal(SIGINT, request_exit);
     signal(SIGTERM, request_exit);
     signal(SIGQUIT, request_exit);
     signal(SIGHUP, request_reset_db);
     signal(SIGPIPE, sig_pipe);
#ifdef PURIFY
     signal(SIGUSR1, request_pure_report);
     signal(SIGUSR2, request_pure_clear);
#endif /* PURIFY */
     krb5_klog_syslog(LOG_INFO, "starting");

     kadm_svc_run();
     krb5_klog_syslog(LOG_INFO, "finished, exiting");
     kadm5_destroy(global_server_handle);
     close(s);
     krb5_klog_close();
     exit(2);
}

/*
 * Function: kadm_svc_run
 * 
 * Purpose: modified version of sunrpc svc_run.
 *	    which closes the database every TIMEOUT seconds.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 */

void kadm_svc_run(void)
{
     fd_set	rfd;
     int	sz = _rpc_dtablesize();
     struct	timeval	    timeout;
     
     while(signal_request_exit == 0) {
	  if (signal_request_reset)
	    reset_db();
#ifdef PURIFY
	  if (signal_pure_report)	/* check to see if a report */
					/* should be dumped... */
	    {
	      purify_new_reports();
	      signal_pure_report = 0;
	    }
	  if (signal_pure_clear)	/* ...before checking whether */
					/* the info should be cleared. */
	    {
	      purify_clear_new_reports();
	      signal_pure_clear = 0;
	    }
#endif /* PURIFY */
	  timeout.tv_sec = TIMEOUT;
	  timeout.tv_usec = 0;
	  rfd = svc_fdset;
	  switch(select(sz, (fd_set *) &rfd, NULL, NULL, &timeout)) {
	  case -1:
	       if(errno == EINTR)
		    continue;
	       perror("select");
	       return;
	  case 0:
	       reset_db();
	       break;
	  default:
	       svc_getreqset(&rfd);
	  }
     }
}

#ifdef PURIFY
/*
 * Function: request_pure_report
 * 
 * Purpose: sets flag saying the server got a signal and that it should
 *		dump a purify report when convenient.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *	sets signal_pure_report to one
 */

void request_pure_report(int signum)
{
     krb5_klog_syslog(LOG_DEBUG, "Got signal to request a Purify report");
     signal_pure_report = 1;
     return;
}

/*
 * Function: request_pure_clear
 * 
 * Purpose: sets flag saying the server got a signal and that it should
 *		dump a purify report when convenient, then clear the
 *		purify tables.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *	sets signal_pure_report to one
 *	sets signal_pure_clear to one
 */

void request_pure_clear(int signum)
{
     krb5_klog_syslog(LOG_DEBUG, "Got signal to request a Purify report and clear the old Purify info");
     signal_pure_report = 1;
     signal_pure_clear = 1;
     return;
}
#endif /* PURIFY */

/*
 * Function: request_reset_db
 * 
 * Purpose: sets flag saying the server got a signal and that it should
 *		reset the database files when convenient.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *	sets signal_request_reset to one
 */

void request_reset_db(int signum)
{
     krb5_klog_syslog(LOG_DEBUG, "Got signal to request resetting the databases");
     signal_request_reset = 1;
     return;
}

/*
 * Function: reset-db
 * 
 * Purpose: flushes the currently opened database files to disk.
 *
 * Arguments:
 * Requires:
 * Effects:
 * 
 * Currently, just sets signal_request_reset to 0.  The kdb and adb
 * libraries used to be sufficiently broken that it was prudent to
 * close and reopen the databases periodically.  They are no longer
 * that broken, so this function is not necessary.
 */
void reset_db(void)
{
#ifdef notdef
     kadm5_ret_t ret;
     
     if (ret = kadm5_flush(global_server_handle)) {
	  krb5_klog_syslog(LOG_ERR, "FATAL ERROR!  %s while flushing databases.  "
		 "Databases may be corrupt!  Aborting.",
		 error_message(ret));
	  krb5_klog_close();
	  exit(3);
     }
#endif

     signal_request_reset = 0;
     return;
}

/*
 * Function: request-exit
 * 
 * Purpose: sets flags saying the server got a signal and that it
 *	    should exit when convient.
 *
 * Arguments:
 * Requires:
 * Effects:
 *	modifies signal_request_exit which ideally makes the server exit
 *	at some point.
 *
 * Modifies:
 *	signal_request_exit
 */

void request_exit(int signum)
{
     krb5_klog_syslog(LOG_DEBUG, "Got signal to request exit");
     signal_request_exit = 1;
     return;
}

/*
 * Function: sig_pipe
 *
 * Purpose: SIGPIPE handler
 *
 * Effects: krb5_klog_syslogs a message that a SIGPIPE occurred and returns,
 * thus causing the read() or write() to fail and, presumable, the RPC
 * to recover.  Otherwise, the process aborts.
 */
void sig_pipe(int unused)
{
     krb5_klog_syslog(LOG_NOTICE, "Warning: Received a SIGPIPE; probably a "
	    "client aborted.  Continuing.");
     return;
}

/*
 * Function: build_princ_name
 * 
 * Purpose: takes a name and a realm and builds a string that can be
 *	    consumed by krb5_parse_name.
 *
 * Arguments:
 *	name		    (input) name to be part of principal
 *	realm		    (input) realm part of principal
 * 	<return value>	    char * pointing to "name@realm"
 *
 * Requires:
 *	name be non-null.
 * 
 * Effects:
 * Modifies:
 */

char *build_princ_name(char *name, char *realm)
{
     char *fullname;

     fullname = (char *) malloc(strlen(name) + 1 +
				(realm ? strlen(realm) + 1 : 0));
     if (fullname == NULL)
	  return NULL;
     if (realm)
	  sprintf(fullname, "%s@%s", name, realm);
     else
	  strcpy(fullname, name);
     return fullname;
}

/*
 * Function: log_badverf
 *
 * Purpose: Call from GSS-API Sun RPC for garbled/forged/replayed/etc
 * messages.
 *
 * Argiments:
 * 	client_name	(r) GSS-API client name
 * 	server_name	(r) GSS-API server name
 * 	rqst		(r) RPC service request
 * 	msg		(r) RPC message
 * 	data		(r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the invalid request via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_badverf(gss_name_t client_name, gss_name_t server_name,
		 struct svc_req *rqst, struct rpc_msg *msg, char
		 *data)
{
     static const char *const proc_names[] = {
	  "kadm5_create_principal",
	  "kadm5_delete_principal",
	  "kadm5_modify_principal",
	  "kadm5_rename_principal",
	  "kadm5_get_principal",
	  "kadm5_chpass_principal",
	  "kadm5_randkey_principal",
	  "kadm5_create_policy",
	  "kadm5_delete_policy",
	  "kadm5_modify_policy",
	  "kadm5_get_policy",
	  "kadm5_get_privs",
     };
     OM_uint32 minor;
     gss_buffer_desc client, server;
     gss_OID gss_type;
     char *a;

     (void) gss_display_name(&minor, client_name, &client, &gss_type);
     (void) gss_display_name(&minor, server_name, &server, &gss_type);
     a = inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr);

     krb5_klog_syslog(LOG_NOTICE, "WARNING! Forged/garbled request: %s, "
	    "claimed client = %s, server = %s, addr = %s",
	    proc_names[msg->rm_call.cb_proc], client.value,
	    server.value, a);

     (void) gss_release_buffer(&minor, &client);
     (void) gss_release_buffer(&minor, &server);
}

/*
 * Function: log_miscerr
 *
 * Purpose: Callback from GSS-API Sun RPC for miscellaneous errors
 *
 * Arguments:
 * 	rqst		(r) RPC service request
 * 	msg		(r) RPC message
 *	error		(r) error message from RPC
 * 	data		(r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the error via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_miscerr(struct svc_req *rqst, struct rpc_msg *msg,
		 char *error, char *data)
{
     char *a;
     
     a = inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr);
     krb5_klog_syslog(LOG_NOTICE, "Miscellaneous RPC error: %s, %s", a, error);
}



/*
 * Function: log_badauth
 *
 * Purpose: Callback from GSS-API Sun RPC for authentication
 * failures/errors.
 *
 * Arguments:
 * 	major 		(r) GSS-API major status
 * 	minor		(r) GSS-API minor status
 * 	addr		(r) originating address
 * 	data		(r) arbitrary data (NULL), not used
 *
 * Effects:
 *
 * Logs the GSS-API error via krb5_klog_syslog(); see functional spec for
 * format.
 */
void log_badauth(OM_uint32 major, OM_uint32 minor,
		 struct sockaddr_in *addr, char *data)
{
     char *a;
     
     /* Authentication attempt failed: <IP address>, <GSS-API error */
     /* strings> */

     a = inet_ntoa(addr->sin_addr);

     krb5_klog_syslog(LOG_NOTICE, "Authentication attempt failed: %s, GSS-API "
	    "error strings are:", a);
     log_badauth_display_status("   ", major, minor);
     krb5_klog_syslog(LOG_NOTICE, "   GSS-API error strings complete.");
}

void log_badauth_display_status(char *msg, OM_uint32 major, OM_uint32 minor)
{
     log_badauth_display_status_1(msg, major, GSS_C_GSS_CODE, 0);
     log_badauth_display_status_1(msg, minor, GSS_C_MECH_CODE, 0);
}

void log_badauth_display_status_1(char *m, OM_uint32 code, int type,
				  int rec)
{
     OM_uint32 gssstat, minor_stat;
     gss_buffer_desc msg;
     int msg_ctx;

     msg_ctx = 0;
     while (1) {
	  gssstat = gss_display_status(&minor_stat, code,
				       type, GSS_C_NULL_OID,
				       &msg_ctx, &msg);
	  if (gssstat != GSS_S_COMPLETE) {
 	       if (!rec) {
		    log_badauth_display_status_1(m,gssstat,GSS_C_GSS_CODE,1); 
		    log_badauth_display_status_1(m, minor_stat,
						 GSS_C_MECH_CODE, 1);
	       } else
		    krb5_klog_syslog(LOG_ERR, "GSS-API authentication error %s: "
			   "recursive failure!", msg);
	       return;
	  }

	  krb5_klog_syslog(LOG_NOTICE, "%s %s", m, (char *)msg.value); 
	  (void) gss_release_buffer(&minor_stat, &msg);
	  
	  if (!msg_ctx)
	       break;
     }
}
