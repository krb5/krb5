/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

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
#include    <gssrpc/rpc.h>
#include    <gssapi/gssapi.h>
#include    "gssapiP_krb5.h" /* for kg_get_context */
#include    <gssrpc/auth_gssapi.h>
#include    <kadm5/admin.h>
#include    <kadm5/kadm_rpc.h>
#include    <kadm5/server_acl.h>
#include    <adm_proto.h>
#include    "kdb_kt.h"	/* for krb5_ktkdb_set_context */
#include    <string.h>
#include    "kadm5/server_internal.h" /* XXX for kadm5_server_handle_t */

#include    "misc.h"

#ifdef PURIFY
#include    "purify.h"

int	signal_pure_report = 0;
int	signal_pure_clear = 0;
void	request_pure_report(int);
void	request_pure_clear(int);
#endif /* PURIFY */

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

volatile int	signal_request_exit = 0;
volatile int	signal_request_hup = 0;
void    setup_signal_handlers(void);
void	request_exit(int);
void	request_hup(int);
void	reset_db(void);
void	sig_pipe(int);
void	kadm_svc_run(kadm5_config_params *params);

#ifdef POSIX_SIGNALS
static struct sigaction s_action;
#endif /* POSIX_SIGNALS */


#define	TIMEOUT	15

gss_name_t gss_changepw_name = NULL, gss_oldchangepw_name = NULL;
gss_name_t gss_kadmin_name = NULL;
void *global_server_handle;

/*
 * This is a kludge, but the server needs these constants to be
 * compatible with old clients.  They are defined in <kadm5/admin.h>,
 * but only if USE_KADM5_API_VERSION == 1.
 */
#define OVSEC_KADM_ADMIN_SERVICE	"ovsec_adm/admin"
#define OVSEC_KADM_CHANGEPW_SERVICE	"ovsec_adm/changepw"

extern krb5_keyblock master_keyblock;

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
	
int schpw;
void do_schpw(int s, kadm5_config_params *params);

#ifdef USE_PASSWORD_SERVER
void kadm5_set_use_password_server (void);
#endif

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

static void usage()
{
     fprintf(stderr, "Usage: kadmind [-x db_args]* [-r realm] [-m] [-nofork] "
#ifdef USE_PASSWORD_SERVER
             "[-passwordserver] "
#endif
	     "[-port port-number]\n"
	     "\nwhere,\n\t[-x db_args]* - any number of database specific arguments.\n"
	     "\t\t\tLook at each database documentation for supported arguments\n"
	     );
     exit(1);
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 * 	msg		a string to be displayed with the message
 * 	maj_stat	the GSS-API major status code
 * 	min_stat	the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
static void display_status_1(char *, OM_uint32, int);

static void display_status(msg, maj_stat, min_stat)
     char *msg;
     OM_uint32 maj_stat;
     OM_uint32 min_stat;
{
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

static void display_status_1(m, code, type)
     char *m;
     OM_uint32 code;
     int type;
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;
     
	msg_ctx = 0;
	while (1) {
		maj_stat = gss_display_status(&min_stat, code,
					      type, GSS_C_NULL_OID,
					      &msg_ctx, &msg);
		fprintf(stderr, "GSS-API error %s: %s\n", m,
			(char *)msg.value); 
		(void) gss_release_buffer(&min_stat, &msg);
	  
		if (!msg_ctx)
			break;
	}
}


/* XXX yuck.  the signal handlers need this */
static krb5_context context;

static krb5_context hctx;

int main(int argc, char *argv[])
{
     register	SVCXPRT *transp;
     extern	char *optarg;
     extern	int optind, opterr;
     int ret, nofork, oldnames = 0;
     OM_uint32 OMret, major_status, minor_status;
     char *whoami;
     gss_buffer_desc in_buf;
     struct sockaddr_in addr;
     int s;
     auth_gssapi_name names[4];
     gss_buffer_desc gssbuf;
     gss_OID nt_krb5_name_oid;
     kadm5_config_params params;
     char **db_args      = NULL;
     int    db_args_size = 0;
     char *errmsg;

     setvbuf(stderr, NULL, _IONBF, 0);

     /* This is OID value the Krb5_Name NameType */
     gssbuf.value = "{1 2 840 113554 1 2 2 1}";
     gssbuf.length = strlen(gssbuf.value);
     major_status = gss_str_to_oid(&minor_status, &gssbuf, &nt_krb5_name_oid);
     if (major_status != GSS_S_COMPLETE) {
	     fprintf(stderr, "Couldn't create KRB5 Name NameType OID\n");
	     display_status("str_to_oid", major_status, minor_status);
	     exit(1);
     }

     names[0].name = names[1].name = names[2].name = names[3].name = NULL;
     names[0].type = names[1].type = names[2].type = names[3].type =
	     nt_krb5_name_oid;

#ifdef PURIFY
     purify_start_batch();
#endif /* PURIFY */
     whoami = (strrchr(argv[0], '/') ? strrchr(argv[0], '/')+1 : argv[0]);

     nofork = 0;

     memset((char *) &params, 0, sizeof(params));
     
     argc--; argv++;
     while (argc) {
          if (strcmp(*argv, "-x") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       db_args_size++;
	       {
		   char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
		   if( temp == NULL )
		   {
		       fprintf(stderr,"%s: cannot initialize. Not enough memory\n",
			       whoami);
		       exit(1);
		   }
		   db_args = temp;
	       }
	       db_args[db_args_size-1] = *argv;
	       db_args[db_args_size]   = NULL;
	  }else if (strcmp(*argv, "-r") == 0) {
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
#ifdef USE_PASSWORD_SERVER
          } else if (strcmp(*argv, "-passwordserver") == 0) {
              kadm5_set_use_password_server ();
#endif              
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

     if ((ret = kadm5_init_krb5_context(&context))) {
	  fprintf(stderr, "%s: %s while initializing context, aborting\n",
		  whoami, error_message(ret));
	  exit(1);
     }

     krb5_klog_init(context, "admin_server", whoami, 1);

     if((ret = kadm5_init("kadmind", NULL,
			  NULL, &params,
			  KADM5_STRUCT_VERSION,
			  KADM5_API_VERSION_2,
			  db_args,
		     &global_server_handle)) != KADM5_OK) {
	  const char *e_txt = krb5_get_error_message (context, ret);
	  krb5_klog_syslog(LOG_ERR, "%s while initializing, aborting",
			   e_txt);
	  fprintf(stderr, "%s: %s while initializing, aborting\n",
		  whoami, e_txt);
	  krb5_klog_close(context);
	  exit(1);
     }

     if( db_args )
     {
	 free(db_args), db_args=NULL;
     }
     
     if ((ret = kadm5_get_config_params(context, 1, &params,
					&params))) {
	  const char *e_txt = krb5_get_error_message (context, ret);
	  krb5_klog_syslog(LOG_ERR, "%s: %s while initializing, aborting",
			   whoami, e_txt);
	  fprintf(stderr, "%s: %s while initializing, aborting\n",
		  whoami, e_txt);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);
	  exit(1);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | KADM5_CONFIG_ACL_FILE)

     if ((params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
	  krb5_klog_syslog(LOG_ERR, "%s: Missing required configuration values "
			   "while initializing, aborting", whoami,
			   (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  fprintf(stderr, "%s: Missing required configuration values "
		  "(%lx) while initializing, aborting\n", whoami,
		  (params.mask & REQUIRED_PARAMS) ^ REQUIRED_PARAMS);
	  krb5_klog_close(context);
	  kadm5_destroy(global_server_handle);
	  exit(1);
     }

     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = INADDR_ANY;
     addr.sin_port = htons(params.kadmind_port);

     if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	  const char *e_txt = krb5_get_error_message (context, ret);
	  krb5_klog_syslog(LOG_ERR, "Cannot create TCP socket: %s",
			   e_txt);
	  fprintf(stderr, "Cannot create TCP socket: %s",
		  e_txt);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);	  
	  exit(1);
     }

     if ((schpw = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	 const char *e_txt = krb5_get_error_message (context, ret);
	 krb5_klog_syslog(LOG_ERR,
			  "cannot create simple chpw socket: %s",
			  e_txt);
	 fprintf(stderr, "Cannot create simple chpw socket: %s",
		 e_txt);
	 kadm5_destroy(global_server_handle);
	 krb5_klog_close(context);
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
	     const char *e_txt = krb5_get_error_message (context, ret);
	     krb5_klog_syslog(LOG_ERR, "Cannot set SO_REUSEADDR: %s",
			      e_txt);
	     fprintf(stderr, "Cannot set SO_REUSEADDR: %s", e_txt);
	     kadm5_destroy(global_server_handle);
	     krb5_klog_close(context);	  
	     exit(1);
	 }
	 if (setsockopt(schpw, SOL_SOCKET, SO_REUSEADDR,
			(char *) &allowed, sizeof(allowed)) < 0) {
	     const char *e_txt = krb5_get_error_message (context, ret);
	     krb5_klog_syslog(LOG_ERR, "main",
			      "cannot set SO_REUSEADDR on simple chpw socket: %s", 
			      e_txt);
	     fprintf(stderr,
		     "Cannot set SO_REUSEADDR on simple chpw socket: %s",
 		     e_txt);
 	     kadm5_destroy(global_server_handle);
 	     krb5_klog_close(context);
	 }

     }
#endif /* SO_REUSEADDR */
     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = INADDR_ANY;
     addr.sin_port = htons(params.kadmind_port);

     if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  int oerrno = errno;
	  const char *e_txt = krb5_get_error_message (context, errno);
	  fprintf(stderr, "%s: Cannot bind socket.\n", whoami);
	  fprintf(stderr, "bind: %s\n", e_txt);
	  errno = oerrno;
	  krb5_klog_syslog(LOG_ERR, "Cannot bind socket: %s", e_txt);
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
"after being assigned it by the RPC portmap daemon.  If another\n"
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
	  krb5_klog_close(context);
	  exit(1);
     }
     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = INADDR_ANY;
     /* XXX */
     addr.sin_port = htons(params.kpasswd_port);

     if (bind(schpw, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	  char portbuf[32];
	  int oerrno = errno;
	  const char *e_txt = krb5_get_error_message (context, errno);
	  fprintf(stderr, "%s: Cannot bind socket.\n", whoami);
	  fprintf(stderr, "bind: %s\n", e_txt);
	  errno = oerrno;
	  sprintf(portbuf, "%d", ntohs(addr.sin_port));
	  krb5_klog_syslog(LOG_ERR, "cannot bind simple chpw socket: %s",
			   e_txt);
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
"running, or that another program is using the server port (number %d).\n"
"If another %s is already running, you should kill it before\n"
"restarting the server.\n",
		       w, ntohs(addr.sin_port), w);
 	  }
 	  kadm5_destroy(global_server_handle);
 	  krb5_klog_close(context);
	  exit(1);
     }
     
     transp = svctcp_create(s, 0, 0);
     if(transp == NULL) {
	  fprintf(stderr, "%s: Cannot create RPC service.\n", whoami);
	  krb5_klog_syslog(LOG_ERR, "Cannot create RPC service: %m");
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);	  
	  exit(1);
     }
     if(!svc_register(transp, KADM, KADMVERS, kadm_1, 0)) {
	  fprintf(stderr, "%s: Cannot register RPC service.\n", whoami);
	  krb5_klog_syslog(LOG_ERR, "Cannot register RPC service, failing.");
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);	  
	  exit(1);
     }

     names[0].name = build_princ_name(KADM5_ADMIN_SERVICE, params.realm);
     names[1].name = build_princ_name(KADM5_CHANGEPW_SERVICE, params.realm);
     names[2].name = build_princ_name(OVSEC_KADM_ADMIN_SERVICE, params.realm);
     names[3].name = build_princ_name(OVSEC_KADM_CHANGEPW_SERVICE,
				      params.realm); 
     if (names[0].name == NULL || names[1].name == NULL ||
	 names[2].name == NULL || names[3].name == NULL) {
	  krb5_klog_syslog(LOG_ERR,
			   "Cannot build GSS-API authentication names, "
			   "failing.");
	  fprintf(stderr, "%s: Cannot build GSS-API authentication names.\n",
		  whoami);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);	  
	  exit(1);
     }

     /*
      * Go through some contortions to point gssapi at a kdb keytab.
      * This prevents kadmind from needing to use an actual file-based
      * keytab.
      */
     /* XXX extract kadm5's krb5_context */
     hctx = ((kadm5_server_handle_t)global_server_handle)->context;
     /* Set ktkdb's internal krb5_context. */
     ret = krb5_ktkdb_set_context(hctx);
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "Can't set kdb keytab's internal context.");
	  goto kterr;
     }
     /* XXX master_keyblock is in guts of lib/kadm5/server_kdb.c */
     ret = krb5_db_set_mkey(hctx, &master_keyblock);
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "Can't set master key for kdb keytab.");
	  goto kterr;
     }
     ret = krb5_kt_register(context, &krb5_kt_kdb_ops);
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "Can't register kdb keytab.");
	  goto kterr;
     }
     /* Tell gssapi about the kdb keytab. */
     ret = krb5_gss_register_acceptor_identity("KDB:");
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "Can't register acceptor keytab.");
	  goto kterr;
     }
kterr:
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "%s", krb5_get_error_message (context, ret));
	  fprintf(stderr, "%s: Can't set up keytab for RPC.\n", whoami);
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);
	  exit(1);
     }

     /*
      * Try to acquire creds for the old OV services as well as the
      * new names, but if that fails just fall back on the new names.
      */
     if (svcauth_gssapi_set_names(names, 4) == TRUE)
	  oldnames++;
     if (!oldnames && svcauth_gssapi_set_names(names, 2) == FALSE) {
	  krb5_klog_syslog(LOG_ERR,
			   "Cannot set GSS-API authentication names (keytab not present?), "
			   "failing.");
	  fprintf(stderr, "%s: Cannot set GSS-API authentication names.\n",
		  whoami);
	  svcauth_gssapi_unset_names();
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);	  
	  exit(1);
     }

     /* if set_names succeeded, this will too */
     in_buf.value = names[1].name;
     in_buf.length = strlen(names[1].name) + 1;
     (void) gss_import_name(&OMret, &in_buf, nt_krb5_name_oid,
			    &gss_changepw_name);
     if (oldnames) {
	  in_buf.value = names[3].name;
	  in_buf.length = strlen(names[3].name) + 1;
	  (void) gss_import_name(&OMret, &in_buf, nt_krb5_name_oid,
				 &gss_oldchangepw_name);
     }

     svcauth_gssapi_set_log_badauth_func(log_badauth, NULL);
     svcauth_gssapi_set_log_badverf_func(log_badverf, NULL);
     svcauth_gssapi_set_log_miscerr_func(log_miscerr, NULL);
     
     svcauth_gss_set_log_badauth_func(log_badauth, NULL);
     svcauth_gss_set_log_badverf_func(log_badverf, NULL);
     svcauth_gss_set_log_miscerr_func(log_miscerr, NULL);
     
     if (svcauth_gss_set_svc_name(GSS_C_NO_NAME) != TRUE) {
	 fprintf(stderr, "%s: Cannot initialize RPCSEC_GSS service name.\n",
		 whoami);
	 exit(1);
     }

     if ((ret = kadm5int_acl_init(context, 0, params.acl_file))) {
	  errmsg = krb5_get_error_message (context, ret);
	  krb5_klog_syslog(LOG_ERR, "Cannot initialize acl file: %s",
		 errmsg);
	  fprintf(stderr, "%s: Cannot initialize acl file: %s\n",
		  whoami, errmsg);
	  svcauth_gssapi_unset_names();
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);
	  exit(1);
     }

     if (!nofork && (ret = daemon(0, 0))) {
	  ret = errno;
	  errmsg = krb5_get_error_message (context, ret);
	  krb5_klog_syslog(LOG_ERR, "Cannot detach from tty: %s", errmsg);
	  fprintf(stderr, "%s: Cannot detach from tty: %s\n",
		  whoami, errmsg);
	  svcauth_gssapi_unset_names();
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);
	  exit(1);
     }
     
     krb5_klog_syslog(LOG_INFO, "Seeding random number generator");
     ret = krb5_c_random_os_entropy(context, 1, NULL);
     if (ret) {
	  krb5_klog_syslog(LOG_ERR, "Error getting random seed: %s, aborting",
			   krb5_get_error_message(context, ret));
	  svcauth_gssapi_unset_names();
	  kadm5_destroy(global_server_handle);
	  krb5_klog_close(context);
	  exit(1);
     }
	  
     setup_signal_handlers();
     krb5_klog_syslog(LOG_INFO, "starting");
     kadm_svc_run(&params);
     krb5_klog_syslog(LOG_INFO, "finished, exiting");

     /* Clean up memory, etc */
     svcauth_gssapi_unset_names();
     kadm5_destroy(global_server_handle);
     close(s);
     kadm5int_acl_finish(context, 0);
     if(gss_changepw_name) {
          (void) gss_release_name(&OMret, &gss_changepw_name);
     }
     if(gss_oldchangepw_name) {
          (void) gss_release_name(&OMret, &gss_oldchangepw_name);
     }
     for(s = 0 ; s < 4; s++) {
          if (names[s].name) {
	        free(names[s].name);
	  }
     }

     krb5_klog_close(context);
     krb5_free_context(context);
     exit(2);
}

/*
 * Function: setup_signal_handlers
 *
 * Purpose: Setup signal handling functions using POSIX's sigaction()
 * if possible, otherwise with System V's signal().
 */

void setup_signal_handlers(void) {
#ifdef POSIX_SIGNALS
     (void) sigemptyset(&s_action.sa_mask);
     s_action.sa_handler = request_exit;
     (void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
     (void) sigaction(SIGQUIT, &s_action, (struct sigaction *) NULL);
     s_action.sa_handler = request_hup;
     (void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
     s_action.sa_handler = sig_pipe;
     (void) sigaction(SIGPIPE, &s_action, (struct sigaction *) NULL);
#ifdef PURIFY
     s_action.sa_handler = request_pure_report;
     (void) sigaction(SIGUSR1, &s_action, (struct sigaction *) NULL);
     s_action.sa_handler = request_pure_clear;
     (void) sigaction(SIGUSR2, &s_action, (struct sigaction *) NULL);
#endif /* PURIFY */
#else /* POSIX_SIGNALS */
     signal(SIGINT, request_exit);
     signal(SIGTERM, request_exit);
     signal(SIGQUIT, request_exit);
     signal(SIGHUP, request_hup);
     signal(SIGPIPE, sig_pipe);
#ifdef PURIFY
     signal(SIGUSR1, request_pure_report);
     signal(SIGUSR2, request_pure_clear);
#endif /* PURIFY */
#endif /* POSIX_SIGNALS */
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

void kadm_svc_run(params)
kadm5_config_params *params;
{
     fd_set	rfd;
     struct	timeval	    timeout;
     
     while(signal_request_exit == 0) {
	  if (signal_request_hup) {
	      reset_db();
	      krb5_klog_reopen(context);
	      signal_request_hup = 0;
	  }
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
	  FD_SET(schpw, &rfd);
#define max(a, b) (((a) > (b)) ? (a) : (b))
	  switch(select(max(schpw, svc_maxfd) + 1,
			(fd_set *) &rfd, NULL, NULL, &timeout)) {
	  case -1:
	       if(errno == EINTR)
		    continue;
	       perror("select");
	       return;
	  case 0:
	       reset_db();
	       break;
	  default:
	      if (FD_ISSET(schpw, &rfd))
		  do_schpw(schpw, params);
	      else
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
 * Function: request_hup
 * 
 * Purpose: sets flag saying the server got a signal and that it should
 *		reset the database files when convenient.
 *
 * Arguments:
 * Requires:
 * Effects:
 * Modifies:
 *	sets signal_request_hup to one
 */

void request_hup(int signum)
{
     signal_request_hup = 1;
     return;
}

/*
 * Function: reset_db
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
     char *errmsg;
     
     if (ret = kadm5_flush(global_server_handle)) {
	  krb5_klog_syslog(LOG_ERR, "FATAL ERROR!  %s while flushing databases.  "
		 "Databases may be corrupt!  Aborting.",
		 krb5_get_error_message (context, ret));
	  krb5_klog_close(context);
	  exit(3);
     }
#endif

     return;
}

/*
 * Function: request_exit
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
     struct procnames {
	  rpcproc_t proc;
	  const char *proc_name;
     };
     static const struct procnames proc_names[] = {
	  {1, "CREATE_PRINCIPAL"},
	  {2, "DELETE_PRINCIPAL"},
	  {3, "MODIFY_PRINCIPAL"},
	  {4, "RENAME_PRINCIPAL"},
	  {5, "GET_PRINCIPAL"},
	  {6, "CHPASS_PRINCIPAL"},
	  {7, "CHRAND_PRINCIPAL"},
	  {8, "CREATE_POLICY"},
	  {9, "DELETE_POLICY"},
	  {10, "MODIFY_POLICY"},
	  {11, "GET_POLICY"},
	  {12, "GET_PRIVS"},
	  {13, "INIT"},
	  {14, "GET_PRINCS"},
	  {15, "GET_POLS"},
	  {16, "SETKEY_PRINCIPAL"},
	  {17, "SETV4KEY_PRINCIPAL"},
	  {18, "CREATE_PRINCIPAL3"},
	  {19, "CHPASS_PRINCIPAL3"},
	  {20, "CHRAND_PRINCIPAL3"},
	  {21, "SETKEY_PRINCIPAL3"}
     };
#define NPROCNAMES (sizeof (proc_names) / sizeof (struct procnames))
     OM_uint32 minor;
     gss_buffer_desc client, server;
     gss_OID gss_type;
     char *a;
     rpcproc_t proc;
     int i;
     const char *procname;
     size_t clen, slen;
     char *cdots, *sdots;

     client.length = 0;
     client.value = NULL;
     server.length = 0;
     server.value = NULL;

     (void) gss_display_name(&minor, client_name, &client, &gss_type);
     (void) gss_display_name(&minor, server_name, &server, &gss_type);
     if (client.value == NULL) {
	 client.value = "(null)";
	 clen = sizeof("(null)") -1;
     } else {
	 clen = client.length;
     }
     trunc_name(&clen, &cdots);
     if (server.value == NULL) {
	 server.value = "(null)";
	 slen = sizeof("(null)") - 1;
     } else {
	 slen = server.length;
     }
     trunc_name(&slen, &sdots);
     a = inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr);

     proc = msg->rm_call.cb_proc;
     procname = NULL;
     for (i = 0; i < NPROCNAMES; i++) {
	  if (proc_names[i].proc == proc) {
	       procname = proc_names[i].proc_name;
	       break;
	  }
     }
     if (procname != NULL)
	  krb5_klog_syslog(LOG_NOTICE, "WARNING! Forged/garbled request: %s, "
			   "claimed client = %.*s%s, server = %.*s%s, addr = %s",
			   procname, clen, client.value, cdots,
			   slen, server.value, sdots, a);
     else
	  krb5_klog_syslog(LOG_NOTICE, "WARNING! Forged/garbled request: %d, "
			   "claimed client = %.*s%s, server = %.*s%s, addr = %s",
			   proc, clen, client.value, cdots,
			   slen, server.value, sdots, a);

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
     OM_uint32 msg_ctx;

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

void do_schpw(int s1, kadm5_config_params *params)
{
    krb5_error_code ret;
    /* XXX buffer = ethernet mtu */
    char req[1500];
    int len;
    struct sockaddr_in from;
    socklen_t fromlen;
    krb5_keytab kt;
    krb5_data reqdata, repdata;
    int s2;

    fromlen = sizeof(from);
    if ((len = recvfrom(s1, req, sizeof(req), 0, (struct sockaddr *)&from,
			&fromlen)) < 0) {
	krb5_klog_syslog(LOG_ERR, "chpw: Couldn't receive request: %s",
			 krb5_get_error_message (context, errno));
	return;
    }

    if ((ret = krb5_kt_resolve(context, "KDB:", &kt))) {
	krb5_klog_syslog(LOG_ERR, "chpw: Couldn't open admin keytab %s",
			 krb5_get_error_message (context, ret));
	return;
    }

    reqdata.length = len;
    reqdata.data = req;

    /* this is really obscure.  s1 is used for all communications.  it
       is left unconnected in case the server is multihomed and routes
       are asymmetric.  s2 is connected to resolve routes and get
       addresses.  this is the *only* way to get proper addresses for
       multihomed hosts if routing is asymmetric.  

       A related problem in the server, but not the client, is that
       many os's have no way to disconnect a connected udp socket, so
       the s2 socket needs to be closed and recreated for each
       request.  The s1 socket must not be closed, or else queued
       requests will be lost.

       A "naive" client implementation (one socket, no connect,
       hostname resolution to get the local ip addr) will work and
       interoperate if the client is single-homed. */

    if ((s2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	const char *errmsg = krb5_get_error_message (context, errno);
	krb5_klog_syslog(LOG_ERR, "cannot create connecting socket: %s",
			 errmsg);
	fprintf(stderr, "Cannot create connecting socket: %s",
		errmsg);
	svcauth_gssapi_unset_names();
	kadm5_destroy(global_server_handle);
	krb5_klog_close(context);	  
	exit(1);
    }

    if (connect(s2, (struct sockaddr *) &from, sizeof(from)) < 0) {
	krb5_klog_syslog(LOG_ERR, "chpw: Couldn't connect to client: %s",
			 krb5_get_error_message (context, errno));
	goto cleanup;
    }

    if ((ret = process_chpw_request(context, global_server_handle,
				    params->realm, s2, kt, &from,
				    &reqdata, &repdata))) {
	krb5_klog_syslog(LOG_ERR, "chpw: Error processing request: %s", 
			 krb5_get_error_message (context, ret));
    }

    close(s2);

    if (repdata.length == 0) {
	/* just return.  This means something really bad happened */
        goto cleanup;
    }

    len = sendto(s1, repdata.data, (int) repdata.length, 0,
		 (struct sockaddr *) &from, sizeof(from));

    if (len < (int) repdata.length) {
	krb5_xfree(repdata.data);

	krb5_klog_syslog(LOG_ERR, "chpw: Error sending reply: %s", 
			 krb5_get_error_message (context, errno));
	goto cleanup;
    }

    krb5_xfree(repdata.data);

cleanup:
    krb5_kt_close(context, kt);

    return;
}
