/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.16  1996/10/15 20:15:06  bjaspan
 * 	* initial changes to make rpc unit tests work with new build/test
 *  	system
 *
 * Revision 1.15  1996/07/22 20:41:44  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.14.4.1  1996/07/18 04:20:06  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.14.2.1  1996/06/20  23:42:16  marc
 * File added to the repository on a branch
 *
 * Revision 1.14  1996/05/12  06:59:06  marc
 * change SERVICE_NAME to "host" instead of "server"
 *
 * remove KRB5KTNAME support, since the library supports it internally now.
 *
 * Revision 1.13  1995/12/07  17:36:58  jik
 * Use "rpc_test" instead of "rpc-test", to avoid problems with rpcgen on
 * some systems.  See PR 3553.
 *
 * Revision 1.12  1995/11/07 23:20:44  grier
 * Add stdlib.h
 * Add string.h
 *
 * Revision 1.11  1995/03/24  19:55:28  jik
 * Cast a const gss_OID to (gss_OID) to prevent a compiler warning.
 *
 * Revision 1.10  1995/02/22 15:54:17  jik
 * I was a moron in revision 1.8.  This is the server function, not the
 * client function, so it gets a struct svc_req *, not a CLIENT *.
 *
 * Revision 1.9  1995/02/22 15:21:51  jik
 * Linux's rpcgen names the server function differently from the client
 * function ("_svc" is appended to the end of it).
 *
 * Revision 1.8  1995/02/22 14:35:05  jik
 * RPC server functions have CLIENT * passed into them, so I added it as
 * an argument to rpc_test_echo_1.
 *
 * Revision 1.7  1994/09/21 18:35:57  bjaspan
 * [gssapi/438: gss_nt_service_name should default to local host]
 * [secure-releng/2513: audit gssapi/438: gss_nt_service_name should default to local host]
 *
 * Sandbox:
 *
 *  Don't need to get local host name and put it in the service name,
 *  since the gssapi library does that now.  See PR 438.
 *
 * Revision 1.8  1994/09/01  17:21:59  jik
 * Don't need to get local host name and put it in the service name,
 * since the gssapi library does that now.  See PR 438.
 *
 * Revision 1.7  1994/04/08  17:22:11  bjaspan
 * add KRB5KTNAME hack so unit tests continue to work
 *
 * Revision 1.6  1994/04/05  20:50:26  bjaspan
 * print "running" when ready to tests can proceed
 *
 * Revision 1.5  1994/04/05  19:49:54  jik
 * Use host name instead of localhost.
 *
 * Revision 1.4  1994/03/08  00:14:58  shanzer
 * changed call to inet_ntoa
 *
 * Revision 1.3  1993/12/13  01:37:54  bjaspan
 * update for new test system
 * ,.
 *
 * Revision 1.2  1993/12/08  21:45:16  bjaspan
 * display badauth errors, improve arg handling
 *
 * Revision 1.1  1993/11/03  23:53:58  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpc.h>
#include <arpa/inet.h>  /* inet_ntoa */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <rpc/auth_gssapi.h>
#include <sys/param.h>	/* MAXHOSTNAMELEN */
#include "rpc_test.h"

#ifdef linux
/*
  For some reason, Linux's rpcgen names the server function
  differently from the client function.  I suppose this is useful if
  you want to include them both in the same library or something, but
  not useful at all if you want to link the client code directly to
  the server code for testing, instead of going through the RPC layer.
  */
#define rpc_test_echo_1 rpc_test_echo_1_svc
#endif

extern void rpc_test_prog_1();

extern int svc_debug_gssapi, misc_debug_gssapi;

void rpc_test_badauth(OM_uint32 major, OM_uint32 minor,
		 struct sockaddr_in *addr, void *data);
void log_badauth_display_status(OM_uint32 major, OM_uint32 minor);
void log_badauth_display_status_1(OM_uint32 code, int type, int rec);
static void rpc_test_badverf(gss_name_t client, gss_name_t server,
			     struct svc_req *rqst, struct rpc_msg *msg,
			     caddr_t data);

#ifndef SERVICE_NAME
#define SERVICE_NAME "server"
#endif

main(int argc, char **argv)
{
     auth_gssapi_name names[2];
     register SVCXPRT *transp;

     names[0].name = SERVICE_NAME;
     names[0].type = (gss_OID) gss_nt_service_name;
     names[1].name = 0;
     names[1].type = 0;
     
     switch (argc) {
     case 3:
	  misc_debug_gssapi = atoi(argv[2]);
     case 2:
	  svc_debug_gssapi = atoi(argv[1]);
     case 1:
	  break;
     default:
	  fprintf(stderr, "Usage: server [svc-debug] [misc-debug]\n");
	  exit(1);
     }

     (void) pmap_unset(RPC_TEST_PROG, RPC_TEST_VERS_1);

     transp = svctcp_create(RPC_ANYSOCK, 0, 0);
     if (transp == NULL) {
	  fprintf(stderr, "cannot create tcp service.");
	  exit(1);
     }
     if (!svc_register(transp, RPC_TEST_PROG, RPC_TEST_VERS_1,
		       rpc_test_prog_1,  IPPROTO_TCP)) { 
	  fprintf(stderr,
		  "unable to register (RPC_TEST_PROG, RPC_TEST_VERS_1, tcp).");
	  exit(1);
     }
     
     if (_svcauth_gssapi_set_names(names, 0) == FALSE) {
	  fprintf(stderr, "unable to set gssapi names\n");
	  exit(1);
     }

     _svcauth_gssapi_set_log_badauth_func(rpc_test_badauth, NULL);
     _svcauth_gssapi_set_log_badverf_func(rpc_test_badverf, NULL);

     printf("running\n");
     
     svc_run();
     fprintf(stderr, "svc_run returned");
     exit(1);
     /* NOTREACHED */
}

char **rpc_test_echo_1(char **arg, struct svc_req *h)
{
     static char *res = NULL;

     if (res)
	  free(res);
     res = (char *) malloc(strlen(*arg) + strlen("Echo: ") + 1);
     sprintf(res, "Echo: %s", *arg);
     return &res;
}

static void rpc_test_badverf(gss_name_t client, gss_name_t server,
			     struct svc_req *rqst, struct rpc_msg *msg,
			     caddr_t data)
{
     OM_uint32 minor_stat;
     gss_OID type;
     gss_buffer_desc client_name, server_name;

     (void) gss_display_name(&minor_stat, client, &client_name, &type);
     (void) gss_display_name(&minor_stat, server, &server_name, &type);

     printf("rpc_test server: bad verifier from %s at %s:%d for %s\n",
	    client_name.value,
	    inet_ntoa(rqst->rq_xprt->xp_raddr.sin_addr), 
	    ntohs(rqst->rq_xprt->xp_raddr.sin_port),
	    server_name.value);

     (void) gss_release_buffer(&minor_stat, &client_name);
     (void) gss_release_buffer(&minor_stat, &server_name);
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
 * Logs the GSS-API error to stdout.
 */
void rpc_test_badauth(OM_uint32 major, OM_uint32 minor,
		 struct sockaddr_in *addr, void *data)
{
     char *a;
     
     /* Authentication attempt failed: <IP address>, <GSS-API error */
     /* strings> */

     a = inet_ntoa(addr->sin_addr);

     printf("rpc_test server: Authentication attempt failed: %s", a);
     log_badauth_display_status(major, minor);
     printf("\n");
}

void log_badauth_display_status(OM_uint32 major, OM_uint32 minor)
{
     log_badauth_display_status_1(major, GSS_C_GSS_CODE, 0);
     log_badauth_display_status_1(minor, GSS_C_MECH_CODE, 0);
}

void log_badauth_display_status_1(OM_uint32 code, int type, int rec)
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
		    log_badauth_display_status_1(gssstat,GSS_C_GSS_CODE,1); 
		    log_badauth_display_status_1(minor_stat,
						 GSS_C_MECH_CODE, 1);
	       } else
		    printf("GSS-API authentication error %s: "
			   "recursive failure!\n", msg);
	       return;
	  }
	  
	  printf(", %s", (char *)msg.value); 
	  (void) gss_release_buffer(&minor_stat, &msg);
	  
	  if (!msg_ctx)
	       break;
     }
}


#if 0

/* this hack is no longer necessary, since the library supports it
   internally */

/* This is a hack to change the default keytab name */

#include <krb5/krb5.h>
extern char *krb5_defkeyname;

krb5_error_code
krb5_kt_default_name(char *name, int namesize)
{
   char *ktname;

   if ((ktname = getenv("KRB5KTNAME")) == NULL)
      ktname = krb5_defkeyname;

   if (namesize < strlen(ktname)+1)
      return(KRB5_CONFIG_NOTENUFSPACE);

   strcpy(name, ktname);

   return(0);
}

#endif
