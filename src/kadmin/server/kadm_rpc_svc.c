/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.12  1996/07/22 20:28:53  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.11.4.1  1996/07/18 03:03:35  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.11.2.2  1996/07/09 20:07:57  marc
 * 	* kadm_rpc_svc.c: renamed <ovsec_admin/foo.h> to <kadm5/foo.h>
 *
 * Revision 1.11.2.1  1996/06/20 21:56:44  marc
 * File added to the repository on a branch
 *
 * Revision 1.11  1996/06/17  19:49:28  bjaspan
 * use krb5_klog_syslog
 *
 * Revision 1.10  1996/05/29 21:07:53  bjaspan
 * be a bit more loud when warning, and don't exit when args can't be freed
 *
 * Revision 1.9  1996/05/20 21:34:56  bjaspan
 * log an error when sendreply fails
 *
 * Revision 1.8  1996/05/12 07:06:23  marc
 *  - fixup includes to match beta6
 *
 * Revision 1.7  1995/08/01  19:25:59  bjaspan
 * [secure/1318] allow retrieval of some/all principal/policy names
 *
 * Revision 1.6  1994/09/20  16:25:33  bjaspan
 * [secure-admin/2436: API versioning fixes to various admin files]
 * [secure-releng/2502: audit secure-admin/2436: random API versioning fixes]
 *
 * Sandbox:
 *
 *  More API versioning stuff -- need to add api_version field to RPC
 *  return structures in addition to calling structures.
 *
 * Revision 1.6  1994/09/12  20:19:16  jik
 * More API versioning stuff -- need to add api_version field to RPC
 * return structures in addition to calling structures.
 *
 * Revision 1.5  1994/08/16  18:55:46  jik
 * Versioning changes.
 *
 * Revision 1.4  1994/04/25  17:05:05  bjaspan
 * [secure-admin/1832] accept old gssapi number, log error when number
 * is wrong
 *
 * Revision 1.3  1993/11/15  02:30:54  shanzer
 * added funky procedure header comments.
 *
 * Revision 1.2  1993/11/10  23:11:21  bjaspan
 * added getprivs
 *
 * Revision 1.1  1993/11/05  07:09:00  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <memory.h>
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>

/*
 * Function: kadm_1
 * 
 * Purpose: RPC proccessing procedure.
 *	    originally generated from rpcgen
 *
 * Arguments:
 *	rqstp		    (input) rpc request structure
 *	transp		    (input) rpc transport structure
 *	(input/output)
 * 	<return value>
 *
 * Requires:
 * Effects:
 * Modifies:
 */

void kadm_1(rqstp, transp)
   struct svc_req *rqstp;
   register SVCXPRT *transp;
{
     union {
	  cprinc_arg create_principal_1_arg;
	  dprinc_arg delete_principal_1_arg;
	  mprinc_arg modify_principal_1_arg;
	  rprinc_arg rename_principal_1_arg;
	  gprinc_arg get_principal_1_arg;
	  chpass_arg chpass_principal_1_arg;
	  chrand_arg chrand_principal_1_arg;
	  cpol_arg create_policy_1_arg;
	  dpol_arg delete_policy_1_arg;
	  mpol_arg modify_policy_1_arg;
	  gpol_arg get_policy_1_arg;
     } argument;
     char *result;
     bool_t (*xdr_argument)(), (*xdr_result)();
     char *(*local)();

     if (rqstp->rq_cred.oa_flavor != AUTH_GSSAPI &&
	 rqstp->rq_cred.oa_flavor != AUTH_GSSAPI_COMPAT) {
	  krb5_klog_syslog(LOG_ERR, "Authentication attempt failed: %s, invalid "
		 "RPC authentication flavor %d",
		 inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr),
		 rqstp->rq_cred.oa_flavor);
	  svcerr_weakauth(transp);
	  return;
     }
     
     switch (rqstp->rq_proc) {
     case NULLPROC:
	  (void) svc_sendreply(transp, xdr_void, (char *)NULL);
	  return;
	  
     case CREATE_PRINCIPAL:
	  xdr_argument = xdr_cprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) create_principal_1;
	  break;
	  
     case DELETE_PRINCIPAL:
	  xdr_argument = xdr_dprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) delete_principal_1;
	  break;
	  
     case MODIFY_PRINCIPAL:
	  xdr_argument = xdr_mprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) modify_principal_1;
	  break;
	  
     case RENAME_PRINCIPAL:
	  xdr_argument = xdr_rprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) rename_principal_1;
	  break;
	  
     case GET_PRINCIPAL:
	  xdr_argument = xdr_gprinc_arg;
	  xdr_result = xdr_gprinc_ret;
	  local = (char *(*)()) get_principal_1;
	  break;

     case GET_PRINCS:
	  xdr_argument = xdr_gprincs_arg;
	  xdr_result = xdr_gprincs_ret;
	  local = (char *(*)()) get_princs_1;
	  break;
	  
     case CHPASS_PRINCIPAL:
	  xdr_argument = xdr_chpass_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) chpass_principal_1;
	  break;
	  
     case CHRAND_PRINCIPAL:
	  xdr_argument = xdr_chrand_arg;
	  xdr_result = xdr_chrand_ret;
	  local = (char *(*)()) chrand_principal_1;
	  break;
	  
     case CREATE_POLICY:
	  xdr_argument = xdr_cpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) create_policy_1;
	  break;
	  
     case DELETE_POLICY:
	  xdr_argument = xdr_dpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) delete_policy_1;
	  break;
	  
     case MODIFY_POLICY:
	  xdr_argument = xdr_mpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) modify_policy_1;
	  break;
	  
     case GET_POLICY:
	  xdr_argument = xdr_gpol_arg;
	  xdr_result = xdr_gpol_ret;
	  local = (char *(*)()) get_policy_1;
	  break;

     case GET_POLS:
	  xdr_argument = xdr_gpols_arg;
	  xdr_result = xdr_gpols_ret;
	  local = (char *(*)()) get_pols_1;
	  break;
	  
     case GET_PRIVS:
	  xdr_argument = xdr_u_int32;
	  xdr_result = xdr_getprivs_ret;
	  local = (char *(*)()) get_privs_1;
	  break;

     case INIT:
	  xdr_argument = xdr_u_int32;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) init_1;
	  break;

     default:
	  krb5_klog_syslog(LOG_ERR, "Invalid OVSEC_KADM procedure number: %s, %d",
		 inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr),
		 rqstp->rq_proc);
	  svcerr_noproc(transp);
	  return;
     }
     memset((char *)&argument, 0, sizeof(argument));
     if (!svc_getargs(transp, xdr_argument, &argument)) {
	  svcerr_decode(transp);
	  return;
     }
     result = (*local)(&argument, rqstp);
     if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
	  krb5_klog_syslog(LOG_ERR, "WARNING! Unable to send function results, "
		 "continuing.");
	  svcerr_systemerr(transp);
     }
     if (!svc_freeargs(transp, xdr_argument, &argument)) {
	  krb5_klog_syslog(LOG_ERR, "WARNING! Unable to free arguments, "
		 "continuing.");
     }
     return;
}
