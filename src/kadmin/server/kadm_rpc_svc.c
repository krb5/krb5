/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 */

#include <stdio.h>
#include <gssrpc/rpc.h>
#include <syslog.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include "misc.h"

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
	  setkey_arg setkey_principal_1_arg;
	  setv4key_arg setv4key_principal_1_arg;
	  cprinc3_arg create_principal3_1_arg;
	  chpass3_arg chpass_principal3_1_arg;
	  chrand3_arg chrand_principal3_1_arg;
	  setkey3_arg setkey_principal3_1_arg;
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
	  local = (char *(*)()) create_principal_1_svc;
	  break;
	  
     case DELETE_PRINCIPAL:
	  xdr_argument = xdr_dprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) delete_principal_1_svc;
	  break;
	  
     case MODIFY_PRINCIPAL:
	  xdr_argument = xdr_mprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) modify_principal_1_svc;
	  break;
	  
     case RENAME_PRINCIPAL:
	  xdr_argument = xdr_rprinc_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) rename_principal_1_svc;
	  break;
	  
     case GET_PRINCIPAL:
	  xdr_argument = xdr_gprinc_arg;
	  xdr_result = xdr_gprinc_ret;
	  local = (char *(*)()) get_principal_1_svc;
	  break;

     case GET_PRINCS:
	  xdr_argument = xdr_gprincs_arg;
	  xdr_result = xdr_gprincs_ret;
	  local = (char *(*)()) get_princs_1_svc;
	  break;
	  
     case CHPASS_PRINCIPAL:
	  xdr_argument = xdr_chpass_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) chpass_principal_1_svc;
	  break;

     case SETV4KEY_PRINCIPAL:
	  xdr_argument = xdr_setv4key_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) setv4key_principal_1_svc;
	  break;

     case SETKEY_PRINCIPAL:
	  xdr_argument = xdr_setkey_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) setkey_principal_1_svc;
	  break;
	  
     case CHRAND_PRINCIPAL:
	  xdr_argument = xdr_chrand_arg;
	  xdr_result = xdr_chrand_ret;
	  local = (char *(*)()) chrand_principal_1_svc;
	  break;
	  
     case CREATE_POLICY:
	  xdr_argument = xdr_cpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) create_policy_1_svc;
	  break;
	  
     case DELETE_POLICY:
	  xdr_argument = xdr_dpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) delete_policy_1_svc;
	  break;
	  
     case MODIFY_POLICY:
	  xdr_argument = xdr_mpol_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) modify_policy_1_svc;
	  break;
	  
     case GET_POLICY:
	  xdr_argument = xdr_gpol_arg;
	  xdr_result = xdr_gpol_ret;
	  local = (char *(*)()) get_policy_1_svc;
	  break;

     case GET_POLS:
	  xdr_argument = xdr_gpols_arg;
	  xdr_result = xdr_gpols_ret;
	  local = (char *(*)()) get_pols_1_svc;
	  break;
	  
     case GET_PRIVS:
	  xdr_argument = xdr_u_int32;
	  xdr_result = xdr_getprivs_ret;
	  local = (char *(*)()) get_privs_1_svc;
	  break;

     case INIT:
	  xdr_argument = xdr_u_int32;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) init_1_svc;
	  break;

     case CREATE_PRINCIPAL3:
	  xdr_argument = xdr_cprinc3_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) create_principal3_1_svc;
	  break;

     case CHPASS_PRINCIPAL3:
	  xdr_argument = xdr_chpass3_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) chpass_principal3_1_svc;
	  break;

     case CHRAND_PRINCIPAL3:
	  xdr_argument = xdr_chrand3_arg;
	  xdr_result = xdr_chrand_ret;
	  local = (char *(*)()) chrand_principal3_1_svc;
	  break;

     case SETKEY_PRINCIPAL3:
	  xdr_argument = xdr_setkey3_arg;
	  xdr_result = xdr_generic_ret;
	  local = (char *(*)()) setkey_principal3_1_svc;
	  break;

     default:
	  krb5_klog_syslog(LOG_ERR, "Invalid KADM5 procedure number: %s, %d",
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
