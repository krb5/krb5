/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h> /* for gss_nt_krb5_name */
#include <krb5.h>
#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include <kadm5/server_internal.h>
#include <kadm5/server_acl.h>
#include <syslog.h>
#include <arpa/inet.h>  /* inet_ntoa */
#include <krb5/adm_proto.h>  /* krb5_klog_syslog */
#include "misc.h"

#define xdr_free gssrpc_xdr_free /* XXX kludge */

#define LOG_UNAUTH  "Unauthorized request: %s, %s, client=%s, service=%s, addr=%s"
#define	LOG_DONE    "Request: %s, %s, %s, client=%s, service=%s, addr=%s"

extern gss_name_t 			gss_changepw_name;
extern gss_name_t			gss_oldchangepw_name;
extern void *				global_server_handle;

#define CHANGEPW_SERVICE(rqstp) \
	(cmp_gss_names_rel_1(acceptor_name(rqstp->rq_svccred), gss_changepw_name) |\
	 (gss_oldchangepw_name && \
	  cmp_gss_names_rel_1(acceptor_name(rqstp->rq_svccred), \
			gss_oldchangepw_name)))


static int gss_to_krb5_name(kadm5_server_handle_t handle,
		     gss_name_t gss_name, krb5_principal *princ);

static int gss_name_to_string(gss_name_t gss_name, gss_buffer_desc *str);

static gss_name_t acceptor_name(gss_ctx_id_t context);

static int cmp_gss_names(gss_name_t n1, gss_name_t n2)
{
   OM_uint32 emaj, emin;
   int equal;

   if (GSS_ERROR(emaj = gss_compare_name(&emin, n1, n2, &equal)))
      return(0);

   return(equal);
}

/* Does a comparison of the names and then releases the first entity */
/* For use above in CHANGEPW_SERVICE */
static int cmp_gss_names_rel_1(gss_name_t n1, gss_name_t n2)
{
   OM_uint32 min_stat;
   int ret;

   ret = cmp_gss_names(n1, n2);
   if (n1) (void) gss_release_name(&min_stat, &n1);
   return ret;
}

/*
 * Function check_handle
 *
 * Purpose: Check a server handle and return a com_err code if it is
 * invalid or 0 if it is valid.
 *
 * Arguments:
 *
 * 	handle		The server handle.
 */

static int check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}

/*
 * Function: new_server_handle
 *
 * Purpose: Constructs a server handle suitable for passing into the
 * server library API functions, by folding the client's API version
 * and calling principal into the server handle returned by
 * kadm5_init.
 *
 * Arguments:
 * 	api_version	(input) The API version specified by the client
 * 	rqstp		(input) The RPC request
 * 	handle		(output) The returned handle
 *	<return value>	(output) An error code, or 0 if no error occurred
 * 
 * Effects:
 * 	Returns a pointer to allocated storage containing the server
 * 	handle.  If an error occurs, then no allocated storage is
 *	returned, and the return value of the function will be a
 * 	non-zero com_err code.
 *      
 *      The allocated storage for the handle should be freed with
 * 	free_server_handle (see below) when it is no longer needed.
 */

static kadm5_ret_t new_server_handle(krb5_ui_4 api_version,
					  struct svc_req *rqstp,
					  kadm5_server_handle_t
					  *out_handle)
{
     kadm5_server_handle_t handle;

     if (! (handle = (kadm5_server_handle_t)
	    malloc(sizeof(*handle))))
	  return ENOMEM;

     *handle = *(kadm5_server_handle_t)global_server_handle;
     handle->api_version = api_version;
     
     if (! gss_to_krb5_name(handle, rqstp->rq_clntcred,
			    &handle->current_caller)) {
	  free(handle);
	  return KADM5_FAILURE;
     }

     *out_handle = handle;
     return 0;
}

/*
 * Function: free_server_handle
 *
 * Purpose: Free handle memory allocated by new_server_handle
 *
 * Arguments:
 * 	handle		(input/output) The handle to free
 */
static void free_server_handle(kadm5_server_handle_t handle)
{
     krb5_free_principal(handle->context, handle->current_caller);
     free(handle);
}

/*
 * Function: setup_gss_names
 *
 * Purpose: Create printable representations of the client and server
 * names.
 *
 * Arguments:
 * 	rqstp		(r) the RPC request
 * 	client_name	(w) the gss_buffer_t for the client name
 * 	server_name	(w) the gss_buffer_t for the server name
 *
 * Effects:
 *
 * Unparses the client and server names into client_name and
 * server_name, both of which must be freed by the caller.  Returns 0
 * on success and -1 on failure.
 */
static 
int setup_gss_names(struct svc_req *rqstp,
		    gss_buffer_desc *client_name,
		    gss_buffer_desc *server_name)
{
     OM_uint32 maj_stat, min_stat;
     gss_name_t server_gss_name;

     if (gss_name_to_string(rqstp->rq_clntcred, client_name) != 0)
	  return -1;
     maj_stat = gss_inquire_context(&min_stat, rqstp->rq_svccred, NULL,
				    &server_gss_name, NULL, NULL, NULL,
				    NULL, NULL);
     if (maj_stat != GSS_S_COMPLETE) {
	  gss_release_buffer(&min_stat, client_name);
          gss_release_name(&min_stat, &server_gss_name);
	  return -1;
     }
     if (gss_name_to_string(server_gss_name, server_name) != 0) {
	  gss_release_buffer(&min_stat, client_name);
          gss_release_name(&min_stat, &server_gss_name);
	  return -1;
     }
     gss_release_name(&min_stat, &server_gss_name);
     return 0;
}

static gss_name_t acceptor_name(gss_ctx_id_t context)
{
     OM_uint32 maj_stat, min_stat;
     gss_name_t name;
     
     maj_stat = gss_inquire_context(&min_stat, context, NULL, &name,
				    NULL, NULL, NULL, NULL, NULL);
     if (maj_stat != GSS_S_COMPLETE)
	  return NULL;
     return name;
}
     
static int cmp_gss_krb5_name(kadm5_server_handle_t handle,
		      gss_name_t gss_name, krb5_principal princ)
{
     krb5_principal princ2;
     int status;

     if (! gss_to_krb5_name(handle, gss_name, &princ2))
	  return 0;
     status = krb5_principal_compare(handle->context, princ, princ2);
     krb5_free_principal(handle->context, princ2);
     return status;
}

static int gss_to_krb5_name(kadm5_server_handle_t handle,
		     gss_name_t gss_name, krb5_principal *princ)
{
     OM_uint32 status, minor_stat;
     gss_buffer_desc gss_str;
     gss_OID gss_type;
     int success;

     status = gss_display_name(&minor_stat, gss_name, &gss_str, &gss_type);
     if ((status != GSS_S_COMPLETE) || (gss_type != gss_nt_krb5_name))
	  return 0;
     success = (krb5_parse_name(handle->context, gss_str.value, princ) == 0);
     gss_release_buffer(&minor_stat, &gss_str);
     return success;
}

static int
gss_name_to_string(gss_name_t gss_name, gss_buffer_desc *str)
{
     OM_uint32 status, minor_stat;
     gss_OID gss_type;

     status = gss_display_name(&minor_stat, gss_name, str, &gss_type);
     if ((status != GSS_S_COMPLETE) || (gss_type != gss_nt_krb5_name))
	  return 1;
     return 0;
}

generic_ret *
create_principal_1_svc(cprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg;
    gss_buffer_desc		client_name, service_name;
    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;
    restriction_t		*rp;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (CHANGEPW_SERVICE(rqstp)
	|| !acl_check(handle->context, rqstp->rq_clntcred, ACL_ADD,
		      arg->rec.principal, &rp)
	|| acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_ADD;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_create_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code = kadm5_create_principal((void *)handle,
						&arg->rec, arg->mask,
						arg->passwd);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_create_principal",
		prime_arg,((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
create_principal3_1_svc(cprinc3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg;
    gss_buffer_desc		client_name, service_name;
    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;
    restriction_t		*rp;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (CHANGEPW_SERVICE(rqstp)
	|| !acl_check(handle->context, rqstp->rq_clntcred, ACL_ADD,
		      arg->rec.principal, &rp)
	|| acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_ADD;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_create_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code = kadm5_create_principal_3((void *)handle,
					     &arg->rec, arg->mask,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->passwd);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_create_principal",
		prime_arg,((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
delete_principal_1_svc(dprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }
    
    if (CHANGEPW_SERVICE(rqstp)
	|| !acl_check(handle->context, rqstp->rq_clntcred, ACL_DELETE,
		      arg->princ, NULL)) {
	 ret.code = KADM5_AUTH_DELETE;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_delete_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code = kadm5_delete_principal((void *)handle, arg->princ);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_delete_principal", prime_arg, 
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free(prime_arg);
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
modify_principal_1_svc(mprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;
    restriction_t		    *rp;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (CHANGEPW_SERVICE(rqstp)
	|| !acl_check(handle->context, rqstp->rq_clntcred, ACL_MODIFY,
		      arg->rec.principal, &rp)
	|| acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_MODIFY;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_modify_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code = kadm5_modify_principal((void *)handle, &arg->rec,
						arg->mask);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_modify_principal",
		prime_arg, ((ret.code == 0) ? "success" :
			    error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
rename_principal_1_svc(rprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg1,
				*prime_arg2;
    char			prime_arg[BUFSIZ];
    gss_buffer_desc		client_name,
				service_name;
    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;
    restriction_t		*rp;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->src, &prime_arg1) ||
        krb5_unparse_name(handle->context, arg->dest, &prime_arg2)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }
    sprintf(prime_arg, "%s to %s", prime_arg1, prime_arg2);

    ret.code = KADM5_OK;
    if (! CHANGEPW_SERVICE(rqstp)) {
	 if (!acl_check(handle->context, rqstp->rq_clntcred,
			ACL_DELETE, arg->src, NULL))
	      ret.code = KADM5_AUTH_DELETE;
	 /* any restrictions at all on the ADD kills the RENAME */
	 if (!acl_check(handle->context, rqstp->rq_clntcred,
			ACL_ADD, arg->dest, &rp) || rp) {
	      if (ret.code == KADM5_AUTH_DELETE)
		   ret.code = KADM5_AUTH_INSUFFICIENT;
	      else
		   ret.code = KADM5_AUTH_ADD;
	 }
    } else
	 ret.code = KADM5_AUTH_INSUFFICIENT;
    if (ret.code != KADM5_OK) {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_rename_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code = kadm5_rename_principal((void *)handle, arg->src,
						arg->dest);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_rename_principal",
		prime_arg, ((ret.code == 0) ? "success" :
			    error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg1);
    free(prime_arg2);    
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

gprinc_ret *
get_principal_1_svc(gprinc_arg *arg, struct svc_req *rqstp)
{
    static gprinc_ret		    ret;
    kadm5_principal_ent_t_v1	    e;
    char			    *prime_arg, *funcname;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_gprinc_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_get_principal (V1)" : "kadm5_get_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (! cmp_gss_krb5_name(handle, rqstp->rq_clntcred, arg->princ) &&
	(CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					       rqstp->rq_clntcred,
					       ACL_INQUIRE,
					       arg->princ,
					       NULL))) {
	 ret.code = KADM5_AUTH_GET;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, funcname,
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      ret.code  = kadm5_get_principal_v1((void *)handle,
						 arg->princ, &e); 
	      if(ret.code == KADM5_OK) {
		   memcpy(&ret.rec, e, sizeof(kadm5_principal_ent_rec_v1));
		   free(e);
	      }
	 } else {
	      ret.code  = kadm5_get_principal((void *)handle,
					      arg->princ, &ret.rec,
					      arg->mask);
	 }
	 
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, funcname,
		prime_arg,  
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

gprincs_ret *
get_princs_1_svc(gprincs_arg *arg, struct svc_req *rqstp)
{
    static gprincs_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_gprincs_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->exp;
    if (prime_arg == NULL)
	 prime_arg = "*";

    if (CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_LIST,
					      NULL,
					      NULL)) {
	 ret.code = KADM5_AUTH_LIST;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_get_principals",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code  = kadm5_get_principals((void *)handle,
					       arg->exp, &ret.princs,
					       &ret.count);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_get_principals",
		prime_arg,  
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
chpass_principal_1_svc(chpass_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (cmp_gss_krb5_name(handle, rqstp->rq_clntcred, arg->princ)) {
	 ret.code = chpass_principal_wrapper_3((void *)handle, arg->princ,
					       FALSE, 0, NULL, arg->pass);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_chpass_principal((void *)handle, arg->princ,
						arg->pass);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_chpass_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_chpass_principal", 
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }

    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
chpass_principal3_1_svc(chpass3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (cmp_gss_krb5_name(handle, rqstp->rq_clntcred, arg->princ)) {
	 ret.code = chpass_principal_wrapper_3((void *)handle, arg->princ,
					       arg->keepold,
					       arg->n_ks_tuple,
					       arg->ks_tuple,
					       arg->pass);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_chpass_principal_3((void *)handle, arg->princ,
					     arg->keepold,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->pass);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_chpass_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_chpass_principal", 
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }

    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
setv4key_principal_1_svc(setv4key_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setv4key_principal((void *)handle, arg->princ,
					     arg->keyblock);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_setv4key_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_setv4key_principal", 
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }

    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
setkey_principal_1_svc(setkey_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setkey_principal((void *)handle, arg->princ,
					   arg->keyblocks, arg->n_keys);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_setkey_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_setkey_principal", 
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }

    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
setkey_principal3_1_svc(setkey3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setkey_principal_3((void *)handle, arg->princ,
					     arg->keepold,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->keyblocks, arg->n_keys);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_setkey_principal",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_setkey_principal", 
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }

    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

chrand_ret *
chrand_principal_1_svc(chrand_arg *arg, struct svc_req *rqstp)
{
    static chrand_ret		ret;
    krb5_keyblock		*k;
    int				nkeys;
    char			*prime_arg, *funcname;
    gss_buffer_desc		client_name,
	    			service_name;
    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;

    xdr_free(xdr_chrand_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_randkey_principal (V1)" : "kadm5_randkey_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 free_server_handle(handle);
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (cmp_gss_krb5_name(handle, rqstp->rq_clntcred, arg->princ)) {
	 ret.code = randkey_principal_wrapper_3((void *)handle, arg->princ,
						FALSE, 0, NULL, &k, &nkeys);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_randkey_principal((void *)handle, arg->princ,
					    &k, &nkeys);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, funcname,
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      krb5_copy_keyblock_contents(handle->context, k, &ret.key);
	      krb5_free_keyblock(handle->context, k);
	 } else {
	      ret.keys = k;
	      ret.n_keys = nkeys;
	 }
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, funcname,
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

chrand_ret *
chrand_principal3_1_svc(chrand3_arg *arg, struct svc_req *rqstp)
{
    static chrand_ret		ret;
    krb5_keyblock		*k;
    int				nkeys;
    char			*prime_arg, *funcname;
    gss_buffer_desc		client_name,
	    			service_name;
    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;

    xdr_free(xdr_chrand_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_randkey_principal (V1)" : "kadm5_randkey_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 free_server_handle(handle);
	 return &ret;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 return &ret;
    }

    if (cmp_gss_krb5_name(handle, rqstp->rq_clntcred, arg->princ)) {
	 ret.code = randkey_principal_wrapper_3((void *)handle, arg->princ,
						arg->keepold,
						arg->n_ks_tuple,
						arg->ks_tuple,
						&k, &nkeys);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       acl_check(handle->context, rqstp->rq_clntcred,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_randkey_principal_3((void *)handle, arg->princ,
					      arg->keepold,
					      arg->n_ks_tuple,
					      arg->ks_tuple,
					      &k, &nkeys);
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, funcname,
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      krb5_copy_keyblock_contents(handle->context, k, &ret.key);
	      krb5_free_keyblock(handle->context, k);
	 } else {
	      ret.keys = k;
	      ret.n_keys = nkeys;
	 }
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	krb5_klog_syslog(LOG_NOTICE, LOG_DONE, funcname,
	       prime_arg, ((ret.code == 0) ? "success" :
			   error_message(ret.code)), 
	       client_name.value, service_name.value,
	       inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    free(prime_arg);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
create_policy_1_svc(cpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;    
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->rec.policy;

    if (CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_ADD, NULL, NULL)) {
	 ret.code = KADM5_AUTH_ADD;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_create_policy",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 
    } else {
	 ret.code = kadm5_create_policy((void *)handle, &arg->rec,
					     arg->mask);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_create_policy",
		((prime_arg == NULL) ? "(null)" : prime_arg),
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));	 
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
delete_policy_1_svc(dpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;    
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->name;
    
    if (CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_DELETE, NULL, NULL)) {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_delete_policy",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_DELETE;
    } else {
	 ret.code = kadm5_delete_policy((void *)handle, arg->name);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_delete_policy",
		((prime_arg == NULL) ? "(null)" : prime_arg),
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));	 
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

generic_ret *
modify_policy_1_svc(mpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;    
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_generic_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->rec.policy;

    if (CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_MODIFY, NULL, NULL)) {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_modify_policy",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
	 ret.code = KADM5_AUTH_MODIFY;
    } else {
	 ret.code = kadm5_modify_policy((void *)handle, &arg->rec,
					     arg->mask);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_modify_policy",
		((prime_arg == NULL) ? "(null)" : prime_arg),	    
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));	
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

gpol_ret * 
get_policy_1_svc(gpol_arg *arg, struct svc_req *rqstp)
{
    static gpol_ret		ret;
    kadm5_ret_t		ret2;
    char			*prime_arg, *funcname;
    gss_buffer_desc		client_name,
				service_name;
    OM_uint32			minor_stat;    
    kadm5_policy_ent_t	e;
    kadm5_principal_ent_rec	caller_ent;
    kadm5_server_handle_t	handle;

    xdr_free(xdr_gpol_ret,  &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_get_policy (V1)" : "kadm5_get_policy";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->name;

    ret.code = KADM5_AUTH_GET;
    if (!CHANGEPW_SERVICE(rqstp) && acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_INQUIRE, NULL, NULL))
	 ret.code = KADM5_OK;
    else {
	 ret.code = kadm5_get_principal(handle->lhandle,
					handle->current_caller,
					&caller_ent,
					KADM5_PRINCIPAL_NORMAL_MASK);
	 if (ret.code == KADM5_OK) {
	      if (caller_ent.aux_attributes & KADM5_POLICY &&
		  strcmp(caller_ent.policy, arg->name) == 0) {
		   ret.code = KADM5_OK;
	      } else ret.code = KADM5_AUTH_GET;
	      ret2 = kadm5_free_principal_ent(handle->lhandle,
					      &caller_ent);
	      ret.code = ret.code ? ret.code : ret2;
	 }
    }
    
    if (ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      ret.code  = kadm5_get_policy_v1((void *)handle, arg->name, &e);
	      if(ret.code == KADM5_OK) {
		   memcpy(&ret.rec, e, sizeof(kadm5_policy_ent_rec));
		   free(e);
	      }
	 } else {
	      ret.code = kadm5_get_policy((void *)handle, arg->name,
					  &ret.rec);
	 }
	 
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, funcname,
		((prime_arg == NULL) ? "(null)" : prime_arg),
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));	 
    } else {
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, funcname,
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;

}

gpols_ret *
get_pols_1_svc(gpols_arg *arg, struct svc_req *rqstp)
{
    static gpols_ret		    ret;
    char			    *prime_arg;
    gss_buffer_desc		    client_name,
				    service_name;
    OM_uint32			    minor_stat;
    kadm5_server_handle_t	    handle;

    xdr_free(xdr_gpols_ret, &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle))) {
	 free_server_handle(handle);
	 return &ret;
    }

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 return &ret;
    }
    prime_arg = arg->exp;
    if (prime_arg == NULL)
	 prime_arg = "*";

    if (CHANGEPW_SERVICE(rqstp) || !acl_check(handle->context,
					      rqstp->rq_clntcred,
					      ACL_LIST, NULL, NULL)) {
	 ret.code = KADM5_AUTH_LIST;
	 krb5_klog_syslog(LOG_NOTICE, LOG_UNAUTH, "kadm5_get_policies",
		prime_arg, client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    } else {
	 ret.code  = kadm5_get_policies((void *)handle,
					       arg->exp, &ret.pols,
					       &ret.count);
	 krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_get_policies",
		prime_arg,  
		((ret.code == 0) ? "success" : error_message(ret.code)), 
		client_name.value, service_name.value,
		inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
    }
    free_server_handle(handle);
    gss_release_buffer(&minor_stat, &client_name);
    gss_release_buffer(&minor_stat, &service_name);
    return &ret;
}

getprivs_ret * get_privs_1_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
{
     static getprivs_ret	    ret;
     gss_buffer_desc		    client_name, service_name;
     OM_uint32			    minor_stat;
     kadm5_server_handle_t	    handle;

     xdr_free(xdr_getprivs_ret, &ret);

     if ((ret.code = new_server_handle(*arg, rqstp, &handle)))
	  return &ret;

     if ((ret.code = check_handle((void *)handle))) {
	  free_server_handle(handle);
	  return &ret;
     }

     ret.api_version = handle->api_version;

     if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	  ret.code = KADM5_FAILURE;
	  return &ret;
     }

     ret.code = kadm5_get_privs((void *)handle, &ret.privs);
     krb5_klog_syslog(LOG_NOTICE, LOG_DONE, "kadm5_get_privs",
	    client_name.value, 
	    ((ret.code == 0) ? "success" : error_message(ret.code)), 
	    client_name.value, service_name.value,
	    inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
     free_server_handle(handle);
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
     return &ret;
}

generic_ret *init_1_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
{
     static generic_ret		ret;
     gss_buffer_desc		client_name,
	 			service_name;
     kadm5_server_handle_t	handle;
     OM_uint32			minor_stat;

     xdr_free(xdr_generic_ret, &ret);

     if ((ret.code = new_server_handle(*arg, rqstp, &handle)))
	  return &ret;
     if (! (ret.code = check_handle((void *)handle))) {
	 ret.api_version = handle->api_version;
     }

     free_server_handle(handle);

     if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	  ret.code = KADM5_FAILURE;
	  return &ret;
     }

     krb5_klog_syslog(LOG_NOTICE, LOG_DONE,
	    (ret.api_version == KADM5_API_VERSION_1 ?
	     "kadm5_init (V1)" : "kadm5_init"),
	    client_name.value,
	    (ret.code == 0) ? "success" : error_message(ret.code),
	    client_name.value, service_name.value,
	    inet_ntoa(rqstp->rq_xprt->xp_raddr.sin_addr));
     gss_release_buffer(&minor_stat, &client_name);
     gss_release_buffer(&minor_stat, &service_name);
	    
     return(&ret);
}
