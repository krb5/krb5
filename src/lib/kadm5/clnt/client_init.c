/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
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

#include <stdio.h>
#include <netdb.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <string.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <krb5.h>
#include <k5-int.h> /* for KRB5_ADM_DEFAULT_PORT */
#ifdef __STDC__
#include <stdlib.h>
#endif

#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include "client_internal.h"

#include <gssrpc/rpc.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssrpc/auth_gssapi.h>

#define	ADM_CCACHE  "/tmp/ovsec_adm.XXXXXX"

static int old_auth_gssapi = 0;

enum init_type { INIT_PASS, INIT_SKEY, INIT_CREDS };

static kadm5_ret_t _kadm5_init_any(char *client_name,
				   enum init_type init_type,
				   char *pass,
				   krb5_ccache ccache_in,
				   char *service_name,
				   kadm5_config_params *params,
				   krb5_ui_4 struct_version,
				   krb5_ui_4 api_version,
				   void **server_handle);

kadm5_ret_t kadm5_init_with_creds(char *client_name,
				  krb5_ccache ccache,
				  char *service_name,
				  kadm5_config_params *params,
				  krb5_ui_4 struct_version,
				  krb5_ui_4 api_version,
				  void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_CREDS, NULL, ccache,
			    service_name, params,
			    struct_version, api_version,
			    server_handle);
}


kadm5_ret_t kadm5_init_with_password(char *client_name, char *pass,
				     char *service_name,
				     kadm5_config_params *params,
				     krb5_ui_4 struct_version,
				     krb5_ui_4 api_version,
				     void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_PASS, pass, NULL,
			    service_name, params, struct_version,
			    api_version, server_handle);
}

kadm5_ret_t kadm5_init(char *client_name, char *pass,
		       char *service_name, 
		       kadm5_config_params *params,
		       krb5_ui_4 struct_version,
		       krb5_ui_4 api_version,
		       void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_PASS, pass, NULL,
			    service_name, params, struct_version,
			    api_version, server_handle);
}

kadm5_ret_t kadm5_init_with_skey(char *client_name, char *keytab,
				 char *service_name,
				 kadm5_config_params *params,
				 krb5_ui_4 struct_version,
				 krb5_ui_4 api_version,
				 void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_SKEY, keytab, NULL,
			    service_name, params, struct_version,
			    api_version, server_handle);
}

/*
 * Try no preauthentication first; then try the encrypted timestamp
 * (stolen from krb5 kinit.c)
 */
static int preauth_search_list[] = {
     0,			
     KRB5_PADATA_ENC_UNIX_TIME,
     -1
};

static kadm5_ret_t _kadm5_init_any(char *client_name,
				   enum init_type init_type,
				   char *pass,
				   krb5_ccache ccache_in,
				   char *service_name,
				   kadm5_config_params *params_in,
				   krb5_ui_4 struct_version,
				   krb5_ui_4 api_version,
				   void **server_handle)
{
     struct sockaddr_in addr;
     struct hostent *hp;
     int fd;
     int i;

     char full_service_name[BUFSIZ], *ccname_orig;
     const char *c_ccname_orig; 
     char *realm;
     krb5_creds	creds;
     krb5_ccache ccache = NULL;
     krb5_timestamp  now;
     
     OM_uint32 gssstat, minor_stat;
     gss_buffer_desc input_name;
     gss_name_t gss_client;
     gss_name_t gss_target;
     gss_cred_id_t gss_client_creds = GSS_C_NO_CREDENTIAL;

     kadm5_server_handle_t handle;
     kadm5_config_params params_local;

     int code = 0;
     generic_ret *r;
     char svcname[MAXHOSTNAMELEN + 8];

     initialize_ovk_error_table();
     initialize_adb_error_table();
     initialize_ovku_error_table();
     
     if (! server_handle) {
	 return EINVAL;
     }

     if (! (handle = malloc(sizeof(*handle)))) {
	  return ENOMEM;
     }
     if (! (handle->lhandle = malloc(sizeof(*handle)))) {
	  free(handle);
	  return ENOMEM;
     }

     handle->magic_number = KADM5_SERVER_HANDLE_MAGIC;
     handle->struct_version = struct_version;
     handle->api_version = api_version;
     handle->clnt = 0;
     handle->cache_name = 0;
     handle->destroy_cache = 0;
     *handle->lhandle = *handle;
     handle->lhandle->api_version = KADM5_API_VERSION_2;
     handle->lhandle->struct_version = KADM5_STRUCT_VERSION;
     handle->lhandle->lhandle = handle->lhandle;

     krb5_init_context(&handle->context);

     if(client_name == NULL) {
	free(handle);
	return EINVAL;
     }
     memset((char *) &creds, 0, sizeof(creds));

     /*
      * Verify the version numbers before proceeding; we can't use
      * CHECK_HANDLE because not all fields are set yet.
      */
     GENERIC_CHECK_HANDLE(handle, KADM5_OLD_LIB_API_VERSION,
			  KADM5_NEW_LIB_API_VERSION);
     
     /*
      * Acquire relevant profile entries.  In version 2, merge values
      * in params_in with values from profile, based on
      * params_in->mask.
      *
      * In version 1, we've given a realm (which may be NULL) instead
      * of params_in.  So use that realm, make params_in contain an
      * empty mask, and behave like version 2.
      */
     memset((char *) &params_local, 0, sizeof(params_local));
     if (api_version == KADM5_API_VERSION_1) {
	  realm = params_local.realm = (char *) params_in;
	  if (params_in)
	       params_local.mask = KADM5_CONFIG_REALM;

	  /* Use old AUTH_GSSAPI for version 1 protocol. */
	  params_local.mask |= KADM5_CONFIG_OLD_AUTH_GSSAPI;
	  params_in = &params_local;
     } else {
	  if (params_in && (params_in->mask & KADM5_CONFIG_REALM))
	       realm = params_in->realm;
	  else
	       realm = NULL;
     }

#define ILLEGAL_PARAMS (KADM5_CONFIG_DBNAME | KADM5_CONFIG_ADBNAME | \
			KADM5_CONFIG_ADB_LOCKFILE | \
			KADM5_CONFIG_ACL_FILE | KADM5_CONFIG_DICT_FILE \
			| KADM5_CONFIG_ADMIN_KEYTAB | \
			KADM5_CONFIG_STASH_FILE | \
			KADM5_CONFIG_MKEY_NAME | KADM5_CONFIG_ENCTYPE \
			| KADM5_CONFIG_MAX_LIFE | \
			KADM5_CONFIG_MAX_RLIFE | \
			KADM5_CONFIG_EXPIRATION | KADM5_CONFIG_FLAGS | \
			KADM5_CONFIG_ENCTYPES | KADM5_CONFIG_MKEY_FROM_KBD)

     if (params_in && params_in->mask & ILLEGAL_PARAMS) {
	  free(handle);
	  return KADM5_BAD_CLIENT_PARAMS;
     }
			
     if ((code = kadm5_get_config_params(handle->context,
					DEFAULT_PROFILE_PATH,
					"KRB5_CONFIG",
					params_in,
					&handle->params))) {
	  krb5_free_context(handle->context);
	  free(handle);
	  return(code);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | \
			 KADM5_CONFIG_ADMIN_SERVER | \
			 KADM5_CONFIG_KADMIND_PORT) 

     if ((handle->params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) {
	  krb5_free_context(handle->context);
	  free(handle);
	  return KADM5_MISSING_KRB5_CONF_PARAMS;
     }

     /* NULL service_name means use host-based. */
     if (service_name == NULL) {
	  code = kadm5_get_admin_service_name(handle->context,
					      handle->params.realm,
					      svcname, sizeof(svcname));
	  if (code) {
	       krb5_free_context(handle->context);
	       free(handle);
	       return KADM5_MISSING_KRB5_CONF_PARAMS;
	  }
	  service_name = svcname;
     }
     /*
      * Acquire a service ticket for service_name@realm in the name of
      * client_name, using password pass (which could be NULL), and
      * create a ccache to store them in.  If INIT_CREDS, use the
      * ccache we were provided instead.
      */
     
     if ((code = krb5_parse_name(handle->context, client_name, &creds.client)))
	  goto error;

     if (realm) {
          if(strlen(service_name) + strlen(realm) + 1 >= sizeof(full_service_name)) {
	      goto error;
	  }
	  sprintf(full_service_name, "%s@%s", service_name, realm);
     } else {
	  /* krb5_princ_realm(creds.client) is not null terminated */
          if(strlen(service_name) + krb5_princ_realm(handle->context, creds.client)->length + 1 >= sizeof(full_service_name)) {
	      goto error;
	  }
	  strcpy(full_service_name, service_name);
	  strcat(full_service_name, "@");
	  strncat(full_service_name, krb5_princ_realm(handle->context,
						      creds.client)->data, 
		  krb5_princ_realm(handle->context, creds.client)->length);
     }
     
     if ((code = krb5_parse_name(handle->context, full_service_name,
	  &creds.server))) 
	  goto error;

     /* XXX temporarily fix a bug in krb5_cc_get_type */
#undef krb5_cc_get_type
#define krb5_cc_get_type(context, cache) ((cache)->ops->prefix)
     

     if (init_type == INIT_CREDS) {
	  ccache = ccache_in;
	  handle->cache_name = (char *)
	       malloc(strlen(krb5_cc_get_type(handle->context, ccache)) +
		      strlen(krb5_cc_get_name(handle->context, ccache)) + 2);
	  if (handle->cache_name == NULL) {
	       code = ENOMEM;
	       goto error;
	  }
	  sprintf(handle->cache_name, "%s:%s",
		  krb5_cc_get_type(handle->context, ccache),
		  krb5_cc_get_name(handle->context, ccache));
     } else {
#if 0
	  handle->cache_name =
	       (char *) malloc(strlen(ADM_CCACHE)+strlen("FILE:")+1);
	  if (handle->cache_name == NULL) {
	       code = ENOMEM;
	       goto error;
	  }
	  sprintf(handle->cache_name, "FILE:%s", ADM_CCACHE);
	  mktemp(handle->cache_name + strlen("FILE:"));
#else
	  {
	      static int counter = 0;
	      handle->cache_name = malloc(sizeof("MEMORY:kadm5_")
					  + 3*sizeof(counter));
	      sprintf(handle->cache_name, "MEMORY:kadm5_%u", counter++);
	  }
#endif
     
	  if ((code = krb5_cc_resolve(handle->context, handle->cache_name,
				      &ccache))) 
	       goto error;
	  
	  if ((code = krb5_cc_initialize (handle->context, ccache,
					  creds.client))) 
	       goto error;

	  handle->destroy_cache = 1;
     }
     handle->lhandle->cache_name = handle->cache_name;
     
     if ((code = krb5_timeofday(handle->context, &now)))
	  goto error;

     /*
      * Get a ticket, use the method specified in init_type.
      */
     
     creds.times.starttime = 0; /* start timer at KDC */
     creds.times.endtime = 0; /* endtime will be limited by service */

     if (init_type == INIT_PASS) {
	  for (i=0; preauth_search_list[i] >= 0; i++) {
	       code = krb5_get_in_tkt_with_password(handle->context,
						    0, /* no options */
						    0, /* default addresses */
						    0,	  /* enctypes */
						    NULL, /* XXX preauth */
						    pass,
						    ccache,
						    &creds,
						    NULL);
	       if (code != KRB5KDC_ERR_PREAUTH_FAILED &&
		   code != KRB5KDC_ERR_PREAUTH_REQUIRED &&
		   code != KRB5KRB_ERR_GENERIC)
		    break;
	  }
     } else if (init_type == INIT_SKEY) {
	  krb5_keytab kt = NULL;

	  if (pass && (code = krb5_kt_resolve(handle->context, pass, &kt)))
	       ;
	  else {
	       for (i=0; preauth_search_list[i] >= 0; i++) {
		    code = krb5_get_in_tkt_with_keytab(handle->context,
						       0, /* no options */
						       0, /* default addrs */
						       0,    /* enctypes */
						       NULL, /* XXX preauth */
						       kt,
						       ccache,
						       &creds,
						       NULL);
		    if (code != KRB5KDC_ERR_PREAUTH_FAILED &&
			code != KRB5KDC_ERR_PREAUTH_REQUIRED &&
			code != KRB5KRB_ERR_GENERIC)
			 break;
	       }

	       if (pass) krb5_kt_close(handle->context, kt);
	  }
     }

     /* Improved error messages */
     if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY) code = KADM5_BAD_PASSWORD;
     if (code == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
	  code = KADM5_SECURE_PRINC_MISSING;

     if (code != 0) goto error;

#ifdef ZEROPASSWD
     if (pass != NULL)
	  memset(pass, 0, strlen(pass));
#endif

     /*
      * We have ticket; open the RPC connection.
      */

     hp = gethostbyname(handle->params.admin_server);
     if (hp == (struct hostent *) NULL) {
	  code = KADM5_BAD_SERVER_NAME;
	  goto cleanup;
     }

     memset(&addr, 0, sizeof(addr));
     addr.sin_family = hp->h_addrtype;
     (void) memcpy((char *) &addr.sin_addr, (char *) hp->h_addr,
		   sizeof(addr.sin_addr));
     addr.sin_port = htons((u_short) handle->params.kadmind_port);
     
     fd = RPC_ANYSOCK;
     
     handle->clnt = clnttcp_create(&addr, KADM, KADMVERS, &fd, 0, 0);
     if (handle->clnt == NULL) {
	  code = KADM5_RPC_ERROR;
#ifdef DEBUG
	  clnt_pcreateerror("clnttcp_create");
#endif
	  goto error;
     }
     handle->lhandle->clnt = handle->clnt;

     /* now that handle->clnt is set, we can check the handle */
     if ((code = _kadm5_check_handle((void *) handle)))
	  goto error;

     /*
      * The RPC connection is open; establish the GSS-API
      * authentication context.
      */

     /* use the kadm5 cache */
     gssstat = gss_krb5_ccache_name(&minor_stat, handle->cache_name,
				    &c_ccname_orig);
     if (gssstat != GSS_S_COMPLETE) {
	 code = KADM5_GSS_ERROR;
	 goto error;
     }
     if (c_ccname_orig)
	  ccname_orig = strdup(c_ccname_orig);
     else
       ccname_orig = 0;

     input_name.value = full_service_name;
     input_name.length = strlen((char *)input_name.value) + 1;
     gssstat = gss_import_name(&minor_stat, &input_name,
			       (gss_OID) gss_nt_krb5_name, &gss_target);
     if (gssstat != GSS_S_COMPLETE) {
	  code = KADM5_GSS_ERROR;
	  goto error;
     }

     input_name.value = client_name;
     input_name.length = strlen((char *)input_name.value) + 1;
     gssstat = gss_import_name(&minor_stat, &input_name,
			       (gss_OID) gss_nt_krb5_name, &gss_client);
     if (gssstat != GSS_S_COMPLETE) {
	  code = KADM5_GSS_ERROR;
	  goto error;
     }

     gssstat = gss_acquire_cred(&minor_stat, gss_client, 0,
				GSS_C_NULL_OID_SET, GSS_C_INITIATE,
				&gss_client_creds, NULL, NULL);
     (void) gss_release_name(&minor_stat, &gss_client);
     if (gssstat != GSS_S_COMPLETE) {
	  code = KADM5_GSS_ERROR;
	  goto error;
     }
     
     if (params_in != NULL &&
	 (params_in->mask & KADM5_CONFIG_OLD_AUTH_GSSAPI)) {
	  handle->clnt->cl_auth = auth_gssapi_create(handle->clnt,
						     &gssstat,
						     &minor_stat,
						     gss_client_creds,
						     gss_target,
						     (gss_OID) gss_mech_krb5,
						     GSS_C_MUTUAL_FLAG
						     | GSS_C_REPLAY_FLAG,
						     0,
						     NULL,
						     NULL,
						     NULL);
     } else if (params_in == NULL ||
		!(params_in->mask & KADM5_CONFIG_NO_AUTH)) {
	  struct rpc_gss_sec sec;
	  sec.mech = gss_mech_krb5;
	  sec.qop = GSS_C_QOP_DEFAULT;
	  sec.svc = RPCSEC_GSS_SVC_PRIVACY;
	  sec.cred = gss_client_creds;
	  sec.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

	  handle->clnt->cl_auth = authgss_create(handle->clnt,
						 gss_target, &sec);
     }
     (void) gss_release_name(&minor_stat, &gss_target);

     if (ccname_orig) {
	 gssstat = gss_krb5_ccache_name(&minor_stat, ccname_orig, NULL);
	 if (gssstat) {
	     code = KADM5_GSS_ERROR;
	     goto error;
	 }
	 free(ccname_orig);
     } else {
	 gssstat = gss_krb5_ccache_name(&minor_stat, NULL, NULL);
	 if (gssstat) {
	     code = KADM5_GSS_ERROR;
	     goto error;
	 }
     }
     
     if (handle->clnt->cl_auth == NULL) {
	  code = KADM5_GSS_ERROR;
	  goto error;
     }

     r = init_1(&handle->api_version, handle->clnt);
     if (r == NULL) {
	  code = KADM5_RPC_ERROR;
#ifdef DEBUG
	  clnt_perror(handle->clnt, "init_1 null resp");
#endif
	  goto error;
     }
     if (r->code) {
	  code = r->code;
	  goto error;
     }

     *server_handle = (void *) handle;

     if (init_type != INIT_CREDS) 
	  krb5_cc_close(handle->context, ccache);

     goto cleanup;
     
error:
     /*
      * Note that it is illegal for this code to execute if "handle"
      * has not been allocated and initialized.  I.e., don't use "goto
      * error" before the block of code at the top of the function
      * that allocates and initializes "handle".
      */
     if (handle->cache_name)
	 free(handle->cache_name);
     if (handle->destroy_cache && ccache)
	 krb5_cc_destroy(handle->context, ccache);
     if(handle->clnt && handle->clnt->cl_auth)
	  AUTH_DESTROY(handle->clnt->cl_auth);
     if(handle->clnt)
	  clnt_destroy(handle->clnt);

cleanup:
     krb5_free_cred_contents(handle->context, &creds);
     if (gss_client_creds != GSS_C_NO_CREDENTIAL)
	  (void) gss_release_cred(&minor_stat, &gss_client_creds);

     if (code)
	  free(handle);

     return code;
}

kadm5_ret_t
kadm5_destroy(void *server_handle)
{
     krb5_ccache	    ccache = NULL;
     int		    code = KADM5_OK;
     kadm5_server_handle_t	handle =
	  (kadm5_server_handle_t) server_handle;

     CHECK_HANDLE(server_handle);

     if (handle->destroy_cache && handle->cache_name) {
	 if ((code = krb5_cc_resolve(handle->context,
				     handle->cache_name, &ccache)) == 0) 
	     code = krb5_cc_destroy (handle->context, ccache);
     }
     if (handle->cache_name)
	 free(handle->cache_name);
     if (handle->clnt && handle->clnt->cl_auth)
	  AUTH_DESTROY(handle->clnt->cl_auth);
     if (handle->clnt)
	  clnt_destroy(handle->clnt);
     if (handle->lhandle)
          free (handle->lhandle);

     kadm5_free_config_params(handle->context, &handle->params);
     krb5_free_context(handle->context);

     handle->magic_number = 0;
     free(handle);

     return code;
}
/* not supported on client */
kadm5_ret_t kadm5_lock(void *server_handle)
{
    return EINVAL;
}

/* not supported on client */
kadm5_ret_t kadm5_unlock(void *server_handle)
{
    return EINVAL;
}

kadm5_ret_t kadm5_flush(void *server_handle)
{
     return KADM5_OK;
}

int _kadm5_check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}
