/*
 * kdc/kdc_authdata.c
 *
 * Copyright (C) 2007 Apple Inc.  All Rights Reserved.
 * Copyright (C) 2008 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * AuthorizationData routines for the KDC.
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>
#include "adm_proto.h"

#include <syslog.h>

#include <assert.h>
#include "../include/krb5/authdata_plugin.h"

#if TARGET_OS_MAC
static const char *objdirs[] = { KRB5_AUTHDATA_PLUGIN_BUNDLE_DIR, LIBDIR "/krb5/plugins/authdata", NULL }; /* should be a list */
#else
static const char *objdirs[] = { LIBDIR "/krb5/plugins/authdata", NULL };
#endif

/* MIT Kerberos 1.6 (V0) authdata plugin callback */
typedef krb5_error_code (*authdata_proc_0)
    (krb5_context, krb5_db_entry *client,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_enc_tkt_part * enc_tkt_reply);
/* MIT Kerberos 1.7 (V1) authdata plugin callback */
typedef krb5_error_code (*authdata_proc_1)
    (krb5_context, unsigned int flags,
     krb5_db_entry *client, krb5_db_entry *server,
     krb5_db_entry *krbtgt,
     krb5_keyblock *client_key,
     krb5_keyblock *server_key,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_const_principal for_user_princ,
     krb5_enc_tkt_part *enc_tkt_request,
     krb5_enc_tkt_part *enc_tkt_reply);
typedef krb5_error_code (*init_proc)
    (krb5_context, void **);
typedef void (*fini_proc)
    (krb5_context, void *);

/* Internal authdata system for copying TGS-REQ authdata to ticket */
static krb5_error_code handle_request_authdata
    (krb5_context context,
     unsigned int flags,
     krb5_db_entry *client,
     krb5_db_entry *server,
     krb5_db_entry *krbtgt,
     krb5_keyblock *client_key,
     krb5_keyblock *server_key,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_const_principal for_user_princ,
     krb5_enc_tkt_part *enc_tkt_request,
     krb5_enc_tkt_part *enc_tkt_reply);

/* Internal authdata system for handling KDC-issued authdata */
static krb5_error_code handle_tgt_authdata
    (krb5_context context,
     unsigned int flags,
     krb5_db_entry *client,
     krb5_db_entry *server,
     krb5_db_entry *krbtgt,
     krb5_keyblock *client_key,
     krb5_keyblock *server_key,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_const_principal for_user_princ,
     krb5_enc_tkt_part *enc_tkt_request,
     krb5_enc_tkt_part *enc_tkt_reply);

typedef struct _krb5_authdata_systems {
    const char *name;
#define AUTHDATA_SYSTEM_UNKNOWN	-1
#define AUTHDATA_SYSTEM_V0	0
#define AUTHDATA_SYSTEM_V1	1
    int         type;
#define AUTHDATA_FLAG_CRITICAL	0x1
    int         flags;
    void       *plugin_context;
    init_proc   init;
    fini_proc   fini;
    union {
	authdata_proc_1 v1;
	authdata_proc_0 v0;
    } handle_authdata;
} krb5_authdata_systems;

static krb5_authdata_systems static_authdata_systems[] = {
    { "tgs_req", AUTHDATA_SYSTEM_V1, AUTHDATA_FLAG_CRITICAL, NULL, NULL, NULL, { handle_request_authdata } },
    { "tgt", AUTHDATA_SYSTEM_V1, AUTHDATA_FLAG_CRITICAL, NULL, NULL, NULL, { handle_tgt_authdata } },
};

static krb5_authdata_systems *authdata_systems;
static int n_authdata_systems;
static struct plugin_dir_handle authdata_plugins;

/* Load both v0 and v1 authdata plugins */
krb5_error_code
load_authdata_plugins(krb5_context context)
{
    void **authdata_plugins_ftables_v0 = NULL;
    void **authdata_plugins_ftables_v1 = NULL;
    size_t module_count;
    size_t i, k;
    init_proc server_init_proc = NULL;
    krb5_error_code code;

    /* Attempt to load all of the authdata plugins we can find. */
    PLUGIN_DIR_INIT(&authdata_plugins);
    if (PLUGIN_DIR_OPEN(&authdata_plugins) == 0) {
	if (krb5int_open_plugin_dirs(objdirs, NULL,
				     &authdata_plugins, &context->err) != 0) {
	    return KRB5_PLUGIN_NO_HANDLE;
	}
    }

    /* Get the method tables provided by the loaded plugins. */
    authdata_plugins_ftables_v0 = NULL;
    authdata_plugins_ftables_v1 = NULL;
    n_authdata_systems = 0;

    if (krb5int_get_plugin_dir_data(&authdata_plugins,
				    "authdata_server_1",
				    &authdata_plugins_ftables_v1, &context->err) != 0 ||
	krb5int_get_plugin_dir_data(&authdata_plugins,
				    "authdata_server_0",
				    &authdata_plugins_ftables_v0, &context->err) != 0) {
	code = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    }

    /* Count the valid modules. */ 
    module_count = sizeof(static_authdata_systems)
	/ sizeof(static_authdata_systems[0]);

    if (authdata_plugins_ftables_v1 != NULL) {
	struct krb5plugin_authdata_ftable_v1 *ftable;

	for (i = 0; authdata_plugins_ftables_v1[i] != NULL; i++) {
	    ftable = authdata_plugins_ftables_v1[i];
	    if (ftable->authdata_proc != NULL)
		module_count++;
	}
    }
 
    if (authdata_plugins_ftables_v0 != NULL) {
	struct krb5plugin_authdata_ftable_v0 *ftable;

	for (i = 0; authdata_plugins_ftables_v0[i] != NULL; i++) {
	    ftable = authdata_plugins_ftables_v0[i];
	    if (ftable->authdata_proc != NULL)
		module_count++;
	}
    }

    /* Build the complete list of supported authdata options, and
     * leave room for a terminator entry. */
    authdata_systems = calloc(module_count + 1, sizeof(krb5_authdata_systems));
    if (authdata_systems == NULL) {
	code = ENOMEM;
	goto cleanup;
    }

    /* Add the locally-supplied mechanisms to the dynamic list first. */
    for (i = 0, k = 0;
	 i < sizeof(static_authdata_systems) / sizeof(static_authdata_systems[0]);
	 i++) {
	authdata_systems[k] = static_authdata_systems[i];
	/* Try to initialize the authdata system.  If it fails, we'll remove it
	 * from the list of systems we'll be using. */
	server_init_proc = static_authdata_systems[i].init;
	if ((server_init_proc != NULL) &&
	    ((*server_init_proc)(context, &authdata_systems[k].plugin_context) != 0)) {
	    memset(&authdata_systems[k], 0, sizeof(authdata_systems[k]));
	    continue;
	}
	k++;
    }

    /* Add dynamically loaded V1 plugins */
    if (authdata_plugins_ftables_v1 != NULL) {
	struct krb5plugin_authdata_ftable_v1 *ftable;

	for (i = 0; authdata_plugins_ftables_v1[i] != NULL; i++) {
	    krb5_error_code initerr;
	    void *pctx = NULL;

	    ftable = authdata_plugins_ftables_v1[i];
	    if ((ftable->authdata_proc == NULL)) {
		continue;
	    }
	    server_init_proc = ftable->init_proc;
	    if ((server_init_proc != NULL) &&
		((initerr = (*server_init_proc)(context, &pctx)) != 0)) {
		const char *emsg;
		emsg = krb5_get_error_message(context, initerr);
		if (emsg) {
		    krb5_klog_syslog(LOG_ERR,
				     "authdata %s failed to initialize: %s",
				     ftable->name, emsg);
		    krb5_free_error_message(context, emsg);
		}
		memset(&authdata_systems[k], 0, sizeof(authdata_systems[k]));
	
		continue;
	    }
    
	    authdata_systems[k].name = ftable->name;
	    authdata_systems[k].type = AUTHDATA_SYSTEM_V1;
	    authdata_systems[k].init = server_init_proc;
	    authdata_systems[k].fini = ftable->fini_proc;
	    authdata_systems[k].handle_authdata.v1 = ftable->authdata_proc;
	    authdata_systems[k].plugin_context = pctx;
	    k++;
	}
    }

    /* Add dynamically loaded V0 plugins */
    if (authdata_plugins_ftables_v0 != NULL) {
	struct krb5plugin_authdata_ftable_v0 *ftable;

	for (i = 0; authdata_plugins_ftables_v0[i] != NULL; i++) {
	    krb5_error_code initerr;
	    void *pctx = NULL;

	    ftable = authdata_plugins_ftables_v0[i];
	    if ((ftable->authdata_proc == NULL)) {
		continue;
	    }
	    server_init_proc = ftable->init_proc;
	    if ((server_init_proc != NULL) &&
		((initerr = (*server_init_proc)(context, &pctx)) != 0)) {
		const char *emsg;
		emsg = krb5_get_error_message(context, initerr);
		if (emsg) {
		    krb5_klog_syslog(LOG_ERR,
				     "authdata %s failed to initialize: %s",
				     ftable->name, emsg);
		    krb5_free_error_message(context, emsg);
		}
		memset(&authdata_systems[k], 0, sizeof(authdata_systems[k]));
	
		continue;
	    }
    
	    authdata_systems[k].name = ftable->name;
	    authdata_systems[k].type = AUTHDATA_SYSTEM_V0;
	    authdata_systems[k].init = server_init_proc;
	    authdata_systems[k].fini = ftable->fini_proc;
	    authdata_systems[k].handle_authdata.v0 = ftable->authdata_proc;
	    authdata_systems[k].plugin_context = pctx;
	    k++;
	}
    }

    n_authdata_systems = k;
    /* Add the end-of-list marker. */
    authdata_systems[k].name = "[end]";
    authdata_systems[k].type = AUTHDATA_SYSTEM_UNKNOWN;
    code = 0;

cleanup:
    if (authdata_plugins_ftables_v1 != NULL)
	krb5int_free_plugin_dir_data(authdata_plugins_ftables_v1);
    if (authdata_plugins_ftables_v0 != NULL)
	krb5int_free_plugin_dir_data(authdata_plugins_ftables_v0);

    return code;
}

krb5_error_code
unload_authdata_plugins(krb5_context context)
{
    int i;
    if (authdata_systems != NULL) {
	for (i = 0; i < n_authdata_systems; i++) {
	    if (authdata_systems[i].fini != NULL) {
		(*authdata_systems[i].fini)(context,
					    authdata_systems[i].plugin_context);
	    }
	    memset(&authdata_systems[i], 0, sizeof(authdata_systems[i]));
	}
	free(authdata_systems);
	authdata_systems = NULL;
	n_authdata_systems = 0;
	krb5int_close_plugin_dirs(&authdata_plugins);
    }
    return 0;
}

/* Merge authdata. If copy == 0, in_authdata is invalid on return */
static krb5_error_code
merge_authdata (krb5_context context,
		krb5_authdata **in_authdata,
		krb5_authdata ***out_authdata,
		krb5_boolean copy)
{
    size_t i, nadata = 0;
    krb5_authdata **authdata = *out_authdata;

    if (in_authdata == NULL || in_authdata[0] == NULL)
	return 0;

    if (authdata != NULL) {
	for (nadata = 0; authdata[nadata] != NULL; nadata++)
	    ;
    }

    for (i = 0; in_authdata[i] != NULL; i++)
	;

    if (authdata == NULL) {
	authdata = (krb5_authdata **)calloc(i + 1, sizeof(krb5_authdata *));
    } else {
	authdata = (krb5_authdata **)realloc(authdata,
	    ((nadata + i + 1) * sizeof(krb5_authdata *)));
    }
    if (authdata == NULL)
	return ENOMEM;

    if (copy) {
	krb5_error_code code;
	krb5_authdata **tmp;

	code = krb5_copy_authdata(context, in_authdata, &tmp);
	if (code != 0)
	    return code;

	in_authdata = tmp;
    }

    for (i = 0; in_authdata[i] != NULL; i++)
	authdata[nadata + i] = in_authdata[i];

    authdata[nadata + i] = NULL;

    free(in_authdata);

    *out_authdata = authdata;

    return 0;
}

/* Handle copying TGS-REQ authorization data into reply */
static krb5_error_code
handle_request_authdata (krb5_context context,
			 unsigned int flags,
			 krb5_db_entry *client,
			 krb5_db_entry *server,
			 krb5_db_entry *krbtgt,
			 krb5_keyblock *client_key,
			 krb5_keyblock *server_key,
			 krb5_data *req_pkt,
			 krb5_kdc_req *request,
			 krb5_const_principal for_user_princ,
			 krb5_enc_tkt_part *enc_tkt_request,
			 krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code;
    krb5_data scratch;

    if (request->msg_type != KRB5_TGS_REQ ||
	request->authorization_data.ciphertext.data == NULL)
	return 0;

    assert(enc_tkt_request != NULL);

    scratch.length = request->authorization_data.ciphertext.length;
    scratch.data = malloc(scratch.length);
    if (scratch.data == NULL)
	return ENOMEM;

    code = krb5_c_decrypt(context,
			  enc_tkt_request->session,
			  KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY,
			  0, &request->authorization_data,
			  &scratch);
    if (code != 0)
	code = krb5_c_decrypt(context,
			      client_key,
			      KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY,
			      0, &request->authorization_data,
			      &scratch);

    if (code != 0) {
	free(scratch.data);
	return code;
    }

    /* scratch now has the authorization data, so we decode it, and make
     * it available to subsequent authdata plugins */
    code = decode_krb5_authdata(&scratch, &request->unenc_authdata);
    if (code != 0) {
	free(scratch.data);
	return code;
    }

    free(scratch.data);

    code = merge_authdata(context, request->unenc_authdata,
			  &enc_tkt_reply->authorization_data, TRUE /* copy */);

    return code;
}

/* Handle backend-managed authorization data */
static krb5_error_code
handle_tgt_authdata (krb5_context context,
		     unsigned int flags,
		     krb5_db_entry *client,
		     krb5_db_entry *server,
		     krb5_db_entry *krbtgt,
		     krb5_keyblock *client_key,
		     krb5_keyblock *server_key,
		     krb5_data *req_pkt,
		     krb5_kdc_req *request,
		     krb5_const_principal for_user_princ,
		     krb5_enc_tkt_part *enc_tkt_request,
		     krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code;
    krb5_authdata **db_authdata = NULL;
    krb5_db_entry ad_entry;
    int ad_nprincs = 0;
    krb5_boolean tgs_req = (request->msg_type == KRB5_TGS_REQ);
    krb5_const_principal actual_client;

    /*
     * Check whether KDC issued authorization data should be included.
     * A server can explicitly disable the inclusion of authorization
     * data by setting the KRB5_KDB_NO_AUTH_DATA_REQUIRED flag on its
     * principal entry. Otherwise authorization data will be included
     * if it was present in the TGT, the client is from another realm
     * or protocol transition/constrained delegation was used, or, in
     * the AS-REQ case, if the pre-auth data indicated the PAC should
     * be present.
     *
     * We permit sign_authorization_data() to return a krb5_db_entry
     * representing the principal associated with the authorization
     * data, in case that principal is not local to our realm and we
     * need to perform additional checks (such as disabling delegation
     * for cross-realm protocol transition below).
     */
    if (tgs_req) {
	assert(enc_tkt_request != NULL);

	if (isflagset(server->attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED))
	    return 0;

	if (enc_tkt_request->authorization_data == NULL &&
	    !isflagset(flags, KRB5_KDB_FLAG_CROSS_REALM | KRB5_KDB_FLAGS_S4U))
	    return 0;

	assert(enc_tkt_reply->times.authtime == enc_tkt_request->times.authtime);
    } else {
	if (!isflagset(flags, KRB5_KDB_FLAG_INCLUDE_PAC))
	    return 0;
    }

    /*
     * We have this special case for protocol transition, because for
     * cross-realm protocol transition the ticket reply client will
     * not be changed until the final hop.
     */
    if (isflagset(flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION))
	actual_client = for_user_princ;
    else
	actual_client = enc_tkt_reply->client;

    /*
     * If the backend does not implement the sign authdata method, then
     * just copy the TGT authorization data into the reply, except for
     * the constrained delegation case (which requires special handling
     * because it will promote untrusted auth data to KDC issued auth
     * data; this requires backend-specific code)
     *
     * Presently this interface does not support using request auth data
     * to influence (eg. possibly restrict) the reply auth data.
     */
    code = sign_db_authdata(context,
			    flags,
			    actual_client,
			    client,
			    server,
			    krbtgt,
			    client_key,
			    server_key, /* U2U or server key */
			    enc_tkt_reply->times.authtime,
			    tgs_req ? enc_tkt_request->authorization_data : NULL,
			    &db_authdata,
			    &ad_entry,
			    &ad_nprincs);
    if (code == KRB5_KDB_DBTYPE_NOSUP) {
	assert(ad_nprincs == 0);
	assert(db_authdata == NULL);

	if (isflagset(flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION))
	    return KRB5KDC_ERR_POLICY;

	if (tgs_req)
	    return merge_authdata(context, enc_tkt_request->authorization_data,
				  &enc_tkt_reply->authorization_data, TRUE);
	else
	    return 0;
    }

    if (ad_nprincs != 0) {
	if (isflagset(flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION) &&
	    isflagset(ad_entry.attributes, KRB5_KDB_DISALLOW_FORWARDABLE))
	    clear(enc_tkt_reply->flags, TKT_FLG_FORWARDABLE);

	krb5_db_free_principal(context, &ad_entry, ad_nprincs);

	if (ad_nprincs != 1) {
	    if (db_authdata != NULL)
		krb5_free_authdata(context, db_authdata);
	    return KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
	}
    }

    if (db_authdata != NULL) {
	code = merge_authdata(context, db_authdata,
			      &enc_tkt_reply->authorization_data,
			      FALSE);
	if (code != 0)
	    krb5_free_authdata(context, db_authdata);
    }

    return code;
}

krb5_error_code
handle_authdata (krb5_context context,
		 unsigned int flags,
		 krb5_db_entry *client,
		 krb5_db_entry *server,
		 krb5_db_entry *krbtgt,
		 krb5_keyblock *client_key,
		 krb5_keyblock *server_key,
		 krb5_data *req_pkt,
		 krb5_kdc_req *request,
		 krb5_const_principal for_user_princ,
		 krb5_enc_tkt_part *enc_tkt_request,
		 krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code = 0;
    int i;

    for (i = 0; i < n_authdata_systems; i++) {
	const krb5_authdata_systems *asys = &authdata_systems[i];

	switch (asys->type) {
	case AUTHDATA_SYSTEM_V0:
	    /* V0 was only in AS-REQ code path */
	    if (request->msg_type != KRB5_AS_REQ)
		continue;

	    code = (*asys->handle_authdata.v0)(context, client, req_pkt,
					       request, enc_tkt_reply);
	    break;
	case AUTHDATA_SYSTEM_V1:
	    code = (*asys->handle_authdata.v1)(context, flags,
					      client, server, krbtgt,
					      client_key, server_key,
					      req_pkt, request, for_user_princ,
					      enc_tkt_request,
					      enc_tkt_reply);
	    break;
	default:
	    code = 0;
	    break;
	}
	if (code != 0) {
	    const char *emsg;

	    emsg = krb5_get_error_message (context, code);
	    krb5_klog_syslog (LOG_INFO,
			      "authdata (%s) handling failure: %s",
			      asys->name, emsg);
	    krb5_free_error_message (context, emsg);

	    if (asys->flags & AUTHDATA_FLAG_CRITICAL)
		break;
	}
    }

    return code;
}

