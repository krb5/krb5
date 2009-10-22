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
#include <krb5/authdata_plugin.h>

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
/* MIT Kerberos 1.8 (V2) authdata plugin callback */
typedef krb5_error_code (*authdata_proc_2)
    (krb5_context, unsigned int flags,
     krb5_db_entry *client, krb5_db_entry *server,
     krb5_db_entry *krbtgt,
     krb5_keyblock *client_key,
     krb5_keyblock *server_key,
     krb5_keyblock *krbtgt_key,
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
     krb5_keyblock *krbtgt_key,
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
     krb5_keyblock *krbtgt_key,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_const_principal for_user_princ,
     krb5_enc_tkt_part *enc_tkt_request,
     krb5_enc_tkt_part *enc_tkt_reply);

/* Internal authdata system for handling delegation path */
static krb5_error_code handle_signedpath_authdata
    (krb5_context context,
     unsigned int flags,
     krb5_db_entry *client,
     krb5_db_entry *server,
     krb5_db_entry *krbtgt,
     krb5_keyblock *client_key,
     krb5_keyblock *server_key,
     krb5_keyblock *krbtgt_key,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_const_principal for_user_princ,
     krb5_enc_tkt_part *enc_tkt_request,
     krb5_enc_tkt_part *enc_tkt_reply);

typedef struct _krb5_authdata_systems {
    const char *name;
#define AUTHDATA_SYSTEM_UNKNOWN	-1
#define AUTHDATA_SYSTEM_V0	0
#define AUTHDATA_SYSTEM_V2	2
    int         type;
#define AUTHDATA_FLAG_CRITICAL	0x1
    int         flags;
    void       *plugin_context;
    init_proc   init;
    fini_proc   fini;
    union {
	authdata_proc_2 v2;
	authdata_proc_0 v0;
    } handle_authdata;
} krb5_authdata_systems;

static krb5_authdata_systems static_authdata_systems[] = {
    { "tgs_req", AUTHDATA_SYSTEM_V2, AUTHDATA_FLAG_CRITICAL, NULL, NULL, NULL, { handle_request_authdata } },
    { "tgt", AUTHDATA_SYSTEM_V2, AUTHDATA_FLAG_CRITICAL, NULL, NULL, NULL, { handle_tgt_authdata } },
    { "signedpath", AUTHDATA_SYSTEM_V2, AUTHDATA_FLAG_CRITICAL, NULL, NULL, NULL, { handle_signedpath_authdata } },
};

static krb5_authdata_systems *authdata_systems;
static int n_authdata_systems;
static struct plugin_dir_handle authdata_plugins;

/* Load both v0 and v2 authdata plugins */
krb5_error_code
load_authdata_plugins(krb5_context context)
{
    void **authdata_plugins_ftables_v0 = NULL;
    void **authdata_plugins_ftables_v2 = NULL;
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
    authdata_plugins_ftables_v2 = NULL;
    n_authdata_systems = 0;

    if (krb5int_get_plugin_dir_data(&authdata_plugins,
				    "authdata_server_2",
				    &authdata_plugins_ftables_v2, &context->err) != 0 ||
	krb5int_get_plugin_dir_data(&authdata_plugins,
				    "authdata_server_0",
				    &authdata_plugins_ftables_v0, &context->err) != 0) {
	code = KRB5_PLUGIN_NO_HANDLE;
	goto cleanup;
    }

    /* Count the valid modules. */ 
    module_count = 0;

    if (authdata_plugins_ftables_v2 != NULL) {
	struct krb5plugin_authdata_server_ftable_v2 *ftable;

	for (i = 0; authdata_plugins_ftables_v2[i] != NULL; i++) {
	    ftable = authdata_plugins_ftables_v2[i];
	    if (ftable->authdata_proc != NULL)
		module_count++;
	}
    }
 
    if (authdata_plugins_ftables_v0 != NULL) {
	struct krb5plugin_authdata_server_ftable_v0 *ftable;

	for (i = 0; authdata_plugins_ftables_v0[i] != NULL; i++) {
	    ftable = authdata_plugins_ftables_v0[i];
	    if (ftable->authdata_proc != NULL)
		module_count++;
	}
    }

    module_count += sizeof(static_authdata_systems)
	/ sizeof(static_authdata_systems[0]);

    /* Build the complete list of supported authdata options, and
     * leave room for a terminator entry. */
    authdata_systems = calloc(module_count + 1, sizeof(krb5_authdata_systems));
    if (authdata_systems == NULL) {
	code = ENOMEM;
	goto cleanup;
    }

    k = 0;

    /* Add dynamically loaded V2 plugins */
    if (authdata_plugins_ftables_v2 != NULL) {
	struct krb5plugin_authdata_server_ftable_v2 *ftable;

	for (i = 0; authdata_plugins_ftables_v2[i] != NULL; i++) {
	    krb5_error_code initerr;
	    void *pctx = NULL;

	    ftable = authdata_plugins_ftables_v2[i];
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
	    authdata_systems[k].type = AUTHDATA_SYSTEM_V2;
	    authdata_systems[k].init = server_init_proc;
	    authdata_systems[k].fini = ftable->fini_proc;
	    authdata_systems[k].handle_authdata.v2 = ftable->authdata_proc;
	    authdata_systems[k].plugin_context = pctx;
	    k++;
	}
    }

    /* Add dynamically loaded V0 plugins */
    if (authdata_plugins_ftables_v0 != NULL) {
	struct krb5plugin_authdata_server_ftable_v0 *ftable;

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

    /* Add the locally-supplied mechanisms to the dynamic list first. */
    for (i = 0;
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

    n_authdata_systems = k;
    /* Add the end-of-list marker. */
    authdata_systems[k].name = "[end]";
    authdata_systems[k].type = AUTHDATA_SYSTEM_UNKNOWN;
    code = 0;

cleanup:
    if (authdata_plugins_ftables_v2 != NULL)
	krb5int_free_plugin_dir_data(authdata_plugins_ftables_v2);
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

/* Returns TRUE if authdata should be filtered when copying. */
static krb5_boolean
is_kdc_issued_authdatum (krb5_context context,
			 krb5_authdata *authdata,
		         krb5_authdatatype desired_type)
{
    krb5_boolean ret;
    krb5_authdatatype ad_type;

    if (authdata->ad_type == KRB5_AUTHDATA_IF_RELEVANT) {
	krb5_authdata **tmp;

	/* This should avoid decoding the entire container */
	if (krb5_decode_authdata_container(context,
					   authdata->ad_type,
					   authdata,
					   &tmp) != 0)
	    return FALSE;

	if (tmp == NULL || tmp[1] != NULL) {
	    krb5_free_authdata(context, tmp);
	    return FALSE;
	}
	ad_type = tmp[0]->ad_type;
	krb5_free_authdata(context, tmp);
    } else
	ad_type = authdata->ad_type;

    if (desired_type)
	ret = (desired_type == ad_type);
    else
	switch (ad_type) {
	case KRB5_AUTHDATA_SIGNTICKET:
	case KRB5_AUTHDATA_KDC_ISSUED:
	case KRB5_AUTHDATA_WIN2K_PAC:
	    ret = TRUE;
	    break;
	default:
	    ret = FALSE;
	    break;
	}

    return ret;
}

static krb5_boolean
has_kdc_issued_authdata (krb5_context context,
			 krb5_authdata **authdata,
			 krb5_authdatatype desired_type)
{
    int i;
    krb5_boolean ret = FALSE;

    if (authdata != NULL) {
	for (i = 0; authdata[i] != NULL; i++) {
	    if (is_kdc_issued_authdatum(context, authdata[i], desired_type)) {
		ret = TRUE;
		break;
	    }
	}
    }

    return ret;
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

    for (i = 0; in_authdata[i] != NULL; i++) {
	if (is_kdc_issued_authdatum(context, in_authdata[i], 0)) {
	    free(in_authdata[i]->contents);
	    free(in_authdata[i]);
	} else
	    authdata[nadata + i] = in_authdata[i];
    }

    authdata[nadata + i] = NULL;

    free(in_authdata);

    if (authdata[0] == NULL) {
	free(authdata);
	authdata = NULL;
    }

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
                         krb5_keyblock *krbtgt_key,
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

    /*
     * RFC 4120 requires authdata in the TGS body to be encrypted in
     * the subkey with usage 5 if a subkey is present, and in the TGS
     * session key with key usage 4 if it is not.  Prior to krb5 1.7,
     * we got this wrong, always decrypting the authorization data
     * with the TGS session key and usage 4.  For the sake of
     * conservatism, try the decryption the old way (wrong if
     * client_key is a subkey) first, and then try again the right way
     * (in the case where client_key is a subkey) if the first way
     * fails.
     */
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
		     krb5_keyblock *krbtgt_key,
		     krb5_data *req_pkt,
		     krb5_kdc_req *request,
		     krb5_const_principal for_user_princ,
		     krb5_enc_tkt_part *enc_tkt_request,
		     krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code;
    krb5_authdata **db_authdata = NULL;
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
			    krbtgt_key,
			    enc_tkt_reply->times.authtime,
			    tgs_req ? enc_tkt_request->authorization_data : NULL,
			    enc_tkt_reply->session,
			    &db_authdata);
    if (code == KRB5_KDB_DBTYPE_NOSUP) {
	assert(db_authdata == NULL);

	if (tgs_req)
	    return merge_authdata(context, enc_tkt_request->authorization_data,
				  &enc_tkt_reply->authorization_data, TRUE);
	else
	    return 0;
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
		 krb5_keyblock *krbtgt_key,
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
	case AUTHDATA_SYSTEM_V2:
	    code = (*asys->handle_authdata.v2)(context, flags,
					      client, server, krbtgt,
					      client_key, server_key, krbtgt_key,
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

static krb5_error_code
verify_ad_signedpath(krb5_context context,
		     krb5_db_entry *krbtgt,
		     krb5_keyblock *krbtgt_key,
		     krb5_enc_tkt_part *enc_tkt_part,
		     krb5_delegatee ***pdelegated,
		     krb5_boolean *path_is_signed)
{
    krb5_error_code		code;
    krb5_ad_signedpath		*sp = NULL;
    krb5_ad_signedpath_data	sp_data;
    krb5_authdata		**container = NULL;
    krb5_authdata		**sp_authdata = NULL;
    krb5_data			enc_sp, *enc_spdata = NULL;
    int				i;

    *pdelegated = NULL;
    *path_is_signed = FALSE;

    if (enc_tkt_part->authorization_data == NULL)
	return 0;

    for (i = 0; enc_tkt_part->authorization_data[i] != NULL; i++)
	;
    container = &enc_tkt_part->authorization_data[i - 1];
    if (*container == NULL)
	return 0;

    code = krb5_decode_authdata_container(context,
					  KRB5_AUTHDATA_IF_RELEVANT,
					  *container,
					  &sp_authdata);
    if (code != 0)
	goto cleanup;

    if (sp_authdata == NULL ||
	sp_authdata[0]->ad_type != KRB5_AUTHDATA_SIGNTICKET ||
	sp_authdata[1] != NULL)
	goto cleanup;

    enc_sp.data = (char *)sp_authdata[0]->contents;
    enc_sp.length = sp_authdata[0]->length;

    code = decode_krb5_ad_signedpath(&enc_sp, &sp);
    if (code != 0)
	goto cleanup;

    container = enc_tkt_part->authorization_data;
    enc_tkt_part->authorization_data = NULL;

    sp_data.enc_tkt_part = *enc_tkt_part;

    /* XXX workaround for workaround in do_tgs_req.c */
    if (sp_data.enc_tkt_part.times.starttime ==
	sp_data.enc_tkt_part.times.authtime)
	sp_data.enc_tkt_part.times.starttime = 0;
    sp_data.delegated = sp->delegated;

    code = encode_krb5_ad_signedpath_data(&sp_data, &enc_spdata);
    if (code != 0) {
	enc_tkt_part->authorization_data = container;
	goto cleanup;
    }

    enc_tkt_part->authorization_data = container;

    code = krb5_c_verify_checksum(context,
				  krbtgt_key,
				  KRB5_KEYUSAGE_AD_SIGNEDPATH,
				  enc_spdata,
				  &sp->checksum,
				  path_is_signed);
    if (code != 0)
	goto cleanup;

    if (*path_is_signed == FALSE) {
	code = KRB5KRB_AP_ERR_MODIFIED;
	goto cleanup;
    }

    *pdelegated = sp->delegated;
    sp->delegated = NULL;

cleanup:
    krb5_free_data(context, enc_spdata);
    krb5_free_ad_signedpath(context, sp);
    krb5_free_authdata(context, sp_authdata);

    return code;
}

static krb5_error_code
make_ad_signedpath(krb5_context context,
		   krb5_const_principal server,
		   krb5_delegatee **deleg_path,
		   const krb5_db_entry *krbtgt,
		   krb5_keyblock *krbtgt_key,
		   krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code		code;
    krb5_ad_signedpath_data	sp_data;
    krb5_ad_signedpath		sp;
    krb5_delegatee		delegatee;
    krb5_delegatee		**new_deleg_path = NULL;
    int				i;
    krb5_data			*data = NULL;
    krb5_cksumtype		cksumtype;
    krb5_authdata		ad_datum, *ad_data[2];
    krb5_authdata		**if_relevant = NULL;
    krb5_authdata		**authdata;

    memset(&sp_data, 0, sizeof(sp_data));
    memset(&sp,	     0, sizeof(sp));

    if (deleg_path != NULL) {
	for (i = 0; deleg_path[i] != NULL; i++)
	    ;
    } else
	i = 0;

    new_deleg_path = k5alloc((i + 2) * sizeof(krb5_delegatee *), &code);
    if (code != 0)
	goto cleanup;

    if (deleg_path != NULL)
	memcpy(new_deleg_path, deleg_path, i * sizeof(krb5_delegatee *));
    if (server != NULL) {
	delegatee.principal = (krb5_principal)server;
	new_deleg_path[i] = &delegatee;
    }
    new_deleg_path[i + 1] = NULL;

    sp_data.enc_tkt_part = *enc_tkt_reply;
    sp_data.enc_tkt_part.authorization_data = NULL;
    sp_data.delegated = new_deleg_path;

    code = encode_krb5_ad_signedpath_data(&sp_data, &data);
    if (code != 0)
	goto cleanup;

    sp.enctype = krbtgt_key->enctype;

    code = krb5int_c_mandatory_cksumtype(context,
					 krbtgt_key->enctype,
					 &cksumtype);
    if (code != 0)
	goto cleanup;

    code = krb5_c_make_checksum(context, cksumtype, krbtgt_key,
				KRB5_KEYUSAGE_AD_SIGNEDPATH, data,
				&sp.checksum);
    if (code != 0)
	goto cleanup;

    sp.delegated = new_deleg_path;

    code = encode_krb5_ad_signedpath(&sp, &data);
    if (code != 0)
	goto cleanup;

    ad_datum.ad_type = KRB5_AUTHDATA_SIGNTICKET;
    ad_datum.contents = (krb5_octet *)data->data;
    ad_datum.length = data->length;

    ad_data[0] = &ad_datum;
    ad_data[1] = NULL;

    code = krb5_encode_authdata_container(context,
					  KRB5_AUTHDATA_IF_RELEVANT,
					  ad_data,
					  &if_relevant);
    if (code != 0)
	goto cleanup;

    if (enc_tkt_reply->authorization_data != NULL) {
	for (i = 0; enc_tkt_reply->authorization_data[i] != NULL; i++)
	    ;
    } else
	i = 0;

    authdata = realloc(enc_tkt_reply->authorization_data,
		       (i + 2) * sizeof(krb5_authdata *));
    if (authdata == NULL) {
	code = ENOMEM;
	goto cleanup;
    }

    enc_tkt_reply->authorization_data = authdata;
    enc_tkt_reply->authorization_data[i] = if_relevant[0];
    enc_tkt_reply->authorization_data[i + 1] = NULL;

    free(if_relevant);
    if_relevant = NULL;

cleanup:
    if (new_deleg_path != NULL)
	free(new_deleg_path);
    krb5_free_authdata(context, if_relevant);
    krb5_free_data(context, data);
    krb5_free_checksum_contents(context, &sp.checksum);

    return code;
}

static krb5_error_code
handle_signedpath_authdata (krb5_context context,
			    unsigned int flags,
			    krb5_db_entry *client,
			    krb5_db_entry *server,
			    krb5_db_entry *krbtgt,
			    krb5_keyblock *client_key,
			    krb5_keyblock *server_key,
			    krb5_keyblock *krbtgt_key,
			    krb5_data *req_pkt,
			    krb5_kdc_req *request,
			    krb5_const_principal for_user_princ,
			    krb5_enc_tkt_part *enc_tkt_request,
			    krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code = 0;
    krb5_delegatee **deleg_path = NULL;
    krb5_boolean signed_path;
    krb5_boolean s4u2proxy;

    /*
     * If backend/another plugin returned the PAC, then it presumably
     * verified the path for constrained delegation, and we can NOOP.
     */
    if (has_kdc_issued_authdata(context,
				enc_tkt_reply->authorization_data,
				KRB5_AUTHDATA_WIN2K_PAC))
	return 0;

    /* Verification presently depends on us being last. */
    assert(authdata_systems[n_authdata_systems - 1].handle_authdata.v2
	== handle_signedpath_authdata);

    signed_path = FALSE;
    s4u2proxy = ((flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) != 0);

    /* Verification is only necessary for the TGS-REQ case. */
    if ((flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) == 0) {
	code = verify_ad_signedpath(context,
				    krbtgt,
				    krbtgt_key,
				    enc_tkt_request,
				    &deleg_path,
				    &signed_path);
	if (code != 0)
	    goto cleanup;

	if (s4u2proxy == TRUE && signed_path == FALSE) {
	    code = KRB5KDC_ERR_BADOPTION;
	    goto cleanup;
	}
    }

    if ((flags & KRB5_KDB_FLAG_CROSS_REALM) == 0) {
	code = make_ad_signedpath(context,
				  s4u2proxy ? client->princ : NULL,
				  deleg_path,
				  krbtgt,
				  krbtgt_key,
				  enc_tkt_reply);
	if (code != 0)
	    goto cleanup;
    }

cleanup:
    krb5_free_delegatees(context, deleg_path);

    return code;
}

