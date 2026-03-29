/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2009  by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 */
#include "k5-int.h"
#include "gssapiP_krb5.h"
#include "mglueP.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <assert.h>

void
kg_release_imp_step_ctx(kg_imp_step_ctx_t sctx)
{
    if (sctx == NULL)
        return;
    krb5_tkt_creds_free(sctx->context, sctx->tcc);
    krb5_free_context(sctx->context);
    free(sctx);
}

void
kg_release_s4u2proxy_step_ctx(krb5_context context, kg_s4u2proxy_step_ctx_t sctx)
{
    if (sctx == NULL)
        return;
    krb5_tkt_creds_free(context, sctx->proxy_tcc);
    krb5_free_data_contents(context, &sctx->realm);
    free(sctx);
}

/*
 * Initialise a step-based S4U2Proxy TGS exchange.  tgt_ccache is the ccache
 * that holds the service TGT (used as the authenticator for the TGS-REQ).
 * client_princ is the impersonated user, server_princ is the target service,
 * and evidence is the DER-encoded S4U2Self ticket.  On success *out_sctx owns
 * the new context; the caller must free it with kg_release_s4u2proxy_step_ctx.
 */
krb5_error_code
kg_s4u2proxy_step_init(krb5_context context,
                       krb5_ccache tgt_ccache,
                       krb5_principal client_princ,
                       krb5_principal server_princ,
                       const krb5_data *evidence,
                       OM_uint32 time_req,
                       kg_s4u2proxy_step_ctx_t *out_sctx)
{
    krb5_error_code code;
    kg_s4u2proxy_step_ctx_t sctx = NULL;
    krb5_creds in_creds;
    krb5_timestamp now;

    *out_sctx = NULL;

    sctx = k5alloc(sizeof(*sctx), &code);
    if (sctx == NULL)
        return code;

    memset(&in_creds, 0, sizeof(in_creds));
    in_creds.client = client_princ;
    in_creds.server = server_princ;

    if (time_req != 0 && time_req != GSS_C_INDEFINITE) {
        code = krb5_timeofday(context, &now);
        if (code != 0)
            goto cleanup;
        in_creds.times.endtime = ts_incr(now, time_req);
    }

    code = krb5_tkt_creds_init(context, tgt_ccache, &in_creds, 0,
                               &sctx->proxy_tcc);
    if (code != 0)
        goto cleanup;

    code = k5_tkt_creds_set_s4u2proxy(context, sctx->proxy_tcc, evidence);
    if (code != 0)
        goto cleanup;

    *out_sctx = sctx;
    sctx = NULL;

cleanup:
    kg_release_s4u2proxy_step_ctx(context, sctx);
    return code;
}

/*
 * Drive one step of a step-based S4U2Proxy exchange.  in is the KDC reply
 * from the previous step (empty_data() on the first call).  On return, if
 * KRB5_TKT_CREDS_STEP_FLAG_CONTINUE is set in *flags, out contains the next
 * TGS-REQ to send and sctx->realm names the target KDC realm.
 */
krb5_error_code
kg_s4u2proxy_step(krb5_context context, kg_s4u2proxy_step_ctx_t sctx,
                  krb5_data *in, krb5_data *out, unsigned int *flags)
{
    krb5_error_code code;
    krb5_data realm = empty_data();

    *out = empty_data();
    *flags = 0;

    code = krb5_tkt_creds_step(context, sctx->proxy_tcc, in, out, &realm,
                               flags);
    if (code != 0)
        return code;

    krb5_free_data_contents(context, &sctx->realm);
    sctx->realm = realm;
    return 0;
}

/*
 * Create a MEMORY ccache initialised with princ as the default principal and
 * containing a copy of every credential in src.  Used to preserve the service
 * TGT before kg_finalize_impersonation() destroys the pre-finalization ccache.
 */
static krb5_error_code
copy_ccache(krb5_context context, krb5_ccache src, krb5_principal princ,
            krb5_ccache *out)
{
    krb5_error_code code;
    krb5_ccache dst = NULL;
    krb5_cc_cursor cur = 0;
    krb5_creds creds;

    *out = NULL;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &dst);
    if (code != 0)
        return code;

    code = krb5_cc_initialize(context, dst, princ);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_start_seq_get(context, src, &cur);
    if (code != 0)
        goto cleanup;

    while (!(code = krb5_cc_next_cred(context, src, &cur, &creds))) {
        krb5_error_code store_code;
        store_code = krb5_cc_store_cred(context, dst, &creds);
        krb5_free_cred_contents(context, &creds);
        if (store_code != 0) {
            code = store_code;
            break;
        }
    }
    krb5_cc_end_seq_get(context, src, &cur);
    if (code == KRB5_CC_END)
        code = 0;
    if (code != 0)
        goto cleanup;

    *out = dst;
    dst = NULL;

cleanup:
    if (dst != NULL)
        krb5_cc_destroy(context, dst);
    return code;
}

/*
 * Finalize an impersonation credential in-place.  ticket_creds is the S4U2Self
 * (or S4U2Proxy) ticket to store; the caller retains ownership.  cred->name is
 * updated to the impersonated user, cred->ccache is replaced with a new MEMORY
 * ccache containing ticket_creds, and cred->impersonator is set to the service.
 */
krb5_error_code
kg_finalize_impersonation(krb5_context context, krb5_gss_cred_id_t cred,
                          krb5_creds *ticket_creds)
{
    krb5_error_code code;
    krb5_ccache new_ccache = NULL;
    krb5_gss_name_t user_name = NULL;
    krb5_principal service_princ = NULL;
    char *service_str = NULL;
    krb5_data data;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &new_ccache);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_initialize(context, new_ccache, ticket_creds->client);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_store_cred(context, new_ccache, ticket_creds);
    if (code != 0)
        goto cleanup;

    code = krb5_unparse_name(context, cred->name->princ, &service_str);
    if (code != 0)
        goto cleanup;
    data = string2data(service_str);
    code = krb5_cc_set_config(context, new_ccache, NULL,
                              KRB5_CC_CONF_PROXY_IMPERSONATOR, &data);
    krb5_free_unparsed_name(context, service_str);
    service_str = NULL;
    if (code != 0)
        goto cleanup;

    code = krb5_copy_principal(context, cred->name->princ, &service_princ);
    if (code != 0)
        goto cleanup;

    code = kg_init_name(context, ticket_creds->client, NULL, NULL, NULL, 0,
                        &user_name);
    if (code != 0)
        goto cleanup;

    kg_release_name(context, &cred->name);
    krb5_cc_destroy(context, cred->ccache);
    krb5_free_principal(context, cred->s4u_user);
    krb5_free_data_contents(context, &cred->s4u_cert);

    cred->name = user_name;
    user_name = NULL;
    cred->ccache = new_ccache;
    new_ccache = NULL;
    cred->impersonator = service_princ;
    service_princ = NULL;
    cred->s4u_user = NULL;
    cred->have_tgt = FALSE;
    cred->expire = ticket_creds->times.endtime;

cleanup:
    kg_release_name(context, &user_name);
    krb5_free_principal(context, service_princ);
    if (new_ccache != NULL)
        krb5_cc_destroy(context, new_ccache);
    return code;
}

static int
kg_is_initiator_cred(krb5_gss_cred_id_t cred)
{
    return (cred->usage == GSS_C_INITIATE || cred->usage == GSS_C_BOTH) &&
        (cred->ccache != NULL);
}

static OM_uint32
kg_impersonate_name(OM_uint32 *minor_status,
                    const krb5_gss_cred_id_t impersonator_cred,
                    const krb5_gss_name_t user,
                    OM_uint32 time_req,
                    krb5_gss_cred_id_t *output_cred,
                    OM_uint32 *time_rec,
                    krb5_context context)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_creds in_creds, *out_creds = NULL;
    krb5_data *subject_cert = NULL;

    *output_cred = NULL;
    memset(&in_creds, 0, sizeof(in_creds));

    if (time_req != 0 && time_req != GSS_C_INDEFINITE) {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }
        in_creds.times.endtime = ts_incr(now, time_req);
    }

    if (user->is_cert)
        subject_cert = user->princ->data;
    else
        in_creds.client = user->princ;
    in_creds.server = impersonator_cred->name->princ;

    if (impersonator_cred->req_enctypes != NULL)
        in_creds.keyblock.enctype = impersonator_cred->req_enctypes[0];

    k5_mutex_lock(&user->lock);

    if (user->ad_context != NULL) {
        code = krb5_authdata_export_authdata(context,
                                             user->ad_context,
                                             AD_USAGE_TGS_REQ,
                                             &in_creds.authdata);
        if (code != 0) {
            k5_mutex_unlock(&user->lock);
            *minor_status = code;
            return GSS_S_FAILURE;
        }
    }

    k5_mutex_unlock(&user->lock);

    code = krb5_get_credentials_for_user(context,
                                         KRB5_GC_CANONICALIZE | KRB5_GC_NO_STORE,
                                         impersonator_cred->ccache,
                                         &in_creds, subject_cert, &out_creds);
    if (code != 0) {
        krb5_free_authdata(context, in_creds.authdata);
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = kg_compose_deleg_cred(minor_status,
                                         impersonator_cred,
                                         out_creds,
                                         time_req,
                                         output_cred,
                                         time_rec,
                                         context);

    krb5_free_authdata(context, in_creds.authdata);
    krb5_free_creds(context, out_creds);

    return major_status;
}

/* The mechglue always passes null desired_mechs and actual_mechs. */
OM_uint32 KRB5_CALLCONV
krb5_gss_acquire_cred_impersonate_name(OM_uint32 *minor_status,
                                       const gss_cred_id_t impersonator_cred_handle,
                                       const gss_name_t desired_name,
                                       OM_uint32 time_req,
                                       const gss_OID_set desired_mechs,
                                       gss_cred_usage_t cred_usage,
                                       gss_cred_id_t *output_cred_handle,
                                       gss_OID_set *actual_mechs,
                                       OM_uint32 *time_rec)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_cred_id_t imp_cred = (krb5_gss_cred_id_t)impersonator_cred_handle;
    krb5_gss_cred_id_t cred;
    krb5_context context;

    if (impersonator_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (desired_name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (output_cred_handle == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (cred_usage != GSS_C_INITIATE) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        return GSS_S_FAILURE;
    }

    if (imp_cred->usage != GSS_C_INITIATE && imp_cred->usage != GSS_C_BOTH) {
        *minor_status = 0;
        return GSS_S_NO_CRED;
    }

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (time_rec != NULL)
        *time_rec = 0;

    code = krb5_gss_init_context(&context);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = kg_cred_resolve(minor_status, context,
                                   impersonator_cred_handle, NULL);
    if (GSS_ERROR(major_status)) {
        krb5_free_context(context);
        return major_status;
    }

    major_status = kg_impersonate_name(minor_status,
                                       imp_cred,
                                       (krb5_gss_name_t)desired_name,
                                       time_req,
                                       &cred,
                                       time_rec,
                                       context);

    if (!GSS_ERROR(major_status))
        *output_cred_handle = (gss_cred_id_t)cred;

    k5_mutex_unlock(&imp_cred->lock);
    krb5_free_context(context);

    return major_status;

}

/*
 * Set up cred to be an S4U2Proxy credential by copying in the impersonator's
 * creds, setting a cache config variable with the impersonator principal name,
 * and saving the impersonator principal name in the cred structure.
 */
static krb5_error_code
make_proxy_cred(krb5_context context, krb5_gss_cred_id_t cred,
                krb5_gss_cred_id_t impersonator_cred,
                krb5_timestamp max_endtime)
{
    krb5_error_code code;
    krb5_data data;
    krb5_cc_cursor cur = 0;
    krb5_creds cur_creds;
    char *str;

    /* Copy credentials from the impersonator ccache, bounding endtime when
     * requested so copied TGTs don't outlive the S4U2Self evidence ticket. */
    code = krb5_cc_start_seq_get(context, impersonator_cred->ccache, &cur);
    if (code)
        return code;

    while (!(code = krb5_cc_next_cred(context, impersonator_cred->ccache,
                                      &cur, &cur_creds))) {
        if (max_endtime != 0 && cur_creds.times.endtime > max_endtime)
            cur_creds.times.endtime = max_endtime;
        code = krb5_cc_store_cred(context, cred->ccache, &cur_creds);
        krb5_free_cred_contents(context, &cur_creds);
        if (code)
            break;
    }

    if (cur)
        krb5_cc_end_seq_get(context, impersonator_cred->ccache, &cur);
    if (code == KRB5_CC_END)
        code = 0;
    if (code)
        return code;

    code = krb5_unparse_name(context, impersonator_cred->name->princ, &str);
    if (code)
        return code;

    data = string2data(str);
    code = krb5_cc_set_config(context, cred->ccache, NULL,
                              KRB5_CC_CONF_PROXY_IMPERSONATOR, &data);
    krb5_free_unparsed_name(context, str);
    if (code)
        return code;

    return krb5_copy_principal(context, impersonator_cred->name->princ,
                               &cred->impersonator);
}

OM_uint32
kg_compose_deleg_cred(OM_uint32 *minor_status,
                      krb5_gss_cred_id_t impersonator_cred,
                      krb5_creds *subject_creds,
                      OM_uint32 time_req,
                      krb5_gss_cred_id_t *output_cred,
                      OM_uint32 *time_rec,
                      krb5_context context)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_cred_id_t cred = NULL;

    *output_cred = NULL;
    k5_mutex_assert_locked(&impersonator_cred->lock);

    if (!kg_is_initiator_cred(impersonator_cred) ||
        impersonator_cred->name == NULL ||
        impersonator_cred->impersonator != NULL) {
        code = G_BAD_USAGE;
        goto cleanup;
    }

    assert(impersonator_cred->name->princ != NULL);

    assert(subject_creds != NULL);
    assert(subject_creds->client != NULL);

    cred = xmalloc(sizeof(*cred));
    if (cred == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    memset(cred, 0, sizeof(*cred));

    code = k5_mutex_init(&cred->lock);
    if (code != 0)
        goto cleanup;

    cred->usage = GSS_C_INITIATE;

    cred->expire = subject_creds->times.endtime;

    code = kg_init_name(context, subject_creds->client, NULL, NULL, NULL, 0,
                        &cred->name);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &cred->ccache);
    if (code != 0)
        goto cleanup;
    cred->destroy_ccache = 1;

    code = krb5_cc_initialize(context, cred->ccache, subject_creds->client);
    if (code != 0)
        goto cleanup;

    /* Bound copied credentials to the evidence ticket's endtime when the
     * caller specified a time_req, so TGTs don't outlive the impersonation. */
    code = make_proxy_cred(context, cred, impersonator_cred,
                           (time_req != 0 && time_req != GSS_C_INDEFINITE) ?
                           subject_creds->times.endtime : 0);
    if (code != 0)
        goto cleanup;

    /* Propagate the IAKERB mech flag so that gss_init_sec_context dispatches
     * to the IAKERB mechanism rather than the plain krb5 mechanism. */
    cred->iakerb_mech = impersonator_cred->iakerb_mech;

    code = krb5_cc_store_cred(context, cred->ccache, subject_creds);
    if (code != 0)
        goto cleanup;

    if (time_rec != NULL) {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0)
            goto cleanup;

        *time_rec = ts_interval(now, cred->expire);
    }

    major_status = GSS_S_COMPLETE;
    *minor_status = 0;
    *output_cred = cred;

cleanup:
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
    }

    if (GSS_ERROR(major_status) && cred != NULL) {
        k5_mutex_destroy(&cred->lock);
        krb5_cc_destroy(context, cred->ccache);
        kg_release_name(context, &cred->name);
        xfree(cred);
    }

    return major_status;
}

/*
 * IAKERB wrapper for gss_acquire_cred_impersonate_name.  Builds a deferred
 * S4U2Self credential: the actual TGS-REQ is proxied through the IAKERB
 * channel during gss_init_sec_context (IAKERB_S4U2SELF_TGS_REQ state) rather
 * than contacting the KDC directly.
 *
 * kg_impersonate_name() is static, so this function lives here alongside it.
 * The mechglue always passes null desired_mechs and actual_mechs.
 */
OM_uint32 KRB5_CALLCONV
iakerb_gss_acquire_cred_impersonate_name(OM_uint32 *minor_status,
                                          const gss_cred_id_t impersonator_cred_handle,
                                          const gss_name_t desired_name,
                                          OM_uint32 time_req,
                                          const gss_OID_set desired_mechs,
                                          gss_cred_usage_t cred_usage,
                                          gss_cred_id_t *output_cred_handle,
                                          gss_OID_set *actual_mechs,
                                          OM_uint32 *time_rec)
{
    OM_uint32 major_status = GSS_S_FAILURE;
    krb5_error_code code;
    krb5_gss_cred_id_t imp_cred = (krb5_gss_cred_id_t)impersonator_cred_handle;
    krb5_gss_cred_id_t cred = NULL;
    krb5_gss_name_t user = (krb5_gss_name_t)desired_name;
    krb5_context context = NULL;
    krb5_cc_cursor cur = 0;
    krb5_creds cur_creds;

    if (impersonator_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (desired_name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (output_cred_handle == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (cred_usage != GSS_C_INITIATE) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        return GSS_S_FAILURE;
    }

    if (imp_cred->usage != GSS_C_INITIATE && imp_cred->usage != GSS_C_BOTH) {
        *minor_status = 0;
        return GSS_S_NO_CRED;
    }

    /* Cert-only S4U2Self is not supported through the IAKERB proxy channel. */
    if (user->is_cert) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        return GSS_S_UNAVAILABLE;
    }

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (time_rec != NULL)
        *time_rec = 0;

    code = krb5_gss_init_context(&context);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = kg_cred_resolve(minor_status, context,
                                   impersonator_cred_handle, NULL);
    if (GSS_ERROR(major_status))
        goto cleanup;

    /* Build a deferred S4U2Self credential.  The S4U2Self TGS-REQ will be
     * proxied through the IAKERB channel in gss_init_sec_context. */
    cred = k5alloc(sizeof(*cred), &code);
    if (cred == NULL)
        goto k5err;

    code = k5_mutex_init(&cred->lock);
    if (code != 0)
        goto k5err;

    cred->usage = GSS_C_INITIATE;
    cred->iakerb_mech = 1;
    cred->have_tgt = imp_cred->have_tgt;
    cred->expire = imp_cred->expire;
    cred->refresh_time = imp_cred->refresh_time;

    /* Copy the service name (credential acts as the service until S4U2Self). */
    code = kg_duplicate_name(context, imp_cred->name, &cred->name);
    if (code != 0)
        goto k5err;

    /* Create a private MEMORY ccache and copy all creds from imp_cred. */
    code = krb5_cc_new_unique(context, "MEMORY", NULL, &cred->ccache);
    if (code != 0)
        goto k5err;
    cred->destroy_ccache = 1;

    code = krb5_cc_initialize(context, cred->ccache, imp_cred->name->princ);
    if (code != 0)
        goto k5err;

    code = krb5_cc_start_seq_get(context, imp_cred->ccache, &cur);
    if (code != 0)
        goto k5err;
    while (!(code = krb5_cc_next_cred(context, imp_cred->ccache,
                                      &cur, &cur_creds))) {
        code = krb5_cc_store_cred(context, cred->ccache, &cur_creds);
        krb5_free_cred_contents(context, &cur_creds);
        if (code != 0)
            break;
    }
    krb5_cc_end_seq_get(context, imp_cred->ccache, &cur);
    cur = 0;
    if (code != KRB5_CC_END)
        goto k5err;
    code = 0;

    /* Store the user principal for the deferred S4U2Self TGS-REQ. */
    code = krb5_copy_principal(context, user->princ, &cred->s4u_user);
    if (code != 0)
        goto k5err;

    major_status = GSS_S_COMPLETE;
    *minor_status = 0;
    *output_cred_handle = (gss_cred_id_t)cred;
    cred = NULL;
    goto cleanup;

k5err:
    major_status = GSS_S_FAILURE;
    *minor_status = code;

cleanup:
    if (cred != NULL) {
        k5_mutex_destroy(&cred->lock);
        if (cred->ccache != NULL)
            krb5_cc_destroy(context, cred->ccache);
        kg_release_name(context, &cred->name);
        free(cred);
    }
    k5_mutex_unlock(&imp_cred->lock);
    krb5_free_context(context);
    return major_status;
}

/*
 * Wrap a raw krb5 mech credential in a mechglue union credential so that
 * callers using the mechglue API (gss_inquire_cred, gss_release_cred, etc.)
 * can work with the returned handle.  On success, *out owns mech_cred.
 */
static OM_uint32
wrap_imp_step_cred(OM_uint32 *minor_status, krb5_gss_cred_id_t mech_cred,
                   gss_cred_id_t *out)
{
    const gss_OID mech_oid = (gss_OID)gss_mech_krb5;
    gss_union_cred_t uc;

    *out = GSS_C_NO_CREDENTIAL;
    uc = calloc(1, sizeof(*uc));
    if (uc == NULL)
        goto enomem;
    uc->loopback = uc;

    uc->mechs_array = malloc(sizeof(gss_OID_desc));
    if (uc->mechs_array == NULL)
        goto enomem;
    uc->mechs_array[0].elements = malloc(mech_oid->length);
    if (uc->mechs_array[0].elements == NULL)
        goto enomem;
    memcpy(uc->mechs_array[0].elements, mech_oid->elements, mech_oid->length);
    uc->mechs_array[0].length = mech_oid->length;

    uc->cred_array = malloc(sizeof(gss_cred_id_t));
    if (uc->cred_array == NULL)
        goto enomem;
    uc->cred_array[0] = (gss_cred_id_t)mech_cred;
    uc->count = 1;

    *out = (gss_cred_id_t)uc;
    return GSS_S_COMPLETE;

enomem:
    if (uc != NULL) {
        if (uc->mechs_array != NULL)
            free(uc->mechs_array[0].elements);
        free(uc->mechs_array);
        free(uc->cred_array);
        free(uc);
    }
    *minor_status = ENOMEM;
    return GSS_S_FAILURE;
}

/*
 * Step-based S4U2Self credential acquisition.
 *
 * On the first call, set input_token to GSS_C_NO_BUFFER and *cred_handle to
 * GSS_C_NO_CREDENTIAL.  The function returns GSS_S_CONTINUE_NEEDED with an
 * in-progress handle in *cred_handle, a raw Kerberos TGS-REQ in output_token,
 * and the target realm in target_realm.
 *
 * On each subsequent call, pass the KDC reply in input_token and the
 * in-progress handle in *cred_handle.  When the exchange completes,
 * GSS_S_COMPLETE is returned, *cred_handle is a fully finalized impersonation
 * credential, and output_token/target_realm are empty.
 *
 * On any error, *cred_handle is released and set to GSS_C_NO_CREDENTIAL.
 */
OM_uint32 KRB5_CALLCONV
krb5_gss_acquire_cred_impersonate_name_step(
    OM_uint32 *minor_status,
    gss_cred_id_t impersonator_cred_handle,
    gss_name_t desired_name,
    OM_uint32 time_req,
    gss_OID_set desired_mechs,
    gss_cred_usage_t cred_usage,
    gss_buffer_t input_token,
    gss_cred_id_t *cred_handle,
    gss_buffer_t output_token,
    gss_buffer_t target_realm,
    gss_OID_set *actual_mechs,
    OM_uint32 *time_rec)
{
    OM_uint32 major;
    krb5_error_code code = 0;
    krb5_gss_cred_id_t imp_cred = (krb5_gss_cred_id_t)impersonator_cred_handle;
    krb5_gss_name_t user = (krb5_gss_name_t)desired_name;
    krb5_gss_cred_id_t cred = NULL;
    kg_imp_step_ctx_t sctx = NULL;
    krb5_context context = NULL;
    krb5_cc_cursor cur = 0;
    krb5_creds cur_creds, s4u_creds;
    krb5_data in = empty_data(), out = empty_data(), realm = empty_data();
    unsigned int flags = 0;
    krb5_timestamp now;
    krb5_boolean imp_cred_locked = FALSE;
    krb5_boolean first_call;
    gss_name_t allocated_user_name = GSS_C_NO_NAME;

    /* Initialize caller outputs. */
    if (output_token != NULL) {
        output_token->value = NULL;
        output_token->length = 0;
    }
    if (target_realm != NULL) {
        target_realm->value = NULL;
        target_realm->length = 0;
    }
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;
    *minor_status = 0;

    first_call = (*cred_handle == GSS_C_NO_CREDENTIAL);

    if (!first_call) {
        /* Subsequent call: unwrap the mechglue shell (if any) and retrieve the
         * inner krb5 credential.  The first call returns a mechglue-wrapped
         * in-progress handle so that gss_release_cred() dispatches correctly;
         * we peel that wrapper off here before continuing the step. */
        {
            gss_union_cred_t uc = (gss_union_cred_t)*cred_handle;
            if (uc->loopback == uc) {
                cred = (krb5_gss_cred_id_t)uc->cred_array[0];
                free(uc->mechs_array[0].elements);
                free(uc->mechs_array);
                free(uc->cred_array);
                free(uc);
                *cred_handle = GSS_C_NO_CREDENTIAL;
            } else {
                cred = (krb5_gss_cred_id_t)*cred_handle;
            }
        }
        sctx = cred->imp_step_ctx;
        if (sctx == NULL || sctx->tcc == NULL) {
            code = EINVAL;
            goto error;
        }
        if (input_token == NULL || input_token->length == 0) {
            code = EINVAL;
            goto error;
        }
        in = make_data(input_token->value, (unsigned int)input_token->length);
        goto drive_step;
    }

    /* --- First call: validate parameters and set up in-progress credential. --- */

    if (impersonator_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (desired_name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;
    if (cred_handle == NULL || output_token == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    if (cred_usage != GSS_C_INITIATE) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        return GSS_S_FAILURE;
    }

    /* Unwrap a mechglue union credential if one was passed.
     * The mechglue sets loopback to point to itself; use that to detect it. */
    {
        gss_union_cred_t uc = (gss_union_cred_t)impersonator_cred_handle;
        if (uc->loopback == uc) {
            impersonator_cred_handle =
                gssint_get_mechanism_cred(uc, (gss_OID)gss_mech_krb5);
            if (impersonator_cred_handle == GSS_C_NO_CREDENTIAL) {
                *minor_status = 0;
                return GSS_S_NO_CRED;
            }
            imp_cred = (krb5_gss_cred_id_t)impersonator_cred_handle;
        }
    }

    if (imp_cred->usage != GSS_C_INITIATE && imp_cred->usage != GSS_C_BOTH) {
        *minor_status = 0;
        return GSS_S_NO_CRED;
    }

    /* Unwrap a mechglue union name if one was passed. */
    {
        gss_union_name_t un = (gss_union_name_t)desired_name;
        if (un->loopback == un) {
            if (un->mech_type != NULL &&
                g_OID_equal(un->mech_type, (gss_OID)gss_mech_krb5) &&
                un->mech_name != NULL) {
                /* Already canonicalized for krb5: use the internal name directly. */
                user = (krb5_gss_name_t)un->mech_name;
            } else {
                major = gssint_import_internal_name(minor_status,
                                                    (gss_OID)gss_mech_krb5,
                                                    un, &allocated_user_name);
                if (GSS_ERROR(major))
                    return major;
                user = (krb5_gss_name_t)allocated_user_name;
            }
        }
    }

    if (user->is_cert) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        major = GSS_S_UNAVAILABLE;
        goto cleanup;
    }

    code = krb5_gss_init_context(&context);
    if (code != 0)
        goto error;

    major = kg_cred_resolve(minor_status, context, impersonator_cred_handle,
                            NULL);
    if (GSS_ERROR(major)) {
        krb5_free_context(context);
        context = NULL;
        goto cleanup;
    }
    imp_cred_locked = TRUE;

    /* Allocate the in-progress credential. */
    cred = k5alloc(sizeof(*cred), &code);
    if (cred == NULL)
        goto error;
    code = k5_mutex_init(&cred->lock);
    if (code != 0)
        goto error;
    cred->usage = GSS_C_INITIATE;
    cred->have_tgt = imp_cred->have_tgt;
    cred->expire = imp_cred->expire;

    code = kg_duplicate_name(context, imp_cred->name, &cred->name);
    if (code != 0)
        goto error;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &cred->ccache);
    if (code != 0)
        goto error;
    cred->destroy_ccache = 1;

    code = krb5_cc_initialize(context, cred->ccache, imp_cred->name->princ);
    if (code != 0)
        goto error;

    /* Copy all credentials from the impersonator ccache. */
    code = krb5_cc_start_seq_get(context, imp_cred->ccache, &cur);
    if (code != 0)
        goto error;
    while (!(code = krb5_cc_next_cred(context, imp_cred->ccache,
                                      &cur, &cur_creds))) {
        code = krb5_cc_store_cred(context, cred->ccache, &cur_creds);
        krb5_free_cred_contents(context, &cur_creds);
        if (code != 0)
            break;
    }
    krb5_cc_end_seq_get(context, imp_cred->ccache, &cur);
    cur = 0;
    if (code != KRB5_CC_END)
        goto error;
    code = 0;

    /* Copy user principal for S4U2Self. */
    code = krb5_copy_principal(context, user->princ, &cred->s4u_user);
    if (code != 0)
        goto error;

    k5_mutex_unlock(&imp_cred->lock);
    imp_cred_locked = FALSE;

    /* Allocate step context; it takes ownership of 'context'. */
    sctx = k5alloc(sizeof(*sctx), &code);
    if (sctx == NULL)
        goto error;
    sctx->context = context;
    context = NULL;  /* sctx now owns the context */
    cred->imp_step_ctx = sctx;

    /* Initialise the S4U2Self TGS step context. */
    {
        krb5_creds in_creds;
        memset(&in_creds, 0, sizeof(in_creds));
        /* client must match the ccache principal so get_cached_local_tgt
         * can find the impersonator's TGT; the S4U2Self user is set via
         * k5_tkt_creds_set_s4u2self padata. */
        in_creds.client = cred->name->princ;
        in_creds.server = cred->name->princ;
        if (time_req != 0 && time_req != GSS_C_INDEFINITE) {
            code = krb5_timeofday(sctx->context, &now);
            if (code != 0)
                goto error;
            in_creds.times.endtime = ts_incr(now, time_req);
        }
        code = krb5_tkt_creds_init(sctx->context, cred->ccache, &in_creds, 0,
                                   &sctx->tcc);
        if (code != 0)
            goto error;
        code = k5_tkt_creds_set_s4u2self(sctx->context, sctx->tcc,
                                          cred->s4u_user, NULL);
        if (code != 0)
            goto error;
    }
    /* in = empty_data() — correct for first step invocation */

drive_step:
    code = krb5_tkt_creds_step(sctx->context, sctx->tcc, &in, &out,
                                &realm, &flags);
    if (code != 0)
        goto error;

    if (flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE) {
        /* Return the KDC request and realm to the caller. */
        if (output_token != NULL) {
            output_token->value = out.data;
            output_token->length = out.length;
            out = empty_data();
        }
        if (target_realm != NULL) {
            target_realm->value = realm.data;
            target_realm->length = realm.length;
            realm = empty_data();
        }
        /* Wrap in a mechglue union so that gss_release_cred() dispatches
         * to krb5_gss_release_cred() if the caller abandons the exchange. */
        major = wrap_imp_step_cred(minor_status, cred, cred_handle);
        if (GSS_ERROR(major))
            goto error;
        cred = NULL;  /* caller owns the in-progress handle */
        *minor_status = 0;
        major = GSS_S_CONTINUE_NEEDED;
        goto cleanup;
    }

    /* Exchange complete: extract the ticket and finalize the credential. */
    memset(&s4u_creds, 0, sizeof(s4u_creds));
    code = krb5_tkt_creds_get_creds(sctx->context, sctx->tcc, &s4u_creds);
    if (code != 0)
        goto error;

    /*
     * Save the S4U2Self evidence and the service TGT ccache before
     * kg_finalize_impersonation() destroys cred->ccache.  These are used by
     * gss_init_sec_context() to drive the step-based S4U2Proxy exchange.
     */
    code = krb5int_copy_data_contents(sctx->context, &s4u_creds.ticket,
                                      &cred->s4u_evidence);
    if (code != 0) {
        krb5_free_cred_contents(sctx->context, &s4u_creds);
        goto error;
    }
    code = copy_ccache(sctx->context, cred->ccache, cred->name->princ,
                       &cred->s4u_tgt_ccache);
    if (code != 0) {
        krb5_free_cred_contents(sctx->context, &s4u_creds);
        goto error;
    }
    cred->use_step_proxy = 1;

    code = kg_finalize_impersonation(sctx->context, cred, &s4u_creds);
    krb5_free_cred_contents(sctx->context, &s4u_creds);
    if (code != 0)
        goto error;

    if (time_rec != NULL) {
        if (krb5_timeofday(sctx->context, &now) == 0)
            *time_rec = ts_interval(now, cred->expire);
    }

    /* Release step state; cred becomes a fully finalized impersonation cred. */
    kg_release_imp_step_ctx(cred->imp_step_ctx);
    cred->imp_step_ctx = NULL;

    /* Wrap in a mechglue union credential so the mechglue API works. */
    major = wrap_imp_step_cred(minor_status, cred, cred_handle);
    if (GSS_ERROR(major))
        goto error;  /* cred non-NULL; error label will release it */
    cred = NULL;     /* ownership transferred to the union credential */
    *minor_status = 0;
    major = GSS_S_COMPLETE;
    goto cleanup;

error:
    if (imp_cred_locked)
        k5_mutex_unlock(&imp_cred->lock);
    if (cred != NULL) {
        OM_uint32 tmp;
        krb5_gss_release_cred(&tmp, (gss_cred_id_t *)&cred);
    }
    /* context is non-NULL only on first call before sctx took ownership. */
    if (context != NULL)
        krb5_free_context(context);
    *cred_handle = GSS_C_NO_CREDENTIAL;
    *minor_status = code;
    major = GSS_S_FAILURE;

cleanup:
    if (allocated_user_name != GSS_C_NO_NAME) {
        OM_uint32 tmp;
        gssint_release_internal_name(&tmp, (gss_OID)gss_mech_krb5,
                                     &allocated_user_name);
    }
    free(out.data);
    free(realm.data);
    return major;
}

/*
 * Return the target KDC realm for the current step of a step-based S4U2Proxy
 * exchange in progress on context_handle.  The returned buffer is a copy and
 * must be released with gss_release_buffer().  Returns GSS_S_UNAVAILABLE if
 * no step-based S4U2Proxy exchange is in progress.
 */
OM_uint32 KRB5_CALLCONV
krb5_gss_get_proxy_realm(OM_uint32 *minor_status,
                          gss_ctx_id_t context_handle,
                          gss_buffer_t realm_buf)
{
    krb5_gss_ctx_id_rec *ctx;
    kg_s4u2proxy_step_ctx_t sctx;

    *minor_status = 0;
    realm_buf->value = NULL;
    realm_buf->length = 0;

    if (context_handle == GSS_C_NO_CONTEXT)
        return GSS_S_NO_CONTEXT;

    /* Unwrap a mechglue union context if one was passed. */
    {
        gss_union_ctx_id_t uc = (gss_union_ctx_id_t)context_handle;
        if (uc->loopback == uc)
            context_handle = uc->internal_ctx_id;
    }

    ctx = (krb5_gss_ctx_id_rec *)context_handle;
    sctx = ctx->proxy_step_ctx;

    if (sctx == NULL || sctx->realm.length == 0)
        return GSS_S_UNAVAILABLE;

    realm_buf->value = malloc(sctx->realm.length + 1);
    if (realm_buf->value == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(realm_buf->value, sctx->realm.data, sctx->realm.length);
    ((char *)realm_buf->value)[sctx->realm.length] = '\0';
    realm_buf->length = sctx->realm.length;
    return GSS_S_COMPLETE;
}
