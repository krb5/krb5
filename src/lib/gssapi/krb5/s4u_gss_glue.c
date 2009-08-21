/* -*- mode: c; indent-tabs-mode: nil -*- */
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
 *
 */
#include "k5-int.h"
#include "gssapiP_krb5.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <assert.h>

static OM_uint32
kg_set_desired_mechs(OM_uint32 *minor_status,
                     const gss_OID_set desired_mechs,
                     krb5_gss_cred_id_t cred)
{
    unsigned int i;

    if (desired_mechs == GSS_C_NULL_OID_SET) {
        cred->prerfc_mech = 1;
        cred->rfc_mech = 1;
    } else {
        cred->prerfc_mech = 0;
        cred->rfc_mech = 0;

        for (i = 0; i < desired_mechs->count; i++) {
            if (g_OID_equal(gss_mech_krb5_old, &desired_mechs->elements[i]))
                cred->prerfc_mech = 1;
            else if (g_OID_equal(gss_mech_krb5, &desired_mechs->elements[i]))
                cred->rfc_mech = 1;
        }

        if (!cred->prerfc_mech && !cred->rfc_mech) {
            *minor_status = 0;
            return GSS_S_BAD_MECH;
        }
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
kg_return_mechs(OM_uint32 *minor_status,
                krb5_gss_cred_id_t cred,
                gss_OID_set *actual_mechs)
{
    OM_uint32 major_status, minor;
    gss_OID_set mechs;

    if (actual_mechs == NULL)
        return GSS_S_COMPLETE;

    major_status = generic_gss_create_empty_oid_set(minor_status, &mechs);
    if (GSS_ERROR(major_status))
        return major_status;

    if (cred->prerfc_mech) {
        major_status = generic_gss_add_oid_set_member(minor_status,
                                                      gss_mech_krb5_old,
                                                      &mechs);
        if (GSS_ERROR(major_status)) {
            generic_gss_release_oid_set(&minor, &mechs);
            return major_status;
        }
    }
    if (cred->rfc_mech) {
        major_status = generic_gss_add_oid_set_member(minor_status,
                                                      gss_mech_krb5,
                                                      &mechs);
        if (GSS_ERROR(major_status)) {
            generic_gss_release_oid_set(&minor, &mechs);
            return major_status;
        }
    }

    *actual_mechs = mechs;

    return GSS_S_COMPLETE;
}

static int
kg_is_initiator_cred(krb5_gss_cred_id_t cred)
{
    return (cred->usage == GSS_C_INITIATE || cred->usage == GSS_C_BOTH);
}

static OM_uint32
kg_impersonate(OM_uint32 *minor_status,
               const krb5_gss_cred_id_t impersonator_cred,
               const krb5_principal user,
               OM_uint32 time_req,
               const gss_OID_set desired_mechs,
               krb5_gss_cred_id_t *output_cred,
               gss_OID_set *actual_mechs,
               OM_uint32 *time_rec,
               krb5_context context)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_cred_id_t cred = NULL;
    krb5_creds in_creds, *out_creds = NULL;

    memset(&in_creds, 0, sizeof(in_creds));
    memset(&out_creds, 0, sizeof(out_creds));

    k5_mutex_assert_locked(&impersonator_cred->lock);

    if (!kg_is_initiator_cred(impersonator_cred) ||
        impersonator_cred->ccache == NULL ||
        impersonator_cred->princ == NULL) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    cred = (krb5_gss_cred_id_t)xmalloc(sizeof(*cred));
    if (cred == NULL) {
        *minor_status = ENOMEM;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }
    memset(cred, 0, sizeof(*cred));

    code = k5_mutex_init(&cred->lock);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    cred->usage = GSS_C_INITIATE;

    major_status = kg_set_desired_mechs(minor_status, desired_mechs, cred);
    if (GSS_ERROR(major_status))
        goto cleanup;

    code = krb5_copy_principal(context, user, &cred->princ);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    in_creds.client = cred->princ;
    in_creds.server = impersonator_cred->princ;

    if (impersonator_cred->req_enctypes != NULL)
        in_creds.keyblock.enctype = impersonator_cred->req_enctypes[0];

    code = krb5_get_credentials_for_user(context,
                                         KRB5_GC_CANONICALIZE | KRB5_GC_NO_STORE,
                                         impersonator_cred->ccache,
                                         &in_creds,
                                         NULL, &out_creds);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &cred->ccache);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = krb5_cc_initialize(context, cred->ccache, cred->princ);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = krb5_cc_store_cred(context, cred->ccache, out_creds);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    cred->tgt_expire = out_creds->times.endtime;

    if (time_rec != NULL) {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0) {
            *minor_status = code;
            major_status = GSS_S_FAILURE;
            goto cleanup;
        }

        *time_rec = cred->tgt_expire - now;
    }

    major_status = kg_return_mechs(minor_status, cred, actual_mechs);
    if (GSS_ERROR(major_status))
        goto cleanup;

    if (!kg_save_cred_id((gss_cred_id_t)cred)) {
        *minor_status = (OM_uint32)G_VALIDATE_FAILED;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    major_status = GSS_S_COMPLETE;
    *output_cred = cred;

cleanup:
    if (GSS_ERROR(major_status) && cred != NULL) {
        k5_mutex_destroy(&cred->lock);
        if (cred->ccache != NULL)
            krb5_cc_destroy(context, cred->ccache);
        if (cred->princ != NULL)
            krb5_free_principal(context, cred->princ);
        xfree(cred);
    }

    if (out_creds != NULL)
        krb5_free_creds(context, out_creds);

    return major_status;
}

OM_uint32
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

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;

    code = krb5_gss_init_context(&context);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = krb5_gss_validate_cred_1(minor_status,
                                            impersonator_cred_handle,
                                            context);
    if (GSS_ERROR(major_status)) {
        krb5_free_context(context);
        return major_status;
    }

    major_status = kg_impersonate(minor_status,
                                  (krb5_gss_cred_id_t)impersonator_cred_handle,
                                  (krb5_principal)desired_name,
                                  time_req,
                                  desired_mechs,
                                  &cred,
                                  actual_mechs,
                                  time_rec,
                                  context);

    *output_cred_handle = (gss_cred_id_t)cred;

    k5_mutex_unlock(&((krb5_gss_cred_id_t)impersonator_cred_handle)->lock);
    krb5_free_context(context);

    return major_status;

}

static krb5_error_code
kg_get_evidence_ticket(krb5_context context,
                       krb5_gss_cred_id_t impersonator_cred,
                       krb5_gss_cred_id_t subject_cred,
                       krb5_creds *ncreds)
{
    krb5_creds mcreds;

    memset(&mcreds, 0, sizeof(mcreds));

    mcreds.magic = KV5M_CREDS;
    mcreds.times.endtime = subject_cred->tgt_expire;
    mcreds.server = impersonator_cred->princ;
    mcreds.client = subject_cred->princ;

    return krb5_cc_retrieve_cred(context, subject_cred->ccache,
                                 KRB5_TC_MATCH_TIMES, &mcreds, ncreds);
}

static krb5_error_code
kg_duplicate_ccache(krb5_context context,
                    krb5_gss_cred_id_t impersonator_cred,
                    krb5_ccache *out_ccache)
{
    krb5_error_code code;
    krb5_ccache ccache;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &ccache);
    if (code != 0)
        return code;

    code = krb5_cc_initialize(context, ccache, impersonator_cred->princ);
    if (code != 0) {
        krb5_cc_destroy(context, ccache);
        return code;
    }

    code = krb5_cc_copy_creds(context, impersonator_cred->ccache, ccache);
    if (code != 0) {
        krb5_cc_destroy(context, ccache);
        return code;
    }

    *out_ccache = ccache;

    return 0;
}

static OM_uint32
kg_compose_cred(OM_uint32 *minor_status,
                krb5_gss_cred_id_t impersonator_cred,
                krb5_gss_cred_id_t subject_cred,
                OM_uint32 time_req,
                const gss_OID_set desired_mechs,
                krb5_gss_cred_id_t *output_cred,
                gss_OID_set *actual_mechs,
                OM_uint32 *time_rec,
                krb5_context context)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_cred_id_t cred = NULL;
    krb5_creds evidence_creds;

    memset(&evidence_creds, 0, sizeof(evidence_creds));

    k5_mutex_assert_locked(&impersonator_cred->lock);
    k5_mutex_assert_locked(&subject_cred->lock);

    if (!kg_is_initiator_cred(impersonator_cred) ||
        impersonator_cred->ccache == NULL ||
        impersonator_cred->princ == NULL) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    if (!kg_is_initiator_cred(subject_cred) ||
        subject_cred->ccache == NULL ||
        subject_cred->princ == NULL) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    cred = (krb5_gss_cred_id_t)xmalloc(sizeof(*cred));
    if (cred == NULL) {
        *minor_status = ENOMEM;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }
    memset(cred, 0, sizeof(*cred));

    code = k5_mutex_init(&cred->lock);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    cred->usage = GSS_C_INITIATE;
    cred->proxy_cred = 1;

    major_status = kg_set_desired_mechs(minor_status, desired_mechs, cred);
    if (GSS_ERROR(major_status))
        goto cleanup;

    cred->tgt_expire = impersonator_cred->tgt_expire;

    /* The returned credential's subject matches subject_cred */
    code = krb5_copy_principal(context, subject_cred->princ, &cred->princ);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = kg_duplicate_ccache(context, impersonator_cred, &cred->ccache);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = kg_get_evidence_ticket(context, impersonator_cred,
                                  subject_cred, &evidence_creds);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    code = krb5_cc_store_cred(context, cred->ccache, &evidence_creds);
    if (code != 0) {
        *minor_status = code;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    if (time_rec != NULL) {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0) {
            *minor_status = code;
            major_status = GSS_S_FAILURE;
            goto cleanup;
        }

        *time_rec = cred->tgt_expire - now;
    }

    major_status = kg_return_mechs(minor_status, cred, actual_mechs);
    if (GSS_ERROR(major_status))
        goto cleanup;

    if (!kg_save_cred_id((gss_cred_id_t)cred)) {
        *minor_status = (OM_uint32)G_VALIDATE_FAILED;
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    major_status = GSS_S_COMPLETE;
    *output_cred = cred;

cleanup:
    if (GSS_ERROR(major_status) && cred != NULL) {
        k5_mutex_destroy(&cred->lock);
        if (cred->ccache != NULL)
            krb5_cc_destroy(context, cred->ccache);
        if (cred->princ != NULL)
            krb5_free_principal(context, cred->princ);
        xfree(cred);
    }

    krb5_free_cred_contents(context, &evidence_creds);

    return major_status;
}

/*
 * Return a composite credential handle including the service's TGT
 * (service_cred_handle) and the ticket from the client to the service
 * (output_cred_handle).
 */
OM_uint32
krb5_gss_acquire_cred_impersonate_cred(OM_uint32 *minor_status,
                                       const gss_cred_id_t impersonator_cred_handle,
                                       const gss_cred_id_t subject_cred_handle,
                                       OM_uint32 time_req,
                                       const gss_OID_set desired_mechs,
                                       gss_cred_usage_t cred_usage,
                                       gss_cred_id_t *output_cred_handle,
                                       gss_OID_set *actual_mechs,
                                       OM_uint32 *time_rec)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_gss_cred_id_t cred;
    krb5_context context;

    if (impersonator_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (subject_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (output_cred_handle == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (cred_usage != GSS_C_INITIATE) {
        *minor_status = (OM_uint32)G_BAD_USAGE;
        return GSS_S_FAILURE;
    }

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;

    code = krb5_gss_init_context(&context);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = krb5_gss_validate_cred_1(minor_status,
                                            impersonator_cred_handle,
                                            context);
    if (GSS_ERROR(major_status)) {

        krb5_free_context(context);
        return major_status;
    }

    major_status = krb5_gss_validate_cred_1(minor_status,
                                            subject_cred_handle,
                                            context);
    if (GSS_ERROR(major_status)) {
        k5_mutex_unlock(&((krb5_gss_cred_id_t)impersonator_cred_handle)->lock);
        krb5_free_context(context);
        return major_status;
    }

    major_status = kg_compose_cred(minor_status,
                                   (krb5_gss_cred_id_t)impersonator_cred_handle,
                                   (krb5_gss_cred_id_t)subject_cred_handle,
                                   time_req,
                                   desired_mechs,
                                   &cred,
                                   actual_mechs,
                                   time_rec,
                                   context);

    *output_cred_handle = (gss_cred_id_t)cred;

    k5_mutex_unlock(&((krb5_gss_cred_id_t)subject_cred_handle)->lock);
    k5_mutex_unlock(&((krb5_gss_cred_id_t)impersonator_cred_handle)->lock);
    krb5_free_context(context);

    return major_status;
}

