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
    return (cred->usage == GSS_C_INITIATE || cred->usage == GSS_C_BOTH) &&
        (cred->ccache != NULL);
}

static OM_uint32
kg_impersonate_name(OM_uint32 *minor_status,
                    const krb5_gss_cred_id_t impersonator_cred,
                    const krb5_gss_name_t user,
                    OM_uint32 time_req,
                    const gss_OID_set desired_mechs,
                    krb5_gss_cred_id_t *output_cred,
                    gss_OID_set *actual_mechs,
                    OM_uint32 *time_rec,
                    krb5_context context)
{
    OM_uint32 major_status;
    krb5_error_code code;
    krb5_creds in_creds, *out_creds = NULL;

    memset(&in_creds, 0, sizeof(in_creds));
    memset(&out_creds, 0, sizeof(out_creds));

    in_creds.client = user->princ;
    in_creds.server = impersonator_cred->name->princ;

    if (impersonator_cred->req_enctypes != NULL)
        in_creds.keyblock.enctype = impersonator_cred->req_enctypes[0];

    code = k5_mutex_lock(&user->lock);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

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
                                         &in_creds,
                                         NULL, &out_creds);
    if (code != 0) {
        krb5_free_authdata(context, in_creds.authdata);
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    major_status = kg_compose_deleg_cred(minor_status,
                                         impersonator_cred,
                                         out_creds,
                                         time_req,
                                         desired_mechs,
                                         output_cred,
                                         actual_mechs,
                                         time_rec,
                                         context);

    krb5_free_authdata(context, in_creds.authdata);
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

    major_status = kg_impersonate_name(minor_status,
                                       (krb5_gss_cred_id_t)impersonator_cred_handle,
                                       (krb5_gss_name_t)desired_name,
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

OM_uint32
kg_compose_deleg_cred(OM_uint32 *minor_status,
                      krb5_gss_cred_id_t impersonator_cred,
                      krb5_creds *subject_creds,
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

    k5_mutex_assert_locked(&impersonator_cred->lock);

    if (!kg_is_initiator_cred(impersonator_cred) ||
        impersonator_cred->name == NULL ||
        impersonator_cred->proxy_cred) {
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

    /*
     * Only return a "proxy" credential for use with constrained
     * delegation if the subject credentials are forwardable.
     * Submitting non-forwardable credentials to the KDC for use
     * with constrained delegation will only return an error.
     */
    cred->usage = GSS_C_INITIATE;
    cred->proxy_cred = !!(subject_creds->ticket_flags & TKT_FLG_FORWARDABLE);

    major_status = kg_set_desired_mechs(minor_status, desired_mechs, cred);
    if (GSS_ERROR(major_status))
        goto cleanup;

    cred->tgt_expire = impersonator_cred->tgt_expire;

    code = kg_init_name(context, subject_creds->client, NULL, 0, &cred->name);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_new_unique(context, "MEMORY", NULL, &cred->ccache);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_initialize(context, cred->ccache,
                              cred->proxy_cred ? impersonator_cred->name->princ :
                              subject_creds->client);
    if (code != 0)
        goto cleanup;

    if (cred->proxy_cred) {
        /* Impersonator's TGT will be necessary for S4U2Proxy */
        code = krb5_cc_copy_creds(context, impersonator_cred->ccache,
                                  cred->ccache);
        if (code != 0)
            goto cleanup;
    }

    code = krb5_cc_store_cred(context, cred->ccache, subject_creds);
    if (code != 0)
        goto cleanup;

    if (time_rec != NULL) {
        krb5_timestamp now;

        code = krb5_timeofday(context, &now);
        if (code != 0)
            goto cleanup;

        *time_rec = cred->tgt_expire - now;
    }

    major_status = kg_return_mechs(minor_status, cred, actual_mechs);
    if (GSS_ERROR(major_status))
        goto cleanup;

    if (!kg_save_cred_id((gss_cred_id_t)cred)) {
        code = G_VALIDATE_FAILED;
        goto cleanup;
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
        kg_release_name(context, 0, &cred->name);
        xfree(cred);
    }

    return major_status;
}
