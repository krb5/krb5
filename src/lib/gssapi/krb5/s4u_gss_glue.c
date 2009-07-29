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

#ifndef LEAN_CLIENT

OM_uint32
gss_krb5int_unwrap_cred_handle(OM_uint32 *minor_status,
                               gss_cred_id_t cred_handle,
                               const gss_OID desired_object,
                               const gss_buffer_t value)
{
    krb5_gss_cred_id_t *mech_cred = (krb5_gss_cred_id_t *)value->value;

    *mech_cred = (krb5_gss_cred_id_t)cred_handle;

    return GSS_S_COMPLETE;
}

static OM_uint32
kg_unwrap_cred_handle(OM_uint32 *minor_status,
                      gss_cred_id_t union_cred,
                      krb5_gss_cred_id_t *mech_cred)
{
    static const gss_OID_desc req_oid = {
        GSS_KRB5_UNWRAP_CRED_HANDLE_OID_LENGTH,
        GSS_KRB5_UNWRAP_CRED_HANDLE_OID };
    OM_uint32 major_status;
    gss_buffer_desc req_buffer;

    if (union_cred == GSS_C_NO_CREDENTIAL) {
        *mech_cred = NULL;
        return GSS_S_COMPLETE;
    }

    req_buffer.value = mech_cred;
    req_buffer.length = sizeof(mech_cred);

    major_status = gssspi_set_cred_option(minor_status,
                                          union_cred,
                                          (gss_OID)&req_oid,
                                          &req_buffer);

    if (GSS_ERROR(major_status))
        return major_status;

    major_status = krb5_gss_validate_cred(minor_status, (gss_cred_id_t)*mech_cred);
    if (GSS_ERROR(major_status))
        return major_status;

    return GSS_S_COMPLETE;

}

static OM_uint32
kg_unwrap_name(OM_uint32 *minor_status,
               gss_name_t union_name,
               gss_name_t *mech_name)
{
    OM_uint32 minor, major_status;
    gss_name_t canon_name;
    gss_buffer_desc buffer;

    *mech_name = GSS_C_NO_NAME;

    major_status = gss_canonicalize_name(minor_status, union_name,
                                         (gss_OID)gss_mech_krb5, &canon_name);
    if (GSS_ERROR(major_status))
        return major_status;

    major_status = gss_export_name(minor_status, canon_name, &buffer);
    if (GSS_ERROR(major_status)) {
        gss_release_name(&minor, &canon_name);
        return major_status;
    }

    gss_release_name(&minor, &canon_name);

    major_status = krb5_gss_import_name(minor_status, &buffer,
                                        gss_nt_exported_name, mech_name);

    gss_release_buffer(&minor, &buffer);
    return major_status;
}

static OM_uint32
kg_acquire_s4u_creds(OM_uint32 *minor_status,
                     krb5_gss_cred_id_t acceptor_cred,
                     gss_name_t s4u_name,
                     OM_uint32 time_req,
                     krb5_gss_cred_id_t *initiator_cred,
                     krb5_context context)
{
    krb5_error_code code;
    krb5_creds in_creds;
    krb5_creds *out_creds = NULL;

    memset(&in_creds, 0, sizeof(in_creds));

    in_creds.client = (krb5_principal)s4u_name;
    in_creds.server = acceptor_cred->princ;

    if (acceptor_cred->req_enctypes != NULL)
        in_creds.keyblock.enctype = acceptor_cred->req_enctypes[0];

    code = krb5_get_credentials_for_user(context, KRB5_GC_CANONICALIZE,
                                         acceptor_cred->ccache, &in_creds,
                                         NULL, &out_creds);
    if (code != 0) {
        *minor_status = code;
        return GSS_S_FAILURE;
    }

    code = krb5_to_gss_cred(context, out_creds, initiator_cred);
    if (code == 0) {
        if (!kg_save_cred_id((gss_cred_id_t)*initiator_cred)) {
            code = G_VALIDATE_FAILED;

            krb5_cc_destroy(context, (*initiator_cred)->ccache);
            krb5_free_principal(context, (*initiator_cred)->princ);
            k5_mutex_destroy(&(*initiator_cred)->lock);
            xfree(*initiator_cred);
            *initiator_cred = NULL;
        }
    }

    krb5_free_creds(context, out_creds);

    *minor_status = code;

    return (code != 0) ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

/* Wrap up S4U2Self in a convenient API that returns a security context */
OM_uint32 KRB5_CALLCONV
gss_krb5_create_sec_context_for_principal(OM_uint32 *minor_status,
                                          gss_ctx_id_t *context_handle,
                                          gss_cred_id_t verifier_cred_handle,
                                          gss_name_t principal,
                                          OM_uint32 req_flags,
                                          OM_uint32 time_req,
                                          gss_name_t *src_name,
                                          gss_OID *mech_type,
                                          OM_uint32 *ret_flags,
                                          OM_uint32 *time_ret,
                                          gss_cred_id_t *delegated_cred_handle)
{
    OM_uint32 minor, major_status;
    gss_ctx_id_t initiator_ctx = GSS_C_NO_CONTEXT;
    gss_name_t canon_name = NULL;
    gss_buffer_desc exported_name;
    gss_name_t s4u_name = NULL;
    krb5_gss_cred_id_t cred = NULL;
    krb5_gss_cred_id_t s4u_cred = NULL;
    gss_buffer_desc input_token, output_token;
    krb5_context context = NULL;

    exported_name.value = NULL;

    input_token.length = 0;
    input_token.value = NULL;

    output_token.length = 0;
    output_token.value = NULL;

    if (context_handle == NULL || principal == GSS_C_NO_NAME) {
        major_status = GSS_S_CALL_INACCESSIBLE_READ;
        goto cleanup;
    }

    if (mech_type != NULL)
        *mech_type = GSS_C_NO_OID;
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    *minor_status = krb5_gss_init_context(&context);
    if (*minor_status != 0) {
        major_status = GSS_S_FAILURE;
        goto cleanup;
    }

    major_status = kg_sync_ccache_name(context, minor_status);
    if (GSS_ERROR(major_status))
        goto cleanup;

    major_status = kg_unwrap_name(minor_status, principal, &s4u_name);
    if (GSS_ERROR(major_status))
        goto cleanup;

    major_status = kg_unwrap_cred_handle(minor_status, verifier_cred_handle,
                                         &cred);
    if (GSS_ERROR(major_status))
        goto cleanup;

    if (cred == NULL) {
        major_status = kg_get_defcred(minor_status, (gss_cred_id_t *)&cred);
        if (GSS_ERROR(major_status))
            goto cleanup;
    }

    major_status = kg_acquire_s4u_creds(minor_status,
                                        cred,
                                        s4u_name,
                                        time_req,
                                        &s4u_cred,
                                        context);
    if (GSS_ERROR(major_status))
        goto cleanup;

    req_flags &= ~(GSS_C_MUTUAL_FLAG);

    major_status = new_connection(minor_status,
                                  s4u_cred,
                                  &initiator_ctx,
                                  (gss_name_t)cred->princ,
                                  (gss_OID)gss_mech_krb5,
                                  req_flags,
                                  time_req,
                                  NULL, /* input_chan_bindings */
                                  &input_token,
                                  NULL,
                                  &output_token,
                                  NULL,
                                  NULL,
                                  context,
                                  TRUE);
    if (GSS_ERROR(major_status))
        goto cleanup;

    major_status = gss_accept_sec_context(minor_status,
                                          context_handle,
                                          verifier_cred_handle,
                                          &output_token,
                                          NULL,
                                          src_name,
                                          mech_type,
                                          &input_token,
                                          ret_flags,
                                          time_ret,
                                          delegated_cred_handle);
    if (major_status != GSS_S_COMPLETE)
        goto cleanup;

cleanup:
    if (verifier_cred_handle == GSS_C_NO_CREDENTIAL)
        krb5_gss_release_cred(&minor, (gss_cred_id_t *)&cred);
    if (s4u_cred != NULL)
        krb5_gss_release_cred(&minor, (gss_cred_id_t *)&s4u_cred);
    if (initiator_ctx != GSS_C_NO_CONTEXT)
        krb5_gss_delete_sec_context(&minor, &initiator_ctx, NULL);
    gss_release_buffer(&minor, &input_token);
    gss_release_buffer(&minor, &output_token);
    krb5_gss_release_name(&minor, &s4u_name);
    gss_release_buffer(&minor, &exported_name);
    gss_release_name(&minor, &canon_name);
    if (context != NULL) {
        if (GSS_ERROR(major_status) && *minor_status != 0)
            save_error_info(*minor_status, context);
        krb5_free_context(context);
    }

    return major_status;
}

#endif /* !LEAN_CLIENT */

