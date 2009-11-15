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

/*
 * IAKERB implementation
 */

struct _iakerb_ctx_id_rec {
    krb5_context k5c;
    krb5_init_creds_context icc;
    krb5_data conv;
};

typedef struct _iakerb_ctx_id_rec iakerb_ctx_id_rec;
typedef iakerb_ctx_id_rec *iakerb_ctx_id_t;

static void
iakerb_release_context(iakerb_ctx_id_t ctx)
{
    if (ctx == NULL)
        return;

    krb5_init_creds_free(ctx->k5c, ctx->icc);
    krb5_free_data_contents(ctx->k5c, &ctx->conv);
    krb5_free_context(ctx->k5c);
    free(ctx);
}

krb5_error_code
iakerb_make_finished(krb5_context context,
                     krb5_cksumtype cksumtype,
                     const krb5_keyblock *key,
                     const krb5_data *conv,
                     krb5_data **finished)
{
    krb5_error_code code;
    krb5_iakerb_finished iaf;

    *finished = NULL;

    memset(&iaf, 0, sizeof(iaf));

    code = krb5_c_make_checksum(context, cksumtype,
                                key, KRB5_KEYUSAGE_IAKERB_FINISHED,
                                conv, &iaf.checksum);
    if (code != 0)
        return code;

    code = encode_krb5_iakerb_finished(&iaf, finished);

    krb5_free_checksum_contents(context, &iaf.checksum);

    return code;
}

krb5_error_code
iakerb_verify_finished(krb5_context context,
                       const krb5_keyblock *key,
                       const krb5_data *conv,
                       const krb5_data *finished)
{
    krb5_error_code code;
    krb5_iakerb_finished *iaf;
    krb5_boolean valid = FALSE;

    code = decode_krb5_iakerb_finished(finished, &iaf);
    if (code != 0)
        return code;

    code = krb5_c_verify_checksum(context, key, KRB5_KEYUSAGE_IAKERB_FINISHED,
                                  conv, &iaf->checksum, &valid);
    if (code == 0 && valid == FALSE)
        code = KRB5KRB_AP_ERR_BAD_INTEGRITY;

    krb5_free_iakerb_finished(context, iaf);

    return code;
}

static krb5_error_code
iakerb_save_token(iakerb_ctx_id_t ctx, const gss_buffer_t token)
{
    char *p;

    p = realloc(ctx->conv.data, ctx->conv.length + token->length);
    if (p == NULL)
        return ENOMEM;

    memcpy(p + ctx->conv.length, token->value, token->length);
    ctx->conv.data = p;
    ctx->conv.length += token->length;

    return 0;
}

static krb5_error_code
iakerb_make_token(iakerb_ctx_id_t ctx,
                  krb5_data *realm,
                  krb5_data *cookie,
                  krb5_data *request,
                  int initialContextToken,
                  gss_buffer_t token)
{
    krb5_error_code code;
    krb5_iakerb_header iah;
    krb5_data *data = NULL;
    char *p;

    token->value = NULL;
    token->length = 0;

    /*
     * Assemble the IAKERB-HEADER from the realm and cookie
     */
    memset(&iah, 0, sizeof(iah));
    iah.target_realm = *realm;
    iah.cookie = cookie;

    code = encode_krb5_iakerb_header(&iah, &data);
    if (code != 0)
        goto cleanup;

    /*
     * Add the TOK_ID to the beginning of the header and the
     * Kerberos request to the end.
     */
    p = realloc(data->data, 2 + data->length + request->length);
    if (p == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    memmove(p + 2, data->data, data->length);
    memcpy(p + 2 + data->length, request->data, request->length);
    store_16_be(IAKERB_TOK_PROXY, p);

    data->length += 2 /* TOK_ID */ + request->length;
    data->data = p;

    if (initialContextToken) {
        unsigned int tokenSize;
        unsigned char *q;

        tokenSize = g_token_size(gss_mech_iakerb, data->length);
        token->value = k5alloc(tokenSize, &code);
        if (code != 0)
            goto cleanup;
        q = token->value;
        g_make_token_header(gss_mech_iakerb, data->length, &q, -1);
        memcpy(q, data->data, data->length);
        token->length = tokenSize + data->length;
    } else {
        token->value = data->data;
        token->length = data->length;
        data->data = NULL; /* do not double-free */
    }

cleanup:
    krb5_free_data(ctx->k5c, data);

    return code;
}

static krb5_error_code
iakerb_initiator_step(iakerb_ctx_id_t ctx,
                      krb5_gss_cred_id_t cred,
                      const gss_buffer_t input_token,
                      gss_buffer_t output_token,
                      int *continueNeeded)
{
    krb5_error_code code;
    krb5_data in, out, realm;
    unsigned int flags = 0;
    unsigned int bodysize;
    unsigned char *ptr;
    krb5_iakerb_header *iah = NULL;
    OM_uint32 tmp;

    *continueNeeded = 0;
    output_token->length = 0;
    output_token->value = NULL;

    if (input_token != GSS_C_NO_BUFFER) {
        code = g_verify_token_header(gss_mech_iakerb,
                                     &bodysize, &ptr, IAKERB_TOK_PROXY,
                                     input_token->length, 0);
        if (code != 0)
            goto cleanup;

        /* Now, ptr points into the IAKERB-HEADER. Decode that. */
        in.data = (char *)ptr;
        in.length = der_read_length(&ptr, &bodysize);
        if (in.length < 0) {
            code = G_BAD_TOK_HEADER;
            goto cleanup;
        }

        code = decode_krb5_iakerb_header(&in, &iah);
        if (code != 0)
            goto cleanup;

        /* Now, ptr points into the Kerberos message. */
        in.data = (char *)ptr;
        in.length = bodysize;
    } else {
        in.data = NULL;
        in.length = 0;
    }

    out.length = 0;
    out.data = NULL;

    realm.length = 0;
    realm.data = NULL;

    code = krb5_init_creds_step(ctx->k5c,
                                ctx->icc,
                                &in,
                                &out,
                                &realm,
                                &flags);
    if (code != 0)
        goto cleanup;

    if (flags) {
        /* finished */
        krb5_creds creds;

        memset(&creds, 0, sizeof(creds));

        assert(cred->iakerb);

        code = krb5_init_creds_get_creds(ctx->k5c, ctx->icc, &creds);
        if (code != 0)
            goto cleanup;

        code = krb5_cc_store_cred(ctx->k5c, cred->ccache, &creds);
        if (code != 0) {
            krb5_free_cred_contents(ctx->k5c, &creds);
            goto cleanup;
        }
        krb5_free_cred_contents(ctx->k5c, &creds);
    } else {
        code = iakerb_make_token(ctx, &realm, iah ? iah->cookie : NULL, &out,
                                 (input_token == GSS_C_NO_BUFFER),
                                 output_token);
        if (code != 0)
            goto cleanup;
        *continueNeeded = 1;
    }

    /* Save the token for generating a future checksum */
    code = iakerb_save_token(ctx, output_token);
    if (code != 0)
        goto cleanup;

cleanup:
    if (code != 0)
        gss_release_buffer(&tmp, output_token);
    krb5_free_iakerb_header(ctx->k5c, iah);
    krb5_free_data_contents(ctx->k5c, &out);
    krb5_free_data_contents(ctx->k5c, &realm);

    return code;
}

static krb5_error_code
iakerb_initiator_handover(iakerb_ctx_id_t ctx,
                          gss_ctx_id_t *context_handle)
{
    krb5_gss_ctx_id_t kctx;
    krb5_error_code code;



    return code;
}

static krb5_error_code
iakerb_init_creds_ctx(iakerb_ctx_id_t ctx,
                      krb5_gss_cred_id_t cred,
                      krb5_gss_name_t target)
{
    krb5_error_code code;
    krb5_get_init_creds_opt *opts = NULL;

    if (cred->iakerb == 0 || cred->password.data == NULL) {
        code = EINVAL;
        goto cleanup;
    }

    code = krb5_init_creds_init(ctx->k5c,
                                cred->name->princ,
                                NULL,
                                NULL,
                                0,
                                opts,
                                &ctx->icc);
    if (code != 0)
        goto cleanup;

    code = krb5_init_creds_set_password(ctx->k5c,
                                        ctx->icc,
                                        cred->password.data);
    if (code != 0)
        goto cleanup;

cleanup:
    krb5_get_init_creds_opt_free(ctx->k5c, opts);

    return code;
}

static krb5_error_code
iakerb_alloc_context(iakerb_ctx_id_t *pctx)
{
    iakerb_ctx_id_t ctx;
    krb5_error_code code;

    *pctx = NULL;

    ctx = k5alloc(sizeof(*ctx), &code);
    if (ctx == NULL)
        goto cleanup;

    code = krb5_gss_init_context(&ctx->k5c);
    if (code != 0)
        goto cleanup;

    *pctx = ctx;

cleanup:
    if (code != 0)
        iakerb_release_context(ctx);

    return code;
}

OM_uint32
iakerb_delete_sec_context(OM_uint32 *minor_status,
                          gss_ctx_id_t *context_handle,
                          gss_buffer_t output_token)
{
    if (*context_handle != GSS_C_NO_CONTEXT) {
        iakerb_release_context((iakerb_ctx_id_t)*context_handle);
        *context_handle = GSS_C_NO_CONTEXT;
    }

    output_token->length = 0;
    output_token->value = NULL;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
iakerb_accept_sec_context(OM_uint32 *minor_status,
                          gss_ctx_id_t *context_handler,
                          gss_cred_id_t verifier_cred_handle,
                          gss_buffer_t input_token,
                          gss_channel_bindings_t input_chan_bindings,
                          gss_name_t *src_name,
                          gss_OID *mech_type,
                          gss_buffer_t output_token,
                          OM_uint32 *ret_flags,
                          OM_uint32 *time_rec,
                          gss_cred_id_t *delegated_cred_handle)
{
}

OM_uint32
iakerb_init_sec_context(OM_uint32 *minor_status,
                        gss_cred_id_t claimant_cred_handle,
                        gss_ctx_id_t *context_handle,
                        gss_name_t target_name,
                        gss_OID mech_type,
                        OM_uint32 req_flags,
                        OM_uint32 time_req,
                        gss_channel_bindings_t input_chan_bindings,
                        gss_buffer_t input_token,
                        gss_OID *actual_mech_type,
                        gss_buffer_t output_token,
                        OM_uint32 *ret_flags,
                        OM_uint32 *time_rec)
{
    OM_uint32 major_status = GSS_S_FAILURE;
    OM_uint32 code;
    iakerb_ctx_id_t ctx;
    krb5_gss_cred_id_t kcred;
    int credLocked = 0;
    int continueNeeded = 0;

    if (*context_handle == GSS_C_NO_CONTEXT) {
        code = iakerb_alloc_context(&ctx);
        if (code != 0)
            goto cleanup;
    } else
        ctx = (iakerb_ctx_id_t)*context_handle;

    if (!kg_validate_name(target_name)) {
        code = G_VALIDATE_FAILED;
        major_status = GSS_S_CALL_BAD_STRUCTURE | GSS_S_BAD_NAME;
        goto cleanup;
    }

    major_status = krb5_gss_validate_cred_1(&code,
                                            claimant_cred_handle,
                                            ctx->k5c);
    if (GSS_ERROR(major_status))
        goto cleanup;

    credLocked = 1;

    kcred = (krb5_gss_cred_id_t)claimant_cred_handle;
    if (kcred->iakerb == 0) {
        major_status = GSS_S_DEFECTIVE_CREDENTIAL;
        goto cleanup;
    }

    if (*context_handle == GSS_C_NO_CONTEXT) {
        code = iakerb_init_creds_ctx(ctx, kcred, target_name);
        if (code != 0)
            goto cleanup;
    }

    code = iakerb_initiator_step(ctx,
                                 kcred,
                                 input_token,
                                 output_token,
                                 &continueNeeded);
    if (code != 0)
        goto cleanup;

    major_status = GSS_S_CONTINUE_NEEDED;

    if (!continueNeeded) {
        /* Now, handover to native krb5 mech. */
    }

    if (*context_handle == GSS_C_NO_CONTEXT)
        *context_handle = (gss_ctx_id_t)ctx;
    if (actual_mech_type != NULL)
        *actual_mech_type = gss_mech_krb5;
    if (ret_flags != NULL)
        *ret_flags = 0;
    if (time_rec != NULL)
        *time_rec = 0;

cleanup:
    if (credLocked)
        k5_mutex_unlock(&kcred->lock);
    if (*context_handle == GSS_C_NO_CONTEXT && ctx != NULL)
        iakerb_release_context(ctx);

    *minor_status = code;
    return major_status;
}

