/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/gss-kernel-lib/gss_kernel.c - Extra pieces for GSS kernel library */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

/*
 * This file includes a few symbols cherry-picked from larger files, as well as
 * a function to import a lucid sec context.
 */

#include "gssapiP_krb5.h"
#include "kernel_gss.h"

/* Normally defined in lib/gssapi/krb5/gssapi_krb5.c. */
static const gss_OID_desc oid_array[] = {
    {GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID},
    {GSS_MECH_KRB5_OLD_OID_LENGTH, GSS_MECH_KRB5_OLD_OID}
};
const gss_OID_desc *const gss_mech_krb5     = oid_array+0;
const gss_OID_desc *const gss_mech_krb5_old = oid_array+1;

/* Create a key from key data in a lucid context. */
static krb5_error_code
lkey_to_key(const gss_krb5_lucid_key_t *lkey, krb5_key *key_out)
{
    krb5_keyblock kb;

    kb.enctype = lkey->type;
    kb.length = lkey->length;
    kb.contents = lkey->data;
    return krb5_k_create_key(NULL, &kb, key_out);
}

/* Get the RFC3961 mandator cksumtype for key. */
static inline krb5_error_code
get_cksumtype(krb5_key key, krb5_cksumtype *out)
{
    return krb5int_c_mandatory_cksumtype(NULL, key->keyblock.enctype, out);
}

/* Import a lucid context structure, creating a krb5 GSS context structure
 * sufficient for use by by wrap/unwrap/get_mic/verify_mic operations. */
static krb5_error_code
import_lucid_sec_context_v1(const gss_krb5_lucid_context_v1_t *lctx,
                            gss_ctx_id_t *context_handle_out)
{
    krb5_error_code ret;
    krb5_gss_ctx_id_t gctx;
    OM_uint32 tmpmin;
    krb5_key key = NULL;

    gctx = k5alloc(sizeof(*gctx), &ret);
    if (gctx == NULL)
        return ret;

    gctx->initiate = lctx->initiate;
    gctx->krb_times.endtime = lctx->endtime;
    gctx->seq_send = lctx->send_seq;
    gctx->seq_recv = lctx->recv_seq;
    gctx->proto = lctx->protocol;
    if (lctx->protocol == 0) {
        /* Ignore sign_alg and seal_alg since they follow from the enctype. */
        ret = lkey_to_key(&lctx->rfc1964_kd.ctx_key, &key);
        if (ret)
            goto cleanup;
        /* For raw enctypes, choose an enctype expected by kg_setup_keys. */
        if (key->keyblock.enctype == ENCTYPE_DES_CBC_RAW)
            key->keyblock.enctype = ENCTYPE_DES_CBC_CRC;
        else if (key->keyblock.enctype == ENCTYPE_DES3_CBC_RAW)
            key->keyblock.enctype = ENCTYPE_DES3_CBC_SHA1;
        ret = kg_setup_keys(NULL, gctx, key, &gctx->cksumtype);
        if (ret)
            goto cleanup;
        if (gctx->proto != 0) { /* ctx_key did not have a pre-CFX enctype. */
            ret = EINVAL;
            goto cleanup;
        }
    } else if (lctx->protocol == 1) {
        ret = lkey_to_key(&lctx->cfx_kd.ctx_key, &gctx->subkey);
        if (ret)
            goto cleanup;
        ret = get_cksumtype(gctx->subkey, &gctx->cksumtype);
        if (ret)
            goto cleanup;
        if (lctx->cfx_kd.have_acceptor_subkey) {
            gctx->have_acceptor_subkey = 1;
            ret = lkey_to_key(&lctx->cfx_kd.acceptor_subkey,
                              &gctx->acceptor_subkey);
            if (ret)
                goto cleanup;
            ret = get_cksumtype(gctx->acceptor_subkey,
                                &gctx->acceptor_subkey_cksumtype);
            if (ret)
                goto cleanup;
        }
    }

    gctx->seed_init = 0;
    gctx->established = 1;
    gctx->mech_used = (gss_OID_desc *)gss_mech_krb5;

    /*
     * The lucid context doesn't convey the gss_flags which indicate whether
     * the protocol needs replay or sequence protection.  Assume we don't
     * (because RPCSEC_GSS doesn't).
     */
    g_order_init(&gctx->seqstate, gctx->seq_recv, 0, 0, gctx->proto);

    *context_handle_out = (gss_ctx_id_t)gctx;
    gctx = NULL;

cleanup:
    krb5_k_free_key(NULL, key);
    krb5_gss_delete_sec_context(&tmpmin, (gss_ctx_id_t *)&gctx, NULL);
    return ret;
}

OM_uint32
krb5_gss_import_lucid_sec_context(OM_uint32 *minor_status, void *lctx,
                                  gss_ctx_id_t *context_handle_out)
{
    OM_uint32 vers = ((gss_krb5_lucid_context_version_t *)lctx)->version;
    krb5_error_code ret;

    if (vers == 1)
        ret = import_lucid_sec_context_v1((gss_krb5_lucid_context_v1_t *)lctx,
                                          context_handle_out);
    else
        ret = KG_LUCID_VERSION;
    *minor_status = ret;
    return (ret == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

/*
 * Normally defined in lib/gssapi/krb5/delete_sec_context.c; this version
 * is tailored for imported lucid contexts and has fewer dependencies.
 * Does not handle output tokens.
 */
OM_uint32
krb5_gss_delete_sec_context(OM_uint32 *minor_status,
                            gss_ctx_id_t *context_handle,
                            gss_buffer_t output_token)
{
    krb5_gss_ctx_id_t ctx;

    if (output_token) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }

    *minor_status = 0;
    if (*context_handle == GSS_C_NO_CONTEXT)
        return GSS_S_COMPLETE;

    ctx = (krb5_gss_ctx_id_t)*context_handle;
    g_order_free(&ctx->seqstate);
    krb5_k_free_key(NULL, ctx->enc);
    krb5_k_free_key(NULL, ctx->seq);
    krb5_k_free_key(NULL, ctx->subkey);
    krb5_k_free_key(NULL, ctx->acceptor_subkey);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    *context_handle = GSS_C_NO_CONTEXT;
    return GSS_S_COMPLETE;
}

/* Normally defined in lib/krb5/krb/kfree.c. */

void KRB5_CALLCONV
krb5_free_checksum_contents(krb5_context context, register krb5_checksum *val)
{
    if (val == NULL)
        return;
    free(val->contents);
    val->contents = NULL;
}

void KRB5_CALLCONV
krb5_free_keyblock(krb5_context context, register krb5_keyblock *val)
{
    krb5int_c_free_keyblock (context, val);
}

void KRB5_CALLCONV
krb5_free_data(krb5_context context, krb5_data *val)
{
    if (val == NULL)
        return;
    free(val->data);
    free(val);
}
