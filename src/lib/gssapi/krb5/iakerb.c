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

/*
 * IAKERB implementation
 */

extern int gssint_get_der_length(unsigned char **, OM_uint32, unsigned int*);

enum iakerb_state {
    IAKERB_AS_REQ,      /* acquiring ticket with initial creds */
    IAKERB_TGS_REQ,     /* acquiring ticket with TGT */
    IAKERB_AP_REQ       /* hand-off to normal GSS AP-REQ exchange */
};

struct _iakerb_ctx_id_rec {
    krb5_magic magic;                   /* KG_IAKERB_CONTEXT */
    krb5_context k5c;
    gss_cred_id_t defcred;              /* Initiator only */
    enum iakerb_state state;            /* Initiator only */
    krb5_init_creds_context icc;        /* Initiator only */
    krb5_tkt_creds_context tcc;         /* Initiator only */
    gss_ctx_id_t gssc;
    krb5_data conv;                     /* conversation for checksumming */
    unsigned int count;                 /* number of round trips */
    krb5_get_init_creds_opt *gic_opts;
};

#define IAKERB_MAX_HOPS ( 16 /* MAX_IN_TKT_LOOPS */ + KRB5_REFERRAL_MAXHOPS )

typedef struct _iakerb_ctx_id_rec iakerb_ctx_id_rec;
typedef iakerb_ctx_id_rec *iakerb_ctx_id_t;

/*
 * Release an IAKERB context
 */
static void
iakerb_release_context(iakerb_ctx_id_t ctx)
{
    OM_uint32 tmp;

    if (ctx == NULL)
        return;

    krb5_gss_release_cred(&tmp, &ctx->defcred);
    krb5_init_creds_free(ctx->k5c, ctx->icc);
    krb5_tkt_creds_free(ctx->k5c, ctx->tcc);
    krb5_gss_delete_sec_context(&tmp, &ctx->gssc, NULL);
    krb5_free_data_contents(ctx->k5c, &ctx->conv);
    krb5_get_init_creds_opt_free(ctx->k5c, ctx->gic_opts);
    krb5_free_context(ctx->k5c);
    free(ctx);
}

/*
 * Create a IAKERB-FINISHED structure containing a checksum of
 * the entire IAKERB exchange.
 */
krb5_error_code
iakerb_make_finished(krb5_context context,
                     krb5_key key,
                     const krb5_data *conv,
                     krb5_data **finished)
{
    krb5_error_code code;
    krb5_iakerb_finished iaf;

    *finished = NULL;

    memset(&iaf, 0, sizeof(iaf));

    if (key == NULL)
        return KRB5KDC_ERR_NULL_KEY;

    code = krb5_k_make_checksum(context, 0, key, KRB5_KEYUSAGE_IAKERB_FINISHED,
                                conv, &iaf.checksum);
    if (code != 0)
        return code;

    code = encode_krb5_iakerb_finished(&iaf, finished);

    krb5_free_checksum_contents(context, &iaf.checksum);

    return code;
}

/*
 * Verify a IAKERB-FINISHED structure submitted by the initiator
 */
krb5_error_code
iakerb_verify_finished(krb5_context context,
                       krb5_key key,
                       const krb5_data *conv,
                       const krb5_data *finished)
{
    krb5_error_code code;
    krb5_iakerb_finished *iaf;
    krb5_boolean valid = FALSE;

    if (key == NULL)
        return KRB5KDC_ERR_NULL_KEY;

    code = decode_krb5_iakerb_finished(finished, &iaf);
    if (code != 0)
        return code;

    code = krb5_k_verify_checksum(context, key, KRB5_KEYUSAGE_IAKERB_FINISHED,
                                  conv, &iaf->checksum, &valid);
    if (code == 0 && valid == FALSE)
        code = KRB5KRB_AP_ERR_BAD_INTEGRITY;

    krb5_free_iakerb_finished(context, iaf);

    return code;
}

/*
 * Save a token for future checksumming.
 */
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

/*
 * Parse a token into IAKERB-HEADER and KRB-KDC-REQ/REP
 */
static krb5_error_code
iakerb_parse_token(iakerb_ctx_id_t ctx,
                   int initialContextToken,
                   const gss_buffer_t token,
                   krb5_data *realm,
                   krb5_data **cookie,
                   krb5_data *request)
{
    krb5_error_code code;
    krb5_iakerb_header *iah = NULL;
    unsigned int bodysize, lenlen;
    int length;
    unsigned char *ptr;
    int flags = 0;
    krb5_data data;

    if (token == GSS_C_NO_BUFFER || token->length == 0) {
        code = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    if (initialContextToken)
        flags |= G_VFY_TOKEN_HDR_WRAPPER_REQUIRED;

    ptr = token->value;

    code = g_verify_token_header(gss_mech_iakerb,
                                 &bodysize, &ptr,
                                 IAKERB_TOK_PROXY,
                                 token->length, flags);
    if (code != 0)
        goto cleanup;

    data.data = (char *)ptr;

    if (bodysize-- == 0 || *ptr++ != 0x30 /* SEQUENCE */) {
        code = ASN1_BAD_ID;
        goto cleanup;
    }

    length = gssint_get_der_length(&ptr, bodysize, &lenlen);
    if (length < 0 || bodysize - lenlen < (unsigned int)length) {
        code = KRB5_BAD_MSIZE;
        goto cleanup;
    }
    data.length = 1 /* SEQUENCE */ + lenlen + length;

    ptr += length;
    bodysize -= (lenlen + length);

    code = decode_krb5_iakerb_header(&data, &iah);
    if (code != 0)
        goto cleanup;

    if (realm != NULL) {
        *realm = iah->target_realm;
        iah->target_realm.data = NULL;
    }

    if (cookie != NULL) {
        *cookie = iah->cookie;
        iah->cookie = NULL;
    }

    request->data = (char *)ptr;
    request->length = bodysize;

    assert(request->data + request->length ==
           (char *)token->value + token->length);

cleanup:
    krb5_free_iakerb_header(ctx->k5c, iah);

    return code;
}

/*
 * Create a token from IAKERB-HEADER and KRB-KDC-REQ/REP
 */
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
    unsigned int tokenSize;
    unsigned char *q;

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
     * Concatenate Kerberos request.
     */
    p = realloc(data->data, data->length + request->length);
    if (p == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    data->data = p;

    memcpy(data->data + data->length, request->data, request->length);
    data->length += request->length;

    if (initialContextToken)
        tokenSize = g_token_size(gss_mech_iakerb, data->length);
    else
        tokenSize = 2 + data->length;

    token->value = q = gssalloc_malloc(tokenSize);
    if (q == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    token->length = tokenSize;

    if (initialContextToken) {
        g_make_token_header(gss_mech_iakerb, data->length, &q,
                            IAKERB_TOK_PROXY);
    } else {
        store_16_be(IAKERB_TOK_PROXY, q);
        q += 2;
    }
    memcpy(q, data->data, data->length);
    q += data->length;

    assert(q == (unsigned char *)token->value + token->length);

cleanup:
    krb5_free_data(ctx->k5c, data);

    return code;
}

/*
 * Parse the IAKERB token in input_token and send the contained KDC
 * request to the KDC for the realm.
 *
 * Wrap the KDC reply in output_token.
 */
static krb5_error_code
iakerb_acceptor_step(iakerb_ctx_id_t ctx,
                     int initialContextToken,
                     const gss_buffer_t input_token,
                     gss_buffer_t output_token)
{
    krb5_error_code code;
    krb5_data request = empty_data(), reply = empty_data();
    krb5_data realm = empty_data();
    OM_uint32 tmp;
    int tcp_only, use_master;
    krb5_ui_4 kdc_code;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx->count >= IAKERB_MAX_HOPS) {
        code = KRB5_KDC_UNREACH;
        goto cleanup;
    }

    code = iakerb_parse_token(ctx, initialContextToken, input_token, &realm,
                              NULL, &request);
    if (code != 0)
        goto cleanup;

    if (realm.length == 0 || request.length == 0) {
        code = KRB5_BAD_MSIZE;
        goto cleanup;
    }

    code = iakerb_save_token(ctx, input_token);
    if (code != 0)
        goto cleanup;

    for (tcp_only = 0; tcp_only <= 1; tcp_only++) {
        use_master = 0;
        code = krb5_sendto_kdc(ctx->k5c, &request, &realm,
                               &reply, &use_master, tcp_only);
        if (code == 0 && krb5_is_krb_error(&reply)) {
            krb5_error *error;

            code = decode_krb5_error(&reply, &error);
            if (code != 0)
                goto cleanup;
            kdc_code = error->error;
            krb5_free_error(ctx->k5c, error);
            if (kdc_code == KRB_ERR_RESPONSE_TOO_BIG) {
                krb5_free_data_contents(ctx->k5c, &reply);
                reply = empty_data();
                continue;
            }
        }
        break;
    }

    if (code == KRB5_KDC_UNREACH || code == KRB5_REALM_UNKNOWN) {
        krb5_error error;

        memset(&error, 0, sizeof(error));
        if (code == KRB5_KDC_UNREACH)
            error.error = KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE;
        else if (code == KRB5_REALM_UNKNOWN)
            error.error = KRB_AP_ERR_IAKERB_KDC_NOT_FOUND;

        code = krb5_mk_error(ctx->k5c, &error, &reply);
        if (code != 0)
            goto cleanup;
    } else if (code != 0)
        goto cleanup;

    code = iakerb_make_token(ctx, &realm, NULL, &reply, 0, output_token);
    if (code != 0)
        goto cleanup;

    code = iakerb_save_token(ctx, output_token);
    if (code != 0)
        goto cleanup;

    ctx->count++;

cleanup:
    if (code != 0)
        gss_release_buffer(&tmp, output_token);
    /* request is a pointer into input_token, no need to free */
    krb5_free_data_contents(ctx->k5c, &realm);
    krb5_free_data_contents(ctx->k5c, &reply);

    return code;
}

/*
 * Initialise the krb5_init_creds context for the IAKERB context
 */
static krb5_error_code
iakerb_init_creds_ctx(iakerb_ctx_id_t ctx,
                      krb5_gss_cred_id_t cred,
                      OM_uint32 time_req)
{
    krb5_error_code code;

    if (cred->iakerb_mech == 0) {
        code = EINVAL;
        goto cleanup;
    }

    assert(cred->name != NULL);
    assert(cred->name->princ != NULL);

    code = krb5_get_init_creds_opt_alloc(ctx->k5c, &ctx->gic_opts);
    if (code != 0)
        goto cleanup;

    if (time_req != 0 && time_req != GSS_C_INDEFINITE)
        krb5_get_init_creds_opt_set_tkt_life(ctx->gic_opts, time_req);

    code = krb5_get_init_creds_opt_set_out_ccache(ctx->k5c, ctx->gic_opts,
                                                  cred->ccache);
    if (code != 0)
        goto cleanup;

    code = krb5_init_creds_init(ctx->k5c,
                                cred->name->princ,
                                NULL,   /* prompter */
                                NULL,   /* data */
                                0,      /* start_time */
                                ctx->gic_opts,
                                &ctx->icc);
    if (code != 0)
        goto cleanup;

    if (cred->password != NULL) {
        code = krb5_init_creds_set_password(ctx->k5c, ctx->icc,
                                            cred->password);
    } else {
        code = krb5_init_creds_set_keytab(ctx->k5c, ctx->icc,
                                          cred->client_keytab);
    }
    if (code != 0)
        goto cleanup;

cleanup:
    return code;
}

/*
 * Initialise the krb5_tkt_creds context for the IAKERB context
 */
static krb5_error_code
iakerb_tkt_creds_ctx(iakerb_ctx_id_t ctx,
                     krb5_gss_cred_id_t cred,
                     krb5_gss_name_t name,
                     OM_uint32 time_req)

{
    krb5_error_code code;
    krb5_creds creds;
    krb5_timestamp now;

    assert(cred->name != NULL);
    assert(cred->name->princ != NULL);

    memset(&creds, 0, sizeof(creds));

    creds.client = cred->name->princ;
    creds.server = name->princ;

    if (time_req != 0 && time_req != GSS_C_INDEFINITE) {
        code = krb5_timeofday(ctx->k5c, &now);
        if (code != 0)
            goto cleanup;

        creds.times.endtime = now + time_req;
    }

    if (cred->name->ad_context != NULL) {
        code = krb5_authdata_export_authdata(ctx->k5c,
                                             cred->name->ad_context,
                                             AD_USAGE_TGS_REQ,
                                             &creds.authdata);
        if (code != 0)
            goto cleanup;
    }

    code = krb5_tkt_creds_init(ctx->k5c, cred->ccache, &creds, 0, &ctx->tcc);
    if (code != 0)
        goto cleanup;

cleanup:
    krb5_free_authdata(ctx->k5c, creds.authdata);

    return code;
}

/*
 * Parse the IAKERB token in input_token and process the KDC
 * response.
 *
 * Emit the next KDC request, if any, in output_token.
 */
static krb5_error_code
iakerb_initiator_step(iakerb_ctx_id_t ctx,
                      krb5_gss_cred_id_t cred,
                      krb5_gss_name_t name,
                      OM_uint32 time_req,
                      const gss_buffer_t input_token,
                      gss_buffer_t output_token)
{
    krb5_error_code code = 0;
    krb5_data in = empty_data(), out = empty_data(), realm = empty_data();
    krb5_data *cookie = NULL;
    OM_uint32 tmp;
    unsigned int flags = 0;
    krb5_ticket_times times;

    output_token->length = 0;
    output_token->value = NULL;

    if (input_token != GSS_C_NO_BUFFER) {
        code = iakerb_parse_token(ctx, 0, input_token, NULL, &cookie, &in);
        if (code != 0)
            goto cleanup;

        code = iakerb_save_token(ctx, input_token);
        if (code != 0)
            goto cleanup;
    }

    switch (ctx->state) {
    case IAKERB_AS_REQ:
        if (ctx->icc == NULL) {
            code = iakerb_init_creds_ctx(ctx, cred, time_req);
            if (code != 0)
                goto cleanup;
        }

        code = krb5_init_creds_step(ctx->k5c, ctx->icc, &in, &out, &realm,
                                    &flags);
        if (code != 0) {
            if (cred->have_tgt) {
                /* We were trying to refresh; keep going with current creds. */
                ctx->state = IAKERB_TGS_REQ;
                krb5_clear_error_message(ctx->k5c);
            } else {
                goto cleanup;
            }
        } else if (!(flags & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE)) {
            krb5_init_creds_get_times(ctx->k5c, ctx->icc, &times);
            kg_cred_set_initial_refresh(ctx->k5c, cred, &times);
            cred->expire = times.endtime;

            krb5_init_creds_free(ctx->k5c, ctx->icc);
            ctx->icc = NULL;

            ctx->state = IAKERB_TGS_REQ;
        } else
            break;
        in = empty_data();
        /* Done with AS request; fall through to TGS request. */
    case IAKERB_TGS_REQ:
        if (ctx->tcc == NULL) {
            code = iakerb_tkt_creds_ctx(ctx, cred, name, time_req);
            if (code != 0)
                goto cleanup;
        }

        code = krb5_tkt_creds_step(ctx->k5c, ctx->tcc, &in, &out, &realm,
                                   &flags);
        if (code != 0)
            goto cleanup;
        if (!(flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE)) {
            krb5_tkt_creds_get_times(ctx->k5c, ctx->tcc, &times);
            cred->expire = times.endtime;

            krb5_tkt_creds_free(ctx->k5c, ctx->tcc);
            ctx->tcc = NULL;

            ctx->state = IAKERB_AP_REQ;
        } else
            break;
        /* Done with TGS request; fall through to AP request. */
    case IAKERB_AP_REQ:
        break;
    }

    if (out.length != 0) {
        assert(ctx->state != IAKERB_AP_REQ);

        code = iakerb_make_token(ctx, &realm, cookie, &out,
                                 (input_token == GSS_C_NO_BUFFER),
                                 output_token);
        if (code != 0)
            goto cleanup;

        /* Save the token for generating a future checksum */
        code = iakerb_save_token(ctx, output_token);
        if (code != 0)
            goto cleanup;

        ctx->count++;
    }

cleanup:
    if (code != 0)
        gss_release_buffer(&tmp, output_token);
    krb5_free_data(ctx->k5c, cookie);
    krb5_free_data_contents(ctx->k5c, &out);
    krb5_free_data_contents(ctx->k5c, &realm);

    return code;
}

/*
 * Determine the starting IAKERB state for a context. If we already
 * have a ticket, we may not need to do IAKERB at all.
 */
static krb5_error_code
iakerb_get_initial_state(iakerb_ctx_id_t ctx,
                         krb5_gss_cred_id_t cred,
                         krb5_gss_name_t target,
                         OM_uint32 time_req,
                         enum iakerb_state *state)
{
    krb5_creds in_creds, *out_creds = NULL;
    krb5_error_code code;

    memset(&in_creds, 0, sizeof(in_creds));

    in_creds.client = cred->name->princ;
    in_creds.server = target->princ;

    if (cred->name->ad_context != NULL) {
        code = krb5_authdata_export_authdata(ctx->k5c,
                                             cred->name->ad_context,
                                             AD_USAGE_TGS_REQ,
                                             &in_creds.authdata);
        if (code != 0)
            goto cleanup;
    }

    if (time_req != 0 && time_req != GSS_C_INDEFINITE) {
        krb5_timestamp now;

        code = krb5_timeofday(ctx->k5c, &now);
        if (code != 0)
            goto cleanup;

        in_creds.times.endtime = now + time_req;
    }

    /* Make an AS request if we have no creds or it's time to refresh them. */
    if (cred->expire == 0 || kg_cred_time_to_refresh(ctx->k5c, cred)) {
        *state = IAKERB_AS_REQ;
        code = 0;
        goto cleanup;
    }

    code = krb5_get_credentials(ctx->k5c, KRB5_GC_CACHED, cred->ccache,
                                &in_creds, &out_creds);
    if (code == KRB5_CC_NOTFOUND || code == KRB5_CC_NOT_KTYPE) {
        *state = cred->have_tgt ? IAKERB_TGS_REQ : IAKERB_AS_REQ;
        code = 0;
    } else if (code == 0) {
        *state = IAKERB_AP_REQ;
        krb5_free_creds(ctx->k5c, out_creds);
    }

cleanup:
    krb5_free_authdata(ctx->k5c, in_creds.authdata);

    return code;
}

/*
 * Allocate and initialise an IAKERB context
 */
static krb5_error_code
iakerb_alloc_context(iakerb_ctx_id_t *pctx)
{
    iakerb_ctx_id_t ctx;
    krb5_error_code code;

    *pctx = NULL;

    ctx = k5alloc(sizeof(*ctx), &code);
    if (ctx == NULL)
        goto cleanup;
    ctx->defcred = GSS_C_NO_CREDENTIAL;
    ctx->magic = KG_IAKERB_CONTEXT;
    ctx->state = IAKERB_AS_REQ;
    ctx->count = 0;

    code = krb5_gss_init_context(&ctx->k5c);
    if (code != 0)
        goto cleanup;

    *pctx = ctx;

cleanup:
    if (code != 0)
        iakerb_release_context(ctx);

    return code;
}

/*
 * Delete an IAKERB context. This can also accept Kerberos context
 * handles. The heuristic is similar to SPNEGO's delete_sec_context.
 */
OM_uint32 KRB5_CALLCONV
iakerb_gss_delete_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t output_token)
{
    OM_uint32 major_status = GSS_S_COMPLETE;

    if (output_token != GSS_C_NO_BUFFER) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    *minor_status = 0;

    if (*context_handle != GSS_C_NO_CONTEXT) {
        iakerb_ctx_id_t iakerb_ctx = (iakerb_ctx_id_t)*context_handle;

        if (iakerb_ctx->magic == KG_IAKERB_CONTEXT) {
            iakerb_release_context(iakerb_ctx);
            *context_handle = GSS_C_NO_CONTEXT;
        } else {
            assert(iakerb_ctx->magic == KG_CONTEXT);

            major_status = krb5_gss_delete_sec_context(minor_status,
                                                       context_handle,
                                                       output_token);
        }
    }

    return major_status;
}

static krb5_boolean
iakerb_is_iakerb_token(const gss_buffer_t token)
{
    krb5_error_code code;
    unsigned int bodysize = token->length;
    unsigned char *ptr = token->value;

    code = g_verify_token_header(gss_mech_iakerb,
                                 &bodysize, &ptr,
                                 IAKERB_TOK_PROXY,
                                 token->length, 0);

    return (code == 0);
}

static void
iakerb_make_exts(iakerb_ctx_id_t ctx, krb5_gss_ctx_ext_rec *exts)
{
    memset(exts, 0, sizeof(*exts));

    if (ctx->conv.length != 0)
        exts->iakerb.conv = &ctx->conv;
}

OM_uint32 KRB5_CALLCONV
iakerb_gss_accept_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
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
    OM_uint32 major_status = GSS_S_FAILURE;
    OM_uint32 code;
    iakerb_ctx_id_t ctx;
    int initialContextToken = (*context_handle == GSS_C_NO_CONTEXT);

    if (initialContextToken) {
        code = iakerb_alloc_context(&ctx);
        if (code != 0)
            goto cleanup;

    } else
        ctx = (iakerb_ctx_id_t)*context_handle;

    if (iakerb_is_iakerb_token(input_token)) {
        if (ctx->gssc != GSS_C_NO_CONTEXT) {
            /* We shouldn't get an IAKERB token now. */
            code = G_WRONG_TOKID;
            major_status = GSS_S_DEFECTIVE_TOKEN;
            goto cleanup;
        }
        code = iakerb_acceptor_step(ctx, initialContextToken,
                                    input_token, output_token);
        if (code == (OM_uint32)KRB5_BAD_MSIZE)
            major_status = GSS_S_DEFECTIVE_TOKEN;
        if (code != 0)
            goto cleanup;
        if (initialContextToken) {
            *context_handle = (gss_ctx_id_t)ctx;
            ctx = NULL;
        }
        if (src_name != NULL)
            *src_name = GSS_C_NO_NAME;
        if (mech_type != NULL)
            *mech_type = (gss_OID)gss_mech_iakerb;
        if (ret_flags != NULL)
            *ret_flags = 0;
        if (time_rec != NULL)
            *time_rec = 0;
        if (delegated_cred_handle != NULL)
            *delegated_cred_handle = GSS_C_NO_CREDENTIAL;
        major_status = GSS_S_CONTINUE_NEEDED;
    } else {
        krb5_gss_ctx_ext_rec exts;

        iakerb_make_exts(ctx, &exts);

        major_status = krb5_gss_accept_sec_context_ext(&code,
                                                       &ctx->gssc,
                                                       verifier_cred_handle,
                                                       input_token,
                                                       input_chan_bindings,
                                                       src_name,
                                                       NULL,
                                                       output_token,
                                                       ret_flags,
                                                       time_rec,
                                                       delegated_cred_handle,
                                                       &exts);
        if (major_status == GSS_S_COMPLETE) {
            *context_handle = ctx->gssc;
            ctx->gssc = NULL;
            iakerb_release_context(ctx);
        }
        if (mech_type != NULL)
            *mech_type = (gss_OID)gss_mech_krb5;
    }

cleanup:
    if (initialContextToken && GSS_ERROR(major_status)) {
        iakerb_release_context(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }

    *minor_status = code;
    return major_status;
}

OM_uint32 KRB5_CALLCONV
iakerb_gss_init_sec_context(OM_uint32 *minor_status,
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
    krb5_error_code code;
    iakerb_ctx_id_t ctx;
    krb5_gss_cred_id_t kcred;
    krb5_gss_name_t kname;
    krb5_boolean cred_locked = FALSE;
    int initialContextToken = (*context_handle == GSS_C_NO_CONTEXT);

    if (initialContextToken) {
        code = iakerb_alloc_context(&ctx);
        if (code != 0) {
            *minor_status = code;
            goto cleanup;
        }
        if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
            major_status = iakerb_gss_acquire_cred(minor_status, NULL,
                                                   GSS_C_INDEFINITE,
                                                   GSS_C_NULL_OID_SET,
                                                   GSS_C_INITIATE,
                                                   &ctx->defcred, NULL, NULL);
            if (GSS_ERROR(major_status))
                goto cleanup;
            claimant_cred_handle = ctx->defcred;
        }
    } else {
        ctx = (iakerb_ctx_id_t)*context_handle;
        if (claimant_cred_handle == GSS_C_NO_CREDENTIAL)
            claimant_cred_handle = ctx->defcred;
    }

    kname = (krb5_gss_name_t)target_name;

    major_status = kg_cred_resolve(minor_status, ctx->k5c,
                                   claimant_cred_handle, target_name);
    if (GSS_ERROR(major_status))
        goto cleanup;
    cred_locked = TRUE;
    kcred = (krb5_gss_cred_id_t)claimant_cred_handle;

    major_status = GSS_S_FAILURE;

    if (initialContextToken) {
        code = iakerb_get_initial_state(ctx, kcred, kname, time_req,
                                        &ctx->state);
        if (code != 0) {
            *minor_status = code;
            goto cleanup;
        }
        *context_handle = (gss_ctx_id_t)ctx;
    }

    if (ctx->state != IAKERB_AP_REQ) {
        /* We need to do IAKERB. */
        code = iakerb_initiator_step(ctx,
                                     kcred,
                                     kname,
                                     time_req,
                                     input_token,
                                     output_token);
        if (code == KRB5_BAD_MSIZE)
            major_status = GSS_S_DEFECTIVE_TOKEN;
        if (code != 0) {
            *minor_status = code;
            goto cleanup;
        }
    }

    if (ctx->state == IAKERB_AP_REQ) {
        krb5_gss_ctx_ext_rec exts;

        if (cred_locked) {
            k5_mutex_unlock(&kcred->lock);
            cred_locked = FALSE;
        }

        iakerb_make_exts(ctx, &exts);

        if (ctx->gssc == GSS_C_NO_CONTEXT)
            input_token = GSS_C_NO_BUFFER;

        /* IAKERB is finished, or we skipped to Kerberos directly. */
        major_status = krb5_gss_init_sec_context_ext(minor_status,
                                                     (gss_cred_id_t) kcred,
                                                     &ctx->gssc,
                                                     target_name,
                                                     (gss_OID)gss_mech_iakerb,
                                                     req_flags,
                                                     time_req,
                                                     input_chan_bindings,
                                                     input_token,
                                                     NULL,
                                                     output_token,
                                                     ret_flags,
                                                     time_rec,
                                                     &exts);
        if (major_status == GSS_S_COMPLETE) {
            *context_handle = ctx->gssc;
            ctx->gssc = GSS_C_NO_CONTEXT;
            iakerb_release_context(ctx);
        }
        if (actual_mech_type != NULL)
            *actual_mech_type = (gss_OID)gss_mech_krb5;
    } else {
        if (actual_mech_type != NULL)
            *actual_mech_type = (gss_OID)gss_mech_iakerb;
        if (ret_flags != NULL)
            *ret_flags = 0;
        if (time_rec != NULL)
            *time_rec = 0;
        major_status = GSS_S_CONTINUE_NEEDED;
    }

cleanup:
    if (cred_locked)
        k5_mutex_unlock(&kcred->lock);
    if (initialContextToken && GSS_ERROR(major_status)) {
        iakerb_release_context(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }

    return major_status;
}
