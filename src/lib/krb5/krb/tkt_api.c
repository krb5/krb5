/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/tkt_api.c */
/*
 * Copyright 1990, 2008, 2010 by the Massachusetts Institute of Technology.
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

/*
 * Attempts to use the credentials cache or TGS exchange to get an additional
 * ticket for the client identified by in_creds->client, the server identified
 * by in_creds->server, with options options, expiration date specified in
 * in_creds->times.endtime (0 means as long as possible), session key type
 * specified in in_creds->keyblock.enctype (if non-zero)
 */

#include "k5-int.h"
#include "int-proto.h"
#include "os-proto.h"

enum state {
    STATE_INIT,
    STATE_GET_CREDS,
    STATE_COMPLETE
};

enum gc_type {
    GC_TGS,
    GC_S4U2S,
    GC_S4U2P
};

struct _krb5_tkt_creds_context {
    enum state state;

    k5_tkt_creds_in_data in_data;
    krb5_creds *reply_creds;

    /* Underlying get_creds context */
    union {
        krb5_gc_creds_context gc_ctx;
        krb5_s4u2s_creds_context s4u2s_ctx;
        krb5_s4u2p_creds_context s4u2p_ctx;
    };
    enum gc_type gc_type;
};

static krb5_error_code
tkt_creds_set_gc_type(krb5_context context, krb5_tkt_creds_context ctx)
{
    if (ctx->in_data->impersonate != NULL ||
        ctx->in_data->impersonate_cert.length != 0) {
        if (ctx->in_data->req_options & KRB5_GC_CONSTRAINED_DELEGATION)
            return EINVAL;
        ctx->gc_type = GC_S4U2S;
    } else if (ctx->in_data->req_options & KRB5_GC_CONSTRAINED_DELEGATION) {
        if (ctx->in_data->in_creds->second_ticket.length == 0)
            return EINVAL;
        ctx->gc_type = GC_S4U2P;
    } else {
        ctx->gc_type = GC_TGS;
    }

    return 0;
}

/***** API functions *****/

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_init(krb5_context context, krb5_ccache ccache,
                    krb5_creds *in_creds, krb5_flags options,
                    krb5_tkt_creds_context *pctx)
{
    krb5_error_code code;
    krb5_tkt_creds_context ctx;

    *pctx = NULL;

    ctx = k5alloc(sizeof(*ctx), &code);
    if (ctx == NULL)
        goto cleanup;

    ctx->state = STATE_INIT;

    ctx->in_data = k5alloc(sizeof(*ctx->in_data), &code);
    if (ctx->in_data == NULL)
        goto cleanup;

    ctx->in_data->req_options = options;
    ctx->in_data->req_kdcopt = 0;
    if (options & KRB5_GC_CANONICALIZE)
        ctx->in_data->req_kdcopt |= KDC_OPT_CANONICALIZE;
    if (options & KRB5_GC_FORWARDABLE)
        ctx->in_data->req_kdcopt |= KDC_OPT_FORWARDABLE;
    if (options & KRB5_GC_NO_TRANSIT_CHECK)
        ctx->in_data->req_kdcopt |= KDC_OPT_DISABLE_TRANSITED_CHECK;

    code = krb5_copy_creds(context, in_creds, &ctx->in_data->in_creds);
    if (code != 0)
        goto cleanup;

    code = krb5_copy_principal(context, ctx->in_data->in_creds->server,
                               &ctx->in_data->req_server);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_dup(context, ccache, &ctx->in_data->ccache);
    if (code != 0)
        goto cleanup;

    code = krb5_copy_authdata(context, in_creds->authdata,
                              &ctx->in_data->authdata);
    if (code != 0)
        goto cleanup;

    *pctx = ctx;
    ctx = NULL;

cleanup:
    krb5_tkt_creds_free(context, ctx);
    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_step(krb5_context context, krb5_tkt_creds_context ctx,
                    krb5_data *in, krb5_data *out, krb5_data *realm,
                    unsigned int *flags)
{
    krb5_error_code code;

    /* We should not get called after completion. */
    if (ctx->state == STATE_COMPLETE)
        return EINVAL;

    if (ctx->state == STATE_INIT) {
        code = tkt_creds_set_gc_type(context, ctx);
        if (code != 0)
            return code;

        if (ctx->gc_type == GC_TGS)
            code = k5_gc_tgs_init(context, ctx->in_data, &ctx->gc_ctx);
        else if (ctx->gc_type == GC_S4U2S)
            code = k5_gc_s4u2s_init(context, ctx->in_data, &ctx->s4u2s_ctx);
        else if (ctx->gc_type == GC_S4U2P)
            code = k5_gc_s4u2p_init(context, ctx->in_data, &ctx->s4u2p_ctx);
        else
            code = EINVAL;

        if (code != 0)
            return code;

        /* Relinquish ownership of in_data. */
        ctx->in_data = NULL;

        ctx->state = STATE_GET_CREDS;
    }

    *out = empty_data();
    *realm = empty_data();
    *flags = 0;

    if (ctx->gc_type == GC_TGS)
        code = k5_gc_tgs_step(context, ctx->gc_ctx, in, out, realm, flags,
                              &ctx->reply_creds);
    else if (ctx->gc_type == GC_S4U2S)
        code = k5_gc_s4u2s_step(context, ctx->s4u2s_ctx, in, out, realm, flags,
                                &ctx->reply_creds);
    else if (ctx->gc_type == GC_S4U2P)
        code = k5_gc_s4u2p_step(context, ctx->s4u2p_ctx, in, out, realm, flags,
                                &ctx->reply_creds);
    else
        code = EINVAL;

    if (code != 0)
        return code;

    if (!(*flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE))
        ctx->state = STATE_COMPLETE;

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_creds(krb5_context context, krb5_tkt_creds_context ctx,
                         krb5_creds *creds)
{
    if (ctx->state != STATE_COMPLETE)
        return KRB5_NO_TKT_SUPPLIED;
    return k5_copy_creds_contents(context, ctx->reply_creds, creds);
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_times(krb5_context context, krb5_tkt_creds_context ctx,
                         krb5_ticket_times *times)
{
    if (ctx->state != STATE_COMPLETE)
        return KRB5_NO_TKT_SUPPLIED;
    *times = ctx->reply_creds->times;
    return 0;
}

void k5_tkt_creds_in_data_free(krb5_context context,
                               k5_tkt_creds_in_data in_data)
{
    if (in_data == NULL)
        return;
    krb5_free_creds(context, in_data->in_creds);
    krb5_free_principal(context, in_data->req_server);
    krb5_cc_close(context, in_data->ccache);
    krb5_free_authdata(context, in_data->authdata);
    krb5_free_principal(context, in_data->impersonate);
    krb5_free_data_contents(context, &in_data->impersonate_cert);
    free(in_data);
}

void KRB5_CALLCONV
krb5_tkt_creds_free(krb5_context context, krb5_tkt_creds_context ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->gc_type == GC_TGS)
        k5_gc_tgs_free(context, ctx->gc_ctx);
    else if (ctx->gc_type == GC_S4U2S)
        k5_gc_s4u2s_free(context, ctx->s4u2s_ctx);
    else if (ctx->gc_type == GC_S4U2P)
        k5_gc_s4u2p_free(context, ctx->s4u2p_ctx);
    k5_tkt_creds_in_data_free(context, ctx->in_data);
    krb5_free_creds(context, ctx->reply_creds);
    free(ctx);
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_set_impersonate(krb5_context context,
                               krb5_tkt_creds_context ctx,
                               krb5_principal impersonate)
{
    krb5_free_principal(context, ctx->in_data->impersonate);
    ctx->in_data->impersonate = NULL;
    if (impersonate == NULL)
        return 0;
    return krb5_copy_principal(context, impersonate,
                               &ctx->in_data->impersonate);
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_set_impersonate_cert(krb5_context context,
                                    krb5_tkt_creds_context ctx,
                                    krb5_data *cert)
{
    krb5_free_data_contents(context, &ctx->in_data->impersonate_cert);
    ctx->in_data->impersonate_cert.length = 0;
    if (cert == NULL)
        return 0;
    return krb5int_copy_data_contents(context, cert,
                                      &ctx->in_data->impersonate_cert);
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    krb5_data request = empty_data(), reply = empty_data();
    krb5_data realm = empty_data();
    unsigned int flags = 0;
    int tcp_only = 0, use_master;

    for (;;) {
        /* Get the next request and realm.  Turn on TCP if necessary. */
        code = krb5_tkt_creds_step(context, ctx, &reply, &request, &realm,
                                   &flags);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG && !tcp_only) {
            TRACE_TKT_CREDS_RETRY_TCP(context);
            tcp_only = 1;
        } else if (code != 0 || !(flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE))
            break;
        krb5_free_data_contents(context, &reply);

        /* Send it to a KDC for the appropriate realm. */
        use_master = 0;
        code = krb5_sendto_kdc(context, &request, &realm,
                               &reply, &use_master, tcp_only);
        if (code != 0)
            break;

        krb5_free_data_contents(context, &request);
        krb5_free_data_contents(context, &realm);
    }

    krb5_free_data_contents(context, &request);
    krb5_free_data_contents(context, &reply);
    krb5_free_data_contents(context, &realm);
    return code;
}
