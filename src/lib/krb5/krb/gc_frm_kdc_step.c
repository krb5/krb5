/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (c) 1990-2009 by the Massachusetts Institute of Technology.
 * Copyright (c) 1994 CyberSAFE Corporation
 * Copyright (c) 1993 Open Computing Security Group
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
 * Neither M.I.T., the Open Computing Security Group, nor
 * CyberSAFE Corporation make any representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * krb5_tkt_creds_step() and related functions:
 *
 * Get credentials from some KDC somewhere, possibly accumulating TGTs
 * along the way. This is asychronous version of the API in gc_frm_kdc.c.
 * It requires that the KDC support cross-realm referrals.
 */

#include "k5-int.h"
#include <stdio.h>
#include "int-proto.h"

#define KRB5_TKT_CREDS_STEP_FLAG_COMPLETE       0x1
#define KRB5_TKT_CREDS_STEP_FLAG_CTX_KTYPES     0x2

struct _krb5_tkt_creds_context {
    krb5_ccache ccache;
    krb5_creds in_cred;
    krb5_principal client;
    krb5_principal server;
    krb5_principal req_server;
    int req_kdcopt;

    unsigned int flags;
    krb5_creds cc_tgt;
    krb5_creds *tgtptr;
    unsigned int referral_count;
    krb5_creds *referral_tgts[KRB5_REFERRAL_MAXHOPS];
    krb5_boolean default_use_conf_ktypes;
    krb5_timestamp timestamp;
    krb5_int32 nonce;
    int kdcopt;
    krb5_keyblock *subkey;
    krb5_data encoded_previous_request;

    krb5_creds *out_cred;
};

/* Convert ticket flags to necessary KDC options */
#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

static krb5_error_code
tkt_make_tgs_request(krb5_context context,
                     krb5_tkt_creds_context ctx,
                     krb5_creds *tgt,
                     krb5_creds *in_cred,
                     krb5_data *req)
{
    krb5_error_code code;

    /* These flags are always included */
    ctx->kdcopt |= FLAGS2OPTS(tgt->ticket_flags);

    if ((ctx->kdcopt & KDC_OPT_ENC_TKT_IN_SKEY) == 0)
        in_cred->is_skey = FALSE;

    if (!krb5_c_valid_enctype(tgt->keyblock.enctype))
        return KRB5_PROG_ETYPE_NOSUPP;

    code = krb5int_make_tgs_request(context, tgt, ctx->kdcopt,
                                   tgt->addresses, NULL,
                                   in_cred, NULL, NULL, req,
                                   &ctx->timestamp, &ctx->nonce, &ctx->subkey);
    return code;
}

static krb5_error_code
tkt_process_tgs_reply(krb5_context context,
                      krb5_tkt_creds_context ctx,
                      krb5_data *rep,
                      krb5_creds *tgt,
                      krb5_creds *in_cred,
                      krb5_creds **out_cred)
{
    krb5_error_code code;

    code = krb5int_process_tgs_reply(context,
                                    rep,
                                    tgt,
                                    ctx->kdcopt,
                                    tgt->addresses,
                                    NULL,
                                    in_cred,
                                    ctx->timestamp,
                                    ctx->nonce,
                                    ctx->subkey,
                                    NULL,
                                    NULL,
                                    out_cred);

    return code;
}

/*
 * Asynchronous API
 */
krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_init(krb5_context context,
                    krb5_ccache ccache,
                    krb5_creds *creds,
                    int kdcopt,
                    krb5_tkt_creds_context *pctx)
{
    krb5_error_code code;
    krb5_tkt_creds_context ctx = NULL;
    krb5_creds tgtq;
    krb5_flags flags = KRB5_TC_MATCH_SRV_NAMEONLY | KRB5_TC_SUPPORTED_KTYPES;

    memset(&tgtq, 0, sizeof(tgtq));

    ctx = k5alloc(sizeof(*ctx), &code);
    if (code != 0)
        goto cleanup;

    code = krb5int_copy_creds_contents(context, creds, &ctx->in_cred);
    if (code != 0)
        goto cleanup;

    ctx->ccache = ccache; /* XXX */

    ctx->req_kdcopt = kdcopt;
    ctx->default_use_conf_ktypes = context->use_conf_ktypes;
    ctx->client = ctx->in_cred.client;
    ctx->server = ctx->in_cred.server;

    code = krb5_copy_principal(context, ctx->server, &ctx->req_server);
    if (code != 0)
        goto cleanup;

    code = krb5int_tgt_mcred(context, ctx->client, ctx->client,
                             ctx->client, &tgtq);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_retrieve_cred(context, ctx->ccache, flags,
                                 &tgtq, &ctx->cc_tgt);
    if (code != 0)
        goto cleanup;

    ctx->tgtptr = &ctx->cc_tgt;

    *pctx = ctx;

cleanup:
    if (code != 0)
        krb5_tkt_creds_free(context, ctx);
    krb5_free_cred_contents(context, &tgtq);

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_creds(krb5_context context,
                         krb5_tkt_creds_context ctx,
                         krb5_creds *creds)
{
    krb5_error_code code;

    if (ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE)
        code = krb5int_copy_creds_contents(context, ctx->out_cred, creds);
    else
        code = KRB5_NO_TKT_SUPPLIED;

    return code;
}

/*
 * Store credentials in credentials cache. If ccache is NULL, the
 * credentials cache associated with the context is used. This can
 * be called on an incomplete context, in which case the referral
 * TGT only will be stored.
 */
krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_store_creds(krb5_context context,
                           krb5_tkt_creds_context ctx,
                           krb5_ccache ccache)
{
    krb5_error_code code;

    if (ccache == NULL)
        ccache = ctx->ccache;

    /* Only store the referral from our local KDC */
    if (ctx->referral_tgts[0] != NULL)
        krb5_cc_store_cred(context, ccache, ctx->referral_tgts[0]);

    if (ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE)
        code = krb5_cc_store_cred(context, ccache, ctx->out_cred);
    else
        code = KRB5_NO_TKT_SUPPLIED;

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_times(krb5_context context,
                         krb5_tkt_creds_context ctx,
                         krb5_ticket_times *times)
{
    if ((ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE) == 0)
        return KRB5_NO_TKT_SUPPLIED;

    *times = ctx->out_cred->times;

    return 0;
}

void KRB5_CALLCONV
krb5_tkt_creds_free(krb5_context context,
                    krb5_tkt_creds_context ctx)
{
    int i;

    if (ctx == NULL)
        return;

    krb5_free_principal(context, ctx->req_server);
    krb5_free_cred_contents(context, &ctx->in_cred);
    krb5_free_creds(context, ctx->out_cred);
    krb5_free_data_contents(context, &ctx->encoded_previous_request);
    krb5_free_keyblock(context, ctx->subkey);

    /* Free referral TGTs list. */
    for (i = 0; i < KRB5_REFERRAL_MAXHOPS; i++) {
        if (ctx->referral_tgts[i] != NULL) {
            krb5_free_creds(context, ctx->referral_tgts[i]);
            ctx->referral_tgts[i] = NULL;
        }
    }

    free(ctx);
}

static krb5_error_code
tkt_creds_step_request(krb5_context context,
                       krb5_tkt_creds_context ctx,
                       krb5_data *req)
{
    krb5_error_code code;

    if (ctx->referral_count >= KRB5_REFERRAL_MAXHOPS)
        return KRB5_KDC_UNREACH;

    assert(ctx->tgtptr != NULL);

    /* Copy krbtgt realm to server principal */
    krb5_free_data_contents(context, &ctx->server->realm);
    code = krb5int_copy_data_contents(context,
                                      &ctx->tgtptr->server->data[1],
                                      &ctx->server->realm);
    if (code != 0)
        return code;

    ctx->kdcopt = ctx->req_kdcopt | KDC_OPT_CANONICALIZE;

    if (ctx->in_cred.second_ticket.length != 0 &&
        (ctx->kdcopt & KDC_OPT_CNAME_IN_ADDL_TKT) == 0) {
        ctx->kdcopt |= KDC_OPT_ENC_TKT_IN_SKEY;
    }

    if ((ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_CTX_KTYPES) == 0)
        context->use_conf_ktypes = 1;

    code = tkt_make_tgs_request(context, ctx, ctx->tgtptr,
                                &ctx->in_cred, req);

    context->use_conf_ktypes = ctx->default_use_conf_ktypes;

    return code;
}

static krb5_error_code
tkt_creds_step_reply(krb5_context context,
                     krb5_tkt_creds_context ctx,
                     krb5_data *rep)
{
    krb5_error_code code;
    unsigned int i;
    krb5_boolean got_tkt = FALSE;

    krb5_free_creds(context, ctx->out_cred);
    ctx->out_cred = NULL;

    code = tkt_process_tgs_reply(context, ctx, rep, ctx->tgtptr,
                                 &ctx->in_cred, &ctx->out_cred);
    if (code != 0)
        goto cleanup;

    /*
     * Referral request succeeded; let's see what it is
     */
    if (krb5_principal_compare(context, ctx->server, ctx->out_cred->server)) {
        /*
         * Check if the return enctype is one that we requested if
         * needed.
         */
        if (ctx->default_use_conf_ktypes || context->tgs_etypes == NULL)
            got_tkt = TRUE;
        else
            for (i = 0; context->tgs_etypes[i] != ENCTYPE_NULL; i++) {
                if (ctx->out_cred->keyblock.enctype == context->tgs_etypes[i]) {
                    /* Found an allowable etype, so we're done */
                    got_tkt = TRUE;
                    break;
                }
            }

        if (got_tkt == FALSE)
            ctx->flags |= KRB5_TKT_CREDS_STEP_FLAG_CTX_KTYPES; /* try again */
    } else if (IS_TGS_PRINC(context, ctx->out_cred->server)) {
        krb5_data *r1, *r2;

        if (ctx->referral_count == 0)
            r1 = &ctx->tgtptr->server->data[1];
        else
            r1 = &ctx->referral_tgts[ctx->referral_count - 1]->server->data[1];

        r2 = &ctx->out_cred->server->data[1];
        if (data_eq(*r1, *r2)) {
            code = KRB5_KDC_UNREACH;
            goto cleanup;
        }

        /* Check for referral routing loop. */
        for (i = 0; i < ctx->referral_count; i++) {
            if (krb5_principal_compare(context,
                                       ctx->out_cred->server,
                                       ctx->referral_tgts[i]->server)) {
                code = KRB5_KDC_UNREACH;
                goto cleanup;
            }
        }
        /* Point current tgt pointer at newly-received TGT. */
        ctx->tgtptr = ctx->out_cred;

        /* avoid multiple copies of authdata */
        ctx->out_cred->authdata = ctx->in_cred.authdata;
        ctx->in_cred.authdata = NULL;

        ctx->referral_tgts[ctx->referral_count++] = ctx->out_cred;
        ctx->out_cred = NULL;
    } else {
        code = KRB5KRB_AP_ERR_NO_TGT;
    }

    assert(ctx->tgtptr == NULL || code == 0);

    if (code == 0 && got_tkt == TRUE) {
        krb5_free_principal(context, ctx->out_cred->server);
        ctx->out_cred->server = ctx->req_server;
        ctx->req_server = NULL;

        if (ctx->in_cred.authdata != NULL) {
            code = krb5_copy_authdata(context, ctx->in_cred.authdata,
                                      &ctx->out_cred->authdata);
        }

        ctx->flags |= KRB5_TKT_CREDS_STEP_FLAG_COMPLETE;
    }

cleanup:
    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_step(krb5_context context,
                    krb5_tkt_creds_context ctx,
                    krb5_data *in,
                    krb5_data *out,
                    krb5_data *realm,
                    unsigned int *flags)
{
    krb5_error_code code, code2;

    *flags = 0;

    out->data = NULL;
    out->length = 0;

    realm->data = NULL;
    realm->length = 0;

    if (ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE)
        goto cleanup;

    if (in != NULL && in->length != 0) {
        code = tkt_creds_step_reply(context, ctx, in);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG) {
            code2 = krb5int_copy_data_contents(context,
                                               &ctx->encoded_previous_request,
                                               out);
            if (code2 != 0)
                code = code2;
            goto copy_realm;
        }
        if (code != 0 || (ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE))
            goto cleanup;
    }

    code = tkt_creds_step_request(context, ctx, out);
    if (code != 0)
        goto cleanup;

    assert(out->length != 0);

    code = krb5int_copy_data_contents(context,
                                      out,
                                      &ctx->encoded_previous_request);
    if (code != 0)
        goto cleanup;

copy_realm:
    code2 = krb5int_copy_data_contents(context, &ctx->server->realm, realm);
    if (code2 != 0) {
        code = code2;
        goto cleanup;
    }

cleanup:
    *flags = (ctx->flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE);

    return code;
}

