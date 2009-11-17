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
 * krb5_get_cred_from_kdc() and related functions:
 *
 * Get credentials from some KDC somewhere, possibly accumulating TGTs
 * along the way.
 */

#define DEBUG_GC_FRM_KDC 1
#define DEBUG_REFERRALS 1

#include "k5-int.h"
#include <stdio.h>
#include "int-proto.h"

/*
 * Asynchronous API request/response state
 */
struct _krb5_tkt_creds_context {
    krb5_ccache ccache;
    krb5_creds in_cred;
    krb5_creds tgtq;
    krb5_data *realm;
    krb5_principal client;
    krb5_principal server;
    krb5_principal req_server;
    krb5_creds *out_cred;
    krb5_creds **tgts;
    int kdcopt;
    unsigned int referral_count;
    krb5_creds cc_tgt;
    krb5_creds *tgtptr;
    krb5_creds *referral_tgts[KRB5_REFERRAL_MAXHOPS];
    krb5_boolean use_conf_ktypes;
    krb5_timestamp timestamp;
    krb5_keyblock *subkey;
    krb5_data encoded_previous_request;
    int is_referral_realm;
    int complete;
};

#ifdef DEBUG_REFERRALS

#define DPRINTF(x) printf x
#define DFPRINTF(x) fprintf x
#define DUMP_PRINC(x, y) krb5int_dbgref_dump_principal((x), (y))

void
krb5int_dbgref_dump_principal(char *msg, krb5_principal princ)
{
    krb5_context context = NULL;
    krb5_error_code code;
    char *s = NULL;

    code = krb5_init_context(&context);
    if (code != 0)
        goto cleanup;

    code = krb5_unparse_name(context, princ, &s);
    if (code != 0)
        goto cleanup;

    fprintf(stderr, "%s: %s\n", msg, s);

cleanup:
    krb5_free_unparsed_name(context, s);
    krb5_free_context(context);
}

#else

#define DPRINTF(x)
#define DFPRINTF(x)
#define DUMP_PRINC(x, y)

#endif

/* Convert ticket flags to necessary KDC options */
#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

/*
 * Flags for ccache lookups of cross-realm TGTs.
 *
 * A cross-realm TGT may be issued by some other intermediate realm's
 * KDC, so we use KRB5_TC_MATCH_SRV_NAMEONLY.
 */
#define RETR_FLAGS (KRB5_TC_MATCH_SRV_NAMEONLY | KRB5_TC_SUPPORTED_KTYPES)

/*
 * Prototypes of helper functions
 */
static krb5_error_code tgt_mcred(krb5_context, krb5_principal,
                                 krb5_principal, krb5_principal, krb5_creds *);

/*
 * tkt_make_tgs_request()
 *
 * wrapper around krb5_make_tgs_request() that updates realm and
 * performs some additional validation
 */
static krb5_error_code
tkt_make_tgs_request(krb5_context context,
                     krb5_tkt_creds_context ctx,
                     krb5_creds *tgt,
                     krb5_flags kdcopt,
                     krb5_creds *in_cred,
                     krb5_data *req)
{
    krb5_error_code code;

    assert(tgt != NULL);

    assert(req != NULL);
    assert(req->length == 0);
    assert(req->data == NULL);

    assert(in_cred != NULL);
    assert(in_cred->server != NULL);

    ctx->realm = &in_cred->server->realm;

    /* These flags are always included */
    kdcopt |= FLAGS2OPTS(tgt->ticket_flags);

    if ((kdcopt & KDC_OPT_ENC_TKT_IN_SKEY) == 0)
        in_cred->is_skey = FALSE;

    if (!krb5_c_valid_enctype(tgt->keyblock.enctype))
        return KRB5_PROG_ETYPE_NOSUPP;

    code = krb5_make_tgs_request(context, tgt, kdcopt,
                                 tgt->addresses, NULL,
                                 in_cred, NULL, NULL,
                                 req, &ctx->timestamp, &ctx->subkey);
    return code;
}

/*
 * tkt_process_tgs_reply()
 *
 * wrapper around krb5_process_tgs_reply() that uses context
 * information and performs some additional validation
 */
static krb5_error_code
tkt_process_tgs_reply(krb5_context context,
                      krb5_tkt_creds_context ctx,
                      krb5_data *rep,
                      krb5_creds *tgt,
                      krb5_flags kdcopt,
                      krb5_creds *in_cred,
                      krb5_creds **out_cred)
{
    krb5_error_code code;

    /* These flags are always included */
    kdcopt |= FLAGS2OPTS(tgt->ticket_flags);

    if ((kdcopt & KDC_OPT_ENC_TKT_IN_SKEY) == 0)
        in_cred->is_skey = FALSE;

    code = krb5_process_tgs_reply(context,
                                  rep,
                                  tgt,
                                  kdcopt,
                                  tgt->addresses,
                                  NULL,
                                  in_cred,
                                  ctx->timestamp,
                                  ctx->subkey,
                                  NULL,
                                  NULL,
                                  out_cred);

#ifdef DEBUG_GC_FRM_KDC
    if (code != 0)
        fprintf(stderr, "tkt_process_tgs_reply: %s\n",
                krb5_get_error_message(context, code));
#endif

    return code;
}

/*
 * tgt_mcred()
 *
 * Return MCREDS for use as a match criterion.
 *
 * Resulting credential has CLIENT as the client principal, and
 * krbtgt/realm_of(DST)@realm_of(SRC) as the server principal.  Zeroes
 * MCREDS first, does not allocate MCREDS, and cleans MCREDS on
 * failure.  The peculiar ordering of DST and SRC args is for
 * consistency with krb5_tgtname().
 */
static krb5_error_code
tgt_mcred(krb5_context context, krb5_principal client,
          krb5_principal dst, krb5_principal src,
          krb5_creds *mcreds)
{
    krb5_error_code retval;

    memset(mcreds, 0, sizeof(*mcreds));

    retval = krb5_copy_principal(context, client, &mcreds->client);
    if (retval != 0)
        goto cleanup;

    retval = krb5_tgtname(context, krb5_princ_realm(context, dst),
                          krb5_princ_realm(context, src), &mcreds->server);
    if (retval != 0)
        goto cleanup;

cleanup:
    if (retval != 0)
        krb5_free_cred_contents(context, mcreds);

    return retval;
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

    assert(creds->client != NULL);
    assert(creds->server != NULL);

    ctx = k5alloc(sizeof(*ctx), &code);
    if (code != 0)
        goto cleanup;

    code = krb5int_copy_creds_contents(context, creds, &ctx->in_cred);
    if (code != 0)
        goto cleanup;

    ctx->ccache = ccache; /* XXX */

    ctx->use_conf_ktypes = context->use_conf_ktypes;
    ctx->client = ctx->in_cred.client;
    ctx->server = ctx->in_cred.server;

    code = krb5_copy_principal(context, ctx->server, &ctx->req_server);
    if (code != 0)
        goto cleanup;

    code = tgt_mcred(context, ctx->client, ctx->client,
                     ctx->client, &ctx->tgtq);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_retrieve_cred(context, ctx->ccache, RETR_FLAGS,
                                 &ctx->tgtq, &ctx->cc_tgt);
    if (code != 0)
        goto cleanup;

    ctx->tgtptr = &ctx->cc_tgt;
    krb5_free_cred_contents(context, &ctx->tgtq);

    /* The rest must be done by krb5_tkt_creds_step() */
    *pctx = ctx;

cleanup:
    if (code != 0)
        krb5_tkt_creds_free(context, ctx);

    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_creds(krb5_context context,
                         krb5_tkt_creds_context ctx,
                         krb5_creds *creds)
{
    if (ctx->complete == 0)
        return EINVAL;

    return krb5int_copy_creds_contents(context, ctx->out_cred, creds);
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
    krb5_free_cred_contents(context, &ctx->tgtq);
    krb5_free_creds(context, ctx->out_cred);
    krb5_free_tgt_creds(context, ctx->tgts);
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

/*
 * Determine KDC options to use based on context options
 */
static krb5_flags
tkt_creds_kdcopt(krb5_tkt_creds_context ctx)
{
    krb5_flags kdcopt = ctx->kdcopt;

    kdcopt |= KDC_OPT_CANONICALIZE;

    if (ctx->in_cred.second_ticket.length != 0 &&
        (kdcopt & KDC_OPT_CNAME_IN_ADDL_TKT) == 0) {
        kdcopt |= KDC_OPT_ENC_TKT_IN_SKEY;
    }

    return kdcopt;
}

static krb5_error_code
tkt_creds_request_referral_tgt(krb5_context context,
                               krb5_tkt_creds_context ctx,
                               krb5_data *req)
{
    krb5_error_code code;

    /*
     * Try requesting a service ticket from our local KDC with referrals
     * turned on.  If the first referral succeeds, follow a referral-only
     * path, otherwise fall back to old-style assumptions.
     */
    /*
     * Save TGTPTR because we rewrite it in the referral loop, and
     * we might need to explicitly free it later.
     */
    if (ctx->referral_count >= KRB5_REFERRAL_MAXHOPS) {
        code = KRB5_GET_IN_TKT_LOOP; /* XXX */
        goto cleanup;
    }

    assert(ctx->tgtptr);

    /* Copy krbtgt realm to server principal */
    krb5_free_data_contents(context, &ctx->server->realm);
    code = krb5int_copy_data_contents(context,
                                      &ctx->tgtptr->server->data[1],
                                      &ctx->server->realm);
    if (code != 0)
        goto cleanup;

    code = tkt_make_tgs_request(context, ctx, ctx->tgtptr,
                                tkt_creds_kdcopt(ctx),
                                &ctx->in_cred, req);
    if (code != 0)
        goto cleanup;

cleanup:
    return code;
}

static krb5_error_code
tkt_creds_complete(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code = 0;

    assert(ctx->out_cred);

    /*
     * Deal with ccache TGT management: If tgts has been set from
     * initial non-referral TGT discovery, leave it alone.  Otherwise, if
     * referral_tgts[0] exists return it as the only entry in tgts.
     * (Further referrals are never cached, only the referral from the
     * local KDC.)  This is part of cleanup because useful received TGTs
     * should be cached even if the main request resulted in failure.
     */
    if (ctx->tgts == NULL && ctx->referral_tgts[0] != NULL) {
        /* Allocate returnable TGT list. */
        ctx->tgts = k5alloc(2 * sizeof (krb5_creds *), &code);
        if (code != 0)
            goto cleanup;

        code = krb5_copy_creds(context, ctx->referral_tgts[0], &ctx->tgts[0]);
        if (code != 0)
            goto cleanup;
    }

    DUMP_PRINC("tkt_creds_complete: final server after reversion", ctx->server);

    krb5_free_principal(context, ctx->out_cred->server);
    ctx->out_cred->server = ctx->req_server;
    ctx->req_server = NULL;

    assert(ctx->out_cred->authdata == NULL);
    code = krb5_copy_authdata(context, ctx->in_cred.authdata,
                              &ctx->out_cred->authdata);
    if (code != 0)
        goto cleanup;

    ctx->complete = 1;

cleanup:
    return code;
}


static krb5_error_code
tkt_creds_reply_referral_tgt(krb5_context context,
                             krb5_tkt_creds_context ctx,
                             krb5_data *rep)
{
    krb5_error_code code;
    unsigned int i;

    assert(ctx->subkey);

    code = tkt_process_tgs_reply(context, ctx, rep, ctx->tgtptr,
                                 tkt_creds_kdcopt(ctx), &ctx->in_cred,
                                 &ctx->out_cred);
    if (code != 0)
        goto cleanup;

    /*
     * Referral request succeeded; let's see what it is
     */
    if (krb5_principal_compare(context, ctx->server, ctx->out_cred->server)) {
        DPRINTF(("gc_from_kdc: request generated ticket "
                 "for requested server principal\n"));
        DUMP_PRINC("gc_from_kdc final referred reply",
                   ctx->server);
        /*
         * Check if the return enctype is one that we requested if
         * needed.
         */
        if (ctx->use_conf_ktypes || !context->tgs_etypes) {
            code = tkt_creds_complete(context, ctx);
            goto cleanup;
        }
        for (i = 0; context->tgs_etypes[i]; i++) {
            if (ctx->out_cred->keyblock.enctype == context->tgs_etypes[i]) {
                /* Found an allowable etype, so we're done */
                code = tkt_creds_complete(context, ctx);
                goto cleanup;
            }
        }
        context->use_conf_ktypes = ctx->use_conf_ktypes;
    } else if (IS_TGS_PRINC(context, ctx->out_cred->server)) {
        krb5_data *r1, *r2;

        DPRINTF(("gc_from_kdc: request generated referral tgt\n"));
        DUMP_PRINC("gc_from_kdc credential received",
                   ctx->out_cred->server);

        assert(ctx->referral_count < KRB5_REFERRAL_MAXHOPS);
        if (ctx->referral_count == 0) {
            assert(ctx->tgtptr->server != NULL);
            r1 = &ctx->tgtptr->server->data[1];
        } else {
            assert(ctx->referral_tgts[ctx->referral_count - 1] != NULL);
            r1 = &ctx->referral_tgts[ctx->referral_count - 1]->server->data[1];
        }

        r2 = &ctx->out_cred->server->data[1];
        if (data_eq(*r1, *r2)) {
            DPRINTF(("gc_from_kdc: referred back to "
                     "previous realm; fall back\n"));
            krb5_free_creds(context, ctx->out_cred);
            ctx->out_cred = NULL;
            goto cleanup;
        }
        /* Check for referral routing loop. */
        for (i = 0; i < ctx->referral_count; i++) {
            if (krb5_principal_compare(context,
                                       ctx->out_cred->server,
                                       ctx->referral_tgts[i]->server)) {
                DFPRINTF((stderr,
                          "krb5_get_cred_from_kdc_opt: "
                          "referral routing loop - "
                          "got referral back to hop #%d\n", i));
                code = KRB5_KDC_UNREACH;
                goto cleanup;
            }
        }
        /* Point current tgt pointer at newly-received TGT. */
        ctx->tgtptr = ctx->out_cred;

        /* avoid copying authdata multiple times */
        ctx->out_cred->authdata = ctx->in_cred.authdata;
        ctx->in_cred.authdata = NULL;

        /* Save pointer to tgt in referral_tgts */
        ctx->referral_tgts[ctx->referral_count++] = ctx->out_cred;
        ctx->out_cred = NULL;

        /* Future work: rewrite SPN in padata */
    } else {
        code = KRB5KRB_AP_ERR_NO_TGT;
    }

cleanup:
    return code;
}

static krb5_error_code
tkt_creds_step_request(krb5_context context,
                       krb5_tkt_creds_context ctx,
                       krb5_data *req)
{
    krb5_error_code code;

    context->use_conf_ktypes = 1;

    code = tkt_creds_request_referral_tgt(context, ctx, req);

    context->use_conf_ktypes = ctx->use_conf_ktypes;

    return code;
}

static krb5_error_code
tkt_creds_reply(krb5_context context,
                krb5_tkt_creds_context ctx,
                krb5_data *rep)
{
    krb5_error_code code;

    context->use_conf_ktypes = 1;

    krb5_free_creds(context, ctx->out_cred);
    ctx->out_cred = NULL;

    code = tkt_creds_reply_referral_tgt(context, ctx, rep);

    context->use_conf_ktypes = ctx->use_conf_ktypes;

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

    if (in != NULL && in->length != 0) {
        code = tkt_creds_reply(context, ctx, in);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG) {
            code2 = krb5int_copy_data_contents(context,
                                               &ctx->encoded_previous_request,
                                               out);
            if (code2 != 0)
                code = code2;
            goto copy_realm;
        }
        if (code != 0)
            goto cleanup;
    }

    if (ctx->complete) {
        *flags = 1;
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
    assert(ctx->realm && ctx->realm->length);

    code2 = krb5int_copy_data_contents(context, ctx->realm, realm);
    if (code2 != 0) {
        code = code2;
        goto cleanup;
    }

cleanup:
    return code;
}

