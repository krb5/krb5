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

#include "k5-int.h"
#include <stdio.h>
#include "int-proto.h"

/*
 * Ring buffer abstraction for TGTs returned from a ccache; avoids
 * lots of excess copying.
 */
#define NCC_TGTS 2
struct cc_tgts {
    krb5_creds cred[NCC_TGTS];
    int dirty[NCC_TGTS];
    unsigned int cur, nxt;
};

/*
 * State struct for do_traversal() and helpers.
 *
 * CUR_TGT and NXT_TGT can each point either into CC_TGTS or into
 * KDC_TGTS.
 *
 * CUR_TGT is the "working" TGT, which will be used to obtain new
 * TGTs.  NXT_TGT will be CUR_TGT for the next iteration of the loop.
 *
 * Part of the baroqueness of this setup is to deal with annoying
 * differences between krb5_cc_retrieve_cred() and
 * krb5_get_cred_via_tkt(); krb5_cc_retrieve_cred() fills in a
 * caller-allocated krb5_creds, while krb5_get_cred_via_tkt()
 * allocates a krb5_creds for return.
 */
struct tr_state {
    krb5_principal *kdc_list;
    unsigned int nkdcs;
    krb5_principal *cur_kdc;
    krb5_principal *nxt_kdc;
    krb5_principal *lst_kdc;
    krb5_creds *cur_tgt;
    krb5_creds *nxt_tgt;
    krb5_creds **kdc_tgts;
    struct cc_tgts cc_tgts;
    krb5_creds *cur_cc_tgt;
    krb5_creds *nxt_cc_tgt;
    unsigned int ntgts;
    krb5_creds *offpath_tgt;
};

enum krb5_tkt_creds_state {
    TKT_CREDS_INITIAL_TGT,
    TKT_CREDS_REFERRAL_TGT,
    TKT_CREDS_REFERRAL_TGT_NOCANON,
    TKT_CREDS_FALLBACK_INITIAL_TGT,
    TKT_CREDS_FALLBACK_FINAL_TKT,
    TKT_CREDS_COMPLETE
};

/*
 * Asynchronous API request/response state
 */
struct _krb5_tkt_creds_context {
    enum krb5_tkt_creds_state state;
    krb5_ccache ccache;
    krb5_creds in_cred;
    krb5_creds tgtq;
    krb5_data *realm;
    krb5_principal client;
    krb5_principal server;
    krb5_creds *out_cred;
    krb5_creds **tgts;
    int kdcopt;
    unsigned int referral_count;
    krb5_creds cc_tgt;
    krb5_creds *tgtptr;
    krb5_creds *referral_tgts[KRB5_REFERRAL_MAXHOPS];
    krb5_creds *otgtptr;
    int tgtptr_isoffpath;
    krb5_boolean use_conf_ktypes;
    struct tr_state ts;
    krb5_timestamp timestamp;
    krb5_keyblock *subkey;
    krb5_data encoded_previous_request;
};

/* NOTE: This only checks if NXT_TGT is CUR_CC_TGT. */
#define NXT_TGT_IS_CACHED(ts)                   \
    ((ts)->nxt_tgt == (ts)->cur_cc_tgt)

#define MARK_CUR_CC_TGT_CLEAN(ts)                       \
    do {                                                \
        (ts)->cc_tgts.dirty[(ts)->cc_tgts.cur] = 0;     \
    } while (0)

static void init_cc_tgts(krb5_context, krb5_tkt_creds_context);
static void shift_cc_tgts(krb5_context, krb5_tkt_creds_context);
static void clean_cc_tgts(krb5_context, krb5_tkt_creds_context);

/*
 * Debug support
 */
#ifdef DEBUG_GC_FRM_KDC

#define TR_DBG(context, ctx, prog) tr_dbg(context, ctx, prog)
#define TR_DBG_RET(context, ctx, prog, ret) tr_dbg_ret(context, ctx, prog, ret)
#define TR_DBG_RTREE(context, ctx, prog, princ) tr_dbg_rtree(context, ctx, prog, princ)

static void tr_dbg(krb5_context, krb5_tkt_creds_context, const char *);
static void tr_dbg_ret(krb5_context, krb5_tkt_creds_context, const char *, krb5_error_code);
static void tr_dbg_rtree(krb5_context, krb5_tkt_creds_context, const char *, krb5_principal);

#else

#define TR_DBG(context, ctx, prog)
#define TR_DBG_RET(context, ctx, prog, ret)
#define TR_DBG_RTREE(context, ctx, prog, princ)

#endif /* !DEBUG_GC_FRM_KDC */

#ifdef DEBUG_REFERRALS

#define DPRINTF(x) printf x
#define DFPRINTF(x) fprintf x
#define DUMP_PRINC(x, y) krb5int_dbgref_dump_principal((x), (y))

#else

#define DPRINTF(x)
#define DFPRINTF(x)
#define DUMP_PRINC(x, y)

#endif

/* Convert ticket flags to necessary KDC options */
#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

/*
 * Certain krb5_cc_retrieve_cred() errors are soft errors when looking
 * for a cross-realm TGT.
 */
#define HARD_CC_ERR(r) ((r) && (r) != KRB5_CC_NOTFOUND &&       \
                        (r) != KRB5_CC_NOT_KTYPE)

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
static krb5_error_code retr_local_tgt(krb5_context context,
                                      krb5_tkt_creds_context);
static krb5_error_code try_ccache(krb5_context context,
                                  krb5_tkt_creds_context, krb5_creds *);
static krb5_error_code find_nxt_kdc(krb5_context context,
                                    krb5_tkt_creds_context);
static krb5_error_code try_kdc_request(krb5_context context,
                                       krb5_tkt_creds_context,
                                       krb5_data *);
static krb5_error_code try_kdc_reply(krb5_context,
                                     krb5_tkt_creds_context,
                                     krb5_data *);
static krb5_error_code kdc_mcred(krb5_context context,
                                 krb5_tkt_creds_context, krb5_principal,
                                 krb5_creds *mcreds);
static krb5_error_code next_closest_tgt_request(krb5_context context,
                                                krb5_tkt_creds_context,
                                                krb5_data *);
static krb5_error_code next_closest_tgt_reply(krb5_context context,
                                              krb5_tkt_creds_context,
                                              krb5_data *);
static krb5_error_code init_rtree(krb5_context context,
                                  krb5_tkt_creds_context);
static krb5_error_code do_traversal_request(krb5_context context,
                                            krb5_tkt_creds_context,
                                            krb5_data *req);
static krb5_error_code do_traversal_reply(krb5_context context,
                                           krb5_tkt_creds_context,
                                           krb5_data *req);

static krb5_error_code chase_offpath_request(krb5_context,
                                             krb5_tkt_creds_context,
                                             krb5_data *data);
static krb5_error_code chase_offpath_reply(krb5_context,
                                           krb5_tkt_creds_context,
                                           krb5_data *data);
static krb5_error_code offpath_loopchk(krb5_context context,
                                       krb5_tkt_creds_context ctx,
                                       krb5_creds *tgt,
                                       krb5_creds *reftgts[],
                                       unsigned int rcount);

#define TR_STATE(_ctx)  (&(_ctx)->ts)

/*
 * init_cc_tgts()
 *
 * Initialize indices for cached-TGT ring buffer.  Caller must zero
 * CC_TGTS, CC_TGT_DIRTY arrays prior to calling.
 */
static void
init_cc_tgts(krb5_context context, krb5_tkt_creds_context ctx)
{
    struct tr_state *ts = TR_STATE(ctx);

    ts->cc_tgts.cur = 0;
    ts->cc_tgts.nxt = 1;
    ts->cur_cc_tgt = &ts->cc_tgts.cred[0];
    ts->nxt_cc_tgt = &ts->cc_tgts.cred[1];
}

/*
 * shift_cc_tgts()
 *
 * Given a fresh assignment to NXT_CC_TGT, mark NXT_CC_TGT as dirty,
 * and shift indices so old NXT_CC_TGT becomes new CUR_CC_TGT.  Clean
 * the new NXT_CC_TGT.
 */
static void
shift_cc_tgts(krb5_context context, krb5_tkt_creds_context ctx)
{
    unsigned int i;
    struct cc_tgts *rb;
    struct tr_state *ts = TR_STATE(ctx);

    rb = &ts->cc_tgts;
    i = rb->cur = rb->nxt;
    rb->dirty[i] = 1;
    ts->cur_cc_tgt = ts->nxt_cc_tgt;

    i = (i + 1) % NCC_TGTS;

    rb->nxt = i;
    ts->nxt_cc_tgt = &rb->cred[i];
    if (rb->dirty[i]) {
        krb5_free_cred_contents(context, &rb->cred[i]);
        rb->dirty[i] = 0;
    }
}

/*
 * clean_cc_tgts()
 *
 * Free CC_TGTS which were dirty, then mark them clean.
 */
static void
clean_cc_tgts(krb5_context context, krb5_tkt_creds_context ctx)
{
    unsigned int i;
    struct cc_tgts *rb;
    struct tr_state *ts = TR_STATE(ctx);

    rb = &ts->cc_tgts;
    for (i = 0; i < NCC_TGTS; i++) {
        if (rb->dirty[i]) {
            krb5_free_cred_contents(context, &rb->cred[i]);
            rb->dirty[i] = 0;
        }
    }
}

/*
 * Debug support
 */
#ifdef DEBUG_GC_FRM_KDC
static void
tr_dbg(krb5_context context, krb5_tkt_creds_context ctx, const char *prog)
{
    krb5_error_code retval;
    char *cur_tgt_str, *cur_kdc_str, *nxt_kdc_str;
    struct tr_state *ts = TR_STATE(ctx);

    cur_tgt_str = cur_kdc_str = nxt_kdc_str = NULL;
    retval = krb5_unparse_name(context, ts->cur_tgt->server, &cur_tgt_str);
    if (retval) goto cleanup;
    retval = krb5_unparse_name(context, *ts->cur_kdc, &cur_kdc_str);
    if (retval) goto cleanup;
    retval = krb5_unparse_name(context, *ts->nxt_kdc, &nxt_kdc_str);
    if (retval) goto cleanup;
    fprintf(stderr, "%s: cur_tgt %s\n", prog, cur_tgt_str);
    fprintf(stderr, "%s: cur_kdc %s\n", prog, cur_kdc_str);
    fprintf(stderr, "%s: nxt_kdc %s\n", prog, nxt_kdc_str);
cleanup:
    if (cur_tgt_str)
        krb5_free_unparsed_name(context, cur_tgt_str);
    if (cur_kdc_str)
        krb5_free_unparsed_name(context, cur_kdc_str);
    if (nxt_kdc_str)
        krb5_free_unparsed_name(context, nxt_kdc_str);
}

static void
tr_dbg_ret(krb5_context context, krb5_tkt_creds_context ctx,
           const char *prog, krb5_error_code ret)
{
    fprintf(stderr, "%s: return %d (%s)\n", prog, (int)ret,
            error_message(ret));
}

static void
tr_dbg_rtree(krb5_context context, krb5_tkt_creds_context ctx,
             const char *prog, krb5_principal princ)
{
    char *str;

    if (krb5_unparse_name(context, princ, &str))
        return;
    fprintf(stderr, "%s: %s\n", prog, str);
    krb5_free_unparsed_name(context, str);
}
#endif /* DEBUG_GC_FRM_KDC */

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

    retval = 0;
    memset(mcreds, 0, sizeof(*mcreds));

    retval = krb5_copy_principal(context, client, &mcreds->client);
    if (retval)
        goto cleanup;

    retval = krb5_tgtname(context, krb5_princ_realm(context, dst),
                          krb5_princ_realm(context, src), &mcreds->server);
    if (retval)
        goto cleanup;

cleanup:
    if (retval)
        krb5_free_cred_contents(context, mcreds);

    return retval;
}

/*
 * init_rtree()
 *
 * Populate KDC_LIST with the output of krb5_walk_realm_tree().
 */
static krb5_error_code
init_rtree(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    ts->kdc_list = NULL;
    retval = krb5_walk_realm_tree(context, krb5_princ_realm(context,
                                                            ctx->client),
                                  krb5_princ_realm(context, ctx->server),
                                  &ts->kdc_list, KRB5_REALM_BRANCH_CHAR);
    if (retval)
        return retval;

    for (ts->nkdcs = 0; ts->kdc_list[ts->nkdcs]; ts->nkdcs++) {
        assert(krb5_princ_size(context, ts->kdc_list[ts->nkdcs]) == 2);
        TR_DBG_RTREE(context, ctx, "init_rtree", ts->kdc_list[ts->nkdcs]);
    }
    assert(ts->nkdcs > 1);
    ts->lst_kdc = ts->kdc_list + ts->nkdcs - 1;

    ts->kdc_tgts = calloc(ts->nkdcs + 1, sizeof(krb5_creds));
    if (ts->kdc_tgts == NULL)
        return ENOMEM;

    return 0;
}

/*
 * retr_local_tgt()
 *
 * Prime CUR_TGT with the cached TGT of the client's local realm.
 */
static krb5_error_code
retr_local_tgt(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code retval;
    krb5_creds tgtq;
    struct tr_state *ts = TR_STATE(ctx);

    memset(&tgtq, 0, sizeof(tgtq));
    retval = tgt_mcred(context, ctx->client, ctx->client, ctx->client, &tgtq);
    if (retval)
        return retval;

    /* Match realm, unlike other ccache retrievals here. */
    retval = krb5_cc_retrieve_cred(context, ctx->ccache,
                                   KRB5_TC_SUPPORTED_KTYPES,
                                   &tgtq, ts->nxt_cc_tgt);
    krb5_free_cred_contents(context, &tgtq);
    if (!retval) {
        shift_cc_tgts(context, ctx);
        ts->nxt_tgt = ts->cur_tgt = ts->cur_cc_tgt;
    }
    return retval;
}

/*
 * try_ccache()
 *
 * Attempt to retrieve desired NXT_TGT from ccache.  Point NXT_TGT to
 * it if successful.
 */
static krb5_error_code
try_ccache(krb5_context context, krb5_tkt_creds_context ctx, krb5_creds *tgtq)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    TR_DBG(context, ctx, "try_ccache");
    retval = krb5_cc_retrieve_cred(context, ctx->ccache, RETR_FLAGS,
                                   tgtq, ts->nxt_cc_tgt);
    if (!retval) {
        shift_cc_tgts(context, ctx);
        ts->nxt_tgt = ts->cur_cc_tgt;
    }
    TR_DBG_RET(context, ctx, "try_ccache", retval);
    return retval;
}

/*
 * find_nxt_kdc()
 *
 * A NXT_TGT gotten from an intermediate KDC might actually be a
 * referral.  Search KDC_LIST forward starting from CUR_KDC, looking
 * for the KDC with the same remote realm as NXT_TGT.  If we don't
 * find it, the intermediate KDC is leading us off the transit path.
 *
 * Match on CUR_KDC's remote realm, not local realm, because, among
 * other reasons, we can get a referral to the final realm; e.g.,
 * given
 *
 *     KDC_LIST == { krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2,
 *                   krbtgt/R4@R3, NULL }
 *     CUR_TGT->SERVER == krbtgt/R2@R1
 *     NXT_TGT->SERVER == krbtgt/R4@R2
 *
 * i.e., we got a ticket issued by R2 with remote realm R4, we want to
 * find krbtgt/R4@R3, not krbtgt/R3@R2, even though we have no TGT
 * with R3 as its local realm.
 *
 * Set up for next iteration of do_traversal() loop by pointing
 * NXT_KDC to one entry forward of the match.
 */
static krb5_error_code
find_nxt_kdc(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_data *r1, *r2;
    krb5_principal *kdcptr;
    struct tr_state *ts = TR_STATE(ctx);

    TR_DBG(context, ctx, "find_nxt_kdc");
    assert(ts->ntgts > 0);
    assert(ts->nxt_tgt == ts->kdc_tgts[ts->ntgts-1]);
    if (krb5_princ_size(context, ts->nxt_tgt->server) != 2)
        return KRB5_KDCREP_MODIFIED;

    r1 = krb5_princ_component(context, ts->nxt_tgt->server, 1);

    for (kdcptr = ts->cur_kdc + 1; *kdcptr != NULL; kdcptr++) {

        r2 = krb5_princ_component(context, *kdcptr, 1);

        if (r1 != NULL && r2 != NULL && data_eq(*r1, *r2)) {
            break;
        }
    }
    if (*kdcptr != NULL) {
        ts->nxt_kdc = kdcptr;
        TR_DBG_RET(context, ctx, "find_nxt_kdc", 0);
        return 0;
    }

    r2 = krb5_princ_component(context, ts->kdc_list[0], 1);
    if (r1 != NULL && r2 != NULL &&
        r1->length == r2->length &&
        !memcmp(r1->data, r2->data, r1->length)) {
        TR_DBG_RET(context, ctx, "find_nxt_kdc: looped back to local",
                   KRB5_KDCREP_MODIFIED);
        return KRB5_KDCREP_MODIFIED;
    }

    /*
     * Realm is not in our list; we probably got an unexpected realm
     * referral.
     */
    ts->offpath_tgt = ts->nxt_tgt;
    if (ts->cur_kdc == ts->kdc_list) {
        /*
         * Local KDC referred us off path; trust it for caching
         * purposes.
         */
        return 0;
    }
    /*
     * Unlink the off-path TGT from KDC_TGTS but don't free it,
     * because we should return it.
     */
    ts->kdc_tgts[--ts->ntgts] = NULL;
    ts->nxt_tgt = ts->cur_tgt;
    TR_DBG_RET(context, ctx, "find_nxt_kdc", 0);
    return 0;
}

/*
 * try_kdc()
 *
 * Using CUR_TGT, attempt to get desired NXT_TGT.  Update NXT_KDC if
 * successful.
 */
static krb5_error_code
try_kdc_request(krb5_context context,
                krb5_tkt_creds_context ctx,
                krb5_data *req)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    TR_DBG(context, ctx, "try_kdc_request");
    /* This check should probably be in gc_via_tkt. */
    if (!krb5_c_valid_enctype(ts->cur_tgt->keyblock.enctype))
        return KRB5_PROG_ETYPE_NOSUPP;

    assert(ctx->tgtq.server);

    ctx->tgtq.is_skey = FALSE;
    ctx->tgtq.ticket_flags = ts->cur_tgt->ticket_flags;

    assert(ts->cur_tgt != NULL);
    ctx->realm = &ts->cur_tgt->server->realm;

    retval = krb5_make_tgs_request(context, ts->cur_tgt,
                                   FLAGS2OPTS(ts->cur_tgt->ticket_flags),
                                   ts->cur_tgt->addresses, NULL,
                                   &ctx->tgtq, NULL, NULL,
                                   req, &ctx->timestamp, &ctx->subkey);

    TR_DBG_RET(context, ctx, "try_kdc_request", retval);

    return retval;
}

static krb5_error_code
try_kdc_reply(krb5_context context,
              krb5_tkt_creds_context ctx,
              krb5_data *rep)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    TR_DBG(context, ctx, "try_kdc_reply");
    retval = krb5_process_tgs_response(context,
                                       rep,
                                       ts->cur_tgt,
                                       FLAGS2OPTS(ts->cur_tgt->ticket_flags),
                                       ts->cur_tgt->addresses,
                                       NULL,
                                       &ctx->tgtq,
                                       ctx->timestamp,
                                       ctx->subkey,
                                       NULL,
                                       NULL,
                                       &ts->kdc_tgts[ts->ntgts++]);
    if (retval != 0) {
        ts->ntgts--;
        ts->nxt_tgt = ts->cur_tgt;
    } else {
        ts->nxt_tgt = ts->kdc_tgts[ts->ntgts-1];
        retval = find_nxt_kdc(context, ctx);
    }
    TR_DBG_RET(context, ctx, "try_kdc_reply", retval);
    return retval;
}

/*
 * kdc_mcred()
 *
 * Return MCREDS for use as a match criterion.
 *
 * Resulting credential has CLIENT as the client principal, and
 * krbtgt/remote_realm(NXT_KDC)@local_realm(CUR_KDC) as the server
 * principal.  Zeroes MCREDS first, does not allocate MCREDS, and
 * cleans MCREDS on failure.
 */
static krb5_error_code
kdc_mcred(krb5_context context, krb5_tkt_creds_context ctx,
          krb5_principal client, krb5_creds *mcreds)
{
    krb5_error_code retval;
    krb5_data *rdst, *rsrc;
    struct tr_state *ts = TR_STATE(ctx);

    retval = 0;
    memset(mcreds, 0, sizeof(*mcreds));

    rdst = krb5_princ_component(context, *ts->nxt_kdc, 1);
    rsrc = krb5_princ_component(context, *ts->cur_kdc, 1);

    retval = krb5_copy_principal(context, client, &mcreds->client);
    if (retval)
        goto cleanup;

    retval = krb5_tgtname(context, rdst, rsrc, &mcreds->server);
    if (retval)
        goto cleanup;

cleanup:
    if (retval)
        krb5_free_cred_contents(context, mcreds);

    return retval;
}

/*
 * next_closest_tgt()
 *
 * Using CUR_TGT, attempt to get the cross-realm TGT having its remote
 * realm closest to the target principal's.  Update NXT_TGT, NXT_KDC
 * accordingly.
 */
static krb5_error_code
next_closest_tgt_request(krb5_context context,
                         krb5_tkt_creds_context ctx,
                         krb5_data *req)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    retval = 0;

    assert(ctx->tgtq.server == NULL);

    if (ts->nxt_kdc == NULL)
        ts->nxt_kdc = ts->lst_kdc;
    else if (ts->nxt_kdc == ts->cur_kdc)
        return 0;

    retval = kdc_mcred(context, ctx, ctx->client, &ctx->tgtq);
    if (retval)
        goto cleanup;

    /* Don't waste time retrying ccache for direct path. */
    if (ts->cur_kdc != ts->kdc_list || ts->nxt_kdc != ts->lst_kdc) {
        retval = try_ccache(context, ctx, &ctx->tgtq);
        if (retval == 0 || HARD_CC_ERR(retval)) {
            if (retval == 0)
                ctx->state++;
            goto cleanup;
        }
    }

    /* Not in the ccache, so talk to a KDC. */
    retval = try_kdc_request(context, ctx, req);
    if (retval != 0)
        goto cleanup;

cleanup:
    return retval;
}

static krb5_error_code
next_closest_tgt_reply(krb5_context context,
                       krb5_tkt_creds_context ctx,
                       krb5_data *rep)
{
    krb5_error_code retval;
#if 0
    struct tr_state *ts = TR_STATE(ctx);
#endif

    assert(ctx->out_cred == NULL);

    retval = try_kdc_reply(context, ctx, rep);
#if 0
    if (retval == 0)
        ts->nxt_kdc--;
#endif

    return retval;
}

/*
 * do_traversal()
 *
 * Find final TGT needed to get CLIENT a ticket for SERVER.  Point
 * OUT_TGT at the desired TGT, which may be an existing cached TGT
 * (copied into OUT_CC_TGT) or one of the newly obtained TGTs
 * (collected in OUT_KDC_TGTS).
 *
 * Get comfortable; this is somewhat complicated.
 *
 * Nomenclature: Cross-realm TGS principal names have the form:
 *
 *     krbtgt/REMOTE@LOCAL
 *
 * krb5_walk_realm_tree() returns a list like:
 *
 *     krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2, ...
 *
 * These are prinicpal names, not realm names.  We only really use the
 * remote parts of the TGT principal names.
 *
 * The do_traversal loop calls next_closest_tgt() to find the next
 * closest TGT to the destination realm.  next_closest_tgt() updates
 * NXT_KDC for the following iteration of the do_traversal() loop.
 *
 * At the beginning of any given iteration of the do_traversal() loop,
 * CUR_KDC's remote realm is the remote realm of CUR_TGT->SERVER.  The
 * local realms of CUR_KDC and CUR_TGT->SERVER may not match due to
 * short-circuit paths provided by intermediate KDCs, e.g., CUR_KDC
 * might be krbtgt/D@C, while CUR_TGT->SERVER is krbtgt/D@B.
 *
 * For example, given KDC_LIST of
 *
 * krbtgt/R1@R1, krbtgt/R2@R1, krbtgt/R3@R2, krbtgt/R4@R3,
 * krbtgt/R5@R4
 *
 * The next_closest_tgt() loop moves NXT_KDC to the left starting from
 * R5, stopping before it reaches CUR_KDC.  When next_closest_tgt()
 * returns, the do_traversal() loop updates CUR_KDC to be NXT_KDC, and
 * calls next_closest_tgt() again.
 *
 * next_closest_tgt() at start of its loop:
 *
 *      CUR                 NXT
 *       |                   |
 *       V                   V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * next_closest_tgt() returns after finding a ticket for krbtgt/R3@R1:
 *
 *      CUR       NXT
 *       |         |
 *       V         V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * do_traversal() updates CUR_KDC:
 *
 *                NXT
 *                CUR
 *                 |
 *                 V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * next_closest_tgt() at start of its loop:
 *
 *                CUR       NXT
 *                 |         |
 *                 V         V
 *     +----+----+----+----+----+
 *     | R1 | R2 | R3 | R4 | R5 |
 *     +----+----+----+----+----+
 *
 * etc.
 *
 * The algorithm executes in n*(n-1)/2 (the sum of integers from 1 to
 * n-1) attempts in the worst case, i.e., each KDC only has a
 * cross-realm ticket for the immediately following KDC in the transit
 * path.  Typically, short-circuit paths will cause execution to occur
 * faster than this worst-case scenario.
 *
 * When next_closest_tgt() updates NXT_KDC, it may not perform a
 * simple increment from CUR_KDC, in part because some KDC may
 * short-circuit pieces of the transit path.
 */
static krb5_error_code
do_traversal_request(krb5_context context,
                     krb5_tkt_creds_context ctx,
                     krb5_data *req)
{
    krb5_error_code retval = 0;
    struct tr_state *ts = TR_STATE(ctx);

    if (ts->kdc_list == NULL) {
        /* Initial state */
        init_cc_tgts(context, ctx);

        retval = init_rtree(context, ctx);
        if (retval)
            goto cleanup;

        retval = retr_local_tgt(context, ctx);
        if (retval)
            goto cleanup;

        ts->cur_kdc = ts->kdc_list;
        ts->nxt_kdc = NULL;
    }

    if (ts->cur_kdc == NULL || ts->cur_kdc >= ts->lst_kdc) {
        /* termination condition */
        ctx->state++;
        goto cleanup;
    }

    if (ts->offpath_tgt != NULL) {
        retval = chase_offpath_request(context, ctx, req);
    } else {
        retval = next_closest_tgt_request(context, ctx, req);
    }

cleanup:
    return retval;
}

static krb5_error_code
do_traversal_reply(krb5_context context,
                   krb5_tkt_creds_context ctx,
                   krb5_data *rep)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);

    assert(ctx->out_cred == NULL);

    if (ts->offpath_tgt != NULL) {
        retval = chase_offpath_reply(context, ctx, rep);
        if (retval != 0)
            return retval;

        /* this is a termination condition */
        goto success;
    } else {
        retval = next_closest_tgt_reply(context, ctx, rep);
        if (retval != 0)
            return retval;
    }

    assert(ts->cur_kdc != ts->nxt_kdc);

    ts->cur_kdc = ts->nxt_kdc;
    ts->cur_tgt = ts->nxt_tgt;

    if (ts->cur_kdc == ts->lst_kdc) {
success:
        if (NXT_TGT_IS_CACHED(ts)) {
            assert(ts->offpath_tgt == NULL);
            ctx->cc_tgt = *ts->cur_cc_tgt;
            ctx->tgtptr = ts->cur_tgt;
            MARK_CUR_CC_TGT_CLEAN(ts);
        } else if (ts->offpath_tgt != NULL){
            ctx->tgtptr = ts->offpath_tgt;
        } else {
            /* CUR_TGT is somewhere in KDC_TGTS; no need to copy. */
            ctx->tgtptr = ts->nxt_tgt;
        }
        ctx->tgtptr_isoffpath = (ts->offpath_tgt != NULL);

        ctx->state++;
        ctx->referral_count = 0;
    }

   return retval;
}

/*
 * chase_offpath()
 *
 * Chase off-path TGT referrals.
 *
 * If we are traversing a trusted path (either hierarchically derived
 * or explicit capath) and get a TGT pointing to a realm off this
 * path, query the realm referenced by that off-path TGT.  Repeat
 * until we get to the destination realm or encounter an error.
 *
 * CUR_TGT is always either pointing into REFTGTS or is an alias for
 * TS->OFFPATH_TGT.
 */
static krb5_error_code
chase_offpath_request(krb5_context context,
                      krb5_tkt_creds_context ctx,
                      krb5_data *req)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);
    krb5_data *rdst = krb5_princ_realm(context, ctx->server);
    krb5_data *rsrc;

    if (ctx->tgtptr == NULL) {
        ts->cur_tgt = ts->offpath_tgt;
        ctx->referral_count = 0;
    }
    if (ctx->referral_count >= KRB5_REFERRAL_MAXHOPS) {
        /* termination condition */
        retval = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

    rsrc = krb5_princ_component(context, ctx->tgtptr->server, 1);

    assert(ctx->tgtq.server == NULL);

    retval = krb5_tgtname(context, rdst, rsrc, &ctx->tgtq.server);
    if (retval)
        goto cleanup;

    retval = krb5_copy_principal(context, ctx->client, &ctx->tgtq.client);
    if (retval)
        goto cleanup;

    assert(ts->cur_tgt != NULL);
    ctx->realm = &ts->cur_tgt->server->realm;

    retval = krb5_make_tgs_request(context, ts->cur_tgt,
                                   FLAGS2OPTS(ctx->tgtptr->ticket_flags),
                                   ts->cur_tgt->addresses, NULL,
                                   &ctx->tgtq, NULL, NULL,
                                   req, &ctx->timestamp, &ctx->subkey);
    if (retval)
        goto cleanup;

cleanup:
    return retval;
}

static krb5_error_code
chase_offpath_reply(krb5_context context,
                    krb5_tkt_creds_context ctx,
                    krb5_data *rep)
{
    krb5_error_code retval;
    struct tr_state *ts = TR_STATE(ctx);
    krb5_creds *nxt_tgt = NULL;
    krb5_data *rsrc;
    krb5_data *rdst = krb5_princ_realm(context, ctx->server);
    krb5_data *r1;

    rsrc = krb5_princ_component(context, ctx->tgtptr->server, 1);

    retval = krb5_process_tgs_response(context,
                                       rep,
                                       ctx->tgtptr,
                                       FLAGS2OPTS(ts->cur_tgt->ticket_flags),
                                       ctx->tgtptr->addresses,
                                       NULL,
                                       &ctx->tgtq,
                                       ctx->timestamp,
                                       ctx->subkey,
                                       NULL,
                                       NULL,
                                       &nxt_tgt);
    if (!IS_TGS_PRINC(context, nxt_tgt->server)) {
        retval = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }
    r1 = krb5_princ_component(context, nxt_tgt->server, 1);
    if (rdst->length == r1->length &&
        !memcmp(rdst->data, r1->data, rdst->length)) {
        retval = 0;
        goto cleanup;
    }
    retval = offpath_loopchk(context, ctx, nxt_tgt, ctx->referral_tgts,
                             ctx->referral_count);
    if (retval)
        goto cleanup;
    assert(ctx->referral_count < KRB5_REFERRAL_MAXHOPS - 1);
    ctx->referral_tgts[ctx->referral_count++] = nxt_tgt;
    ctx->tgtptr = nxt_tgt;
    nxt_tgt = NULL;

cleanup:
    /*
     * Don't free TS->OFFPATH_TGT if it's in the list of cacheable
     * TGTs to be returned by do_traversal().
     */
    if (ts->offpath_tgt != ts->nxt_tgt) {
        krb5_free_creds(context, ts->offpath_tgt);
    }
    ts->offpath_tgt = NULL;
    if (nxt_tgt != NULL) {
        if (retval)
            krb5_free_creds(context, nxt_tgt);
        else
            ts->offpath_tgt = nxt_tgt;
    }
    return retval;
}

/*
 * offpath_loopchk()
 *
 * Check for loop back to previously-visited realms, both off-path and
 * on-path.
 */
static krb5_error_code
offpath_loopchk(krb5_context context, krb5_tkt_creds_context ctx,
                krb5_creds *tgt, krb5_creds *reftgts[], unsigned int rcount)
{
    krb5_data *r1, *r2;
    unsigned int i;
    struct tr_state *ts = TR_STATE(ctx);

    r1 = krb5_princ_component(context, tgt->server, 1);
    for (i = 0; i < rcount; i++) {
        r2 = krb5_princ_component(context, reftgts[i]->server, 1);
        if (r1->length == r2->length &&
            !memcmp(r1->data, r2->data, r1->length))
            return KRB5_KDCREP_MODIFIED;
    }
    for (i = 0; i < ts->ntgts; i++) {
        r2 = krb5_princ_component(context, ts->kdc_tgts[i]->server, 1);
        if (r1->length == r2->length &&
            !memcmp(r1->data, r2->data, r1->length))
            return KRB5_KDCREP_MODIFIED;
    }
    return 0;
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

    ctx = k5alloc(sizeof(*ctx), &code);
    if (code != 0)
        goto cleanup;

    code = krb5int_copy_creds_contents(context, creds, &ctx->in_cred);
    if (code != 0)
        goto cleanup;

    ctx->ccache = ccache; /* XXX */

    ctx->use_conf_ktypes = context->use_conf_ktypes;

    assert(ctx->in_cred.client);
    assert(ctx->in_cred.server);

    if (krb5_is_referral_realm(&ctx->in_cred.server->realm)) {
        /* Use the client realm. */
        DPRINTF(("krb5_tkt_creds_init: no server realm supplied, "
                 "using client realm\n"));
        krb5_free_data_contents(context, &ctx->in_cred.server->realm);
        code = krb5int_copy_data_contents_add0(context,
                                               &ctx->in_cred.client->realm,
                                               &ctx->in_cred.server->realm);
        if (code != 0)
            goto cleanup;
    }

    /* The rest must be done by krb5_tkt_creds_step() */

    ctx->client = ctx->in_cred.client;
    ctx->server = ctx->in_cred.server;

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
    if (ctx->state != TKT_CREDS_COMPLETE)
        return EINVAL;
    return krb5int_copy_creds_contents(context, ctx->out_cred, creds);
}

void KRB5_CALLCONV
krb5_tkt_creds_free(krb5_context context,
                    krb5_tkt_creds_context ctx)
{
    struct tr_state *ts;
    int i;

    if (ctx == NULL)
        return;

    krb5_free_cred_contents(context, &ctx->in_cred);
    krb5_free_cred_contents(context, &ctx->tgtq);
    krb5_free_creds(context, ctx->out_cred);
    krb5_free_tgt_creds(context, ctx->tgts);
    krb5_free_data_contents(context, &ctx->encoded_previous_request);
    krb5_free_keyblock(context, ctx->subkey);

    /* Free referral TGTs list. */
    for (i = 0; i < KRB5_REFERRAL_MAXHOPS; i++) {
        if (ctx->referral_tgts[i])
            krb5_free_creds(context, ctx->referral_tgts[i]);
    }

    clean_cc_tgts(context, ctx);
    ts = TR_STATE(ctx);
    if (ts->kdc_list != NULL)
        krb5_free_realm_tree(context, ts->kdc_list);
    if (ts->ntgts == 0) {
        if (ts->kdc_tgts != NULL)
            free(ts->kdc_tgts);
    }

    free(ctx);
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get(krb5_context context,
                   krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    krb5_data request;
    krb5_data reply;
    krb5_data realm;
    unsigned int flags = 0;
    int tcp_only = 0;
    int use_master = 0;

    request.length = 0;
    request.data = NULL;
    reply.length = 0;
    reply.data = NULL;
    realm.length = 0;
    realm.data = NULL;

    if (ctx->state == TKT_CREDS_COMPLETE) {
        return 0;
    }

    for (;;) {
        code = krb5_tkt_creds_step(context,
                                   ctx,
                                   &reply,
                                   &request,
                                   &realm,
                                   &flags);
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG && !tcp_only)
            tcp_only = 1;
        else if (code != 0 || (flags & KRB5_TKT_CREDS_STEP_FLAG_COMPLETE))
            break;

        krb5_free_data_contents(context, &reply);

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

/*
 * Retrieve initial TGT to match the specified server, either for the
 * local realm in the default (referral) case or for the remote realm
 * if we're starting someplace non-local.
 */
static krb5_error_code
tkt_creds_step_request_initial_tgt(krb5_context context,
                                   krb5_tkt_creds_context ctx,
                                   krb5_data *req)
{
    krb5_error_code code;

    assert(ctx->tgtptr == NULL);

    DUMP_PRINC("tkt_creds_step_request_initial_tgt: server",
               ctx->in_cred.server);

    assert(ctx->tgtq.server == NULL);

    code = tgt_mcred(context, ctx->client, ctx->server,
                     ctx->client, &ctx->tgtq);
    if (code != 0)
        goto cleanup;

    /* Fast path: is it in the ccache? */
    code = krb5_cc_retrieve_cred(context, ctx->ccache, RETR_FLAGS,
                                 &ctx->tgtq, &ctx->cc_tgt);
    if (code == 0) {
        ctx->state++;
        ctx->tgtptr = &ctx->cc_tgt;
        goto cleanup;
    } else if (HARD_CC_ERR(code)) {
        goto cleanup;
    } else {
        ctx->tgtptr_isoffpath = 0;
        ctx->otgtptr = NULL;

        krb5_free_cred_contents(context, &ctx->tgtq);

        code = do_traversal_request(context, ctx, req);
        if (code != 0)
            goto cleanup;
    }

cleanup:
    return code;
}

static krb5_error_code
tkt_creds_step_reply_initial_tgt(krb5_context context,
                                 krb5_tkt_creds_context ctx,
                                 krb5_data *rep)
{
    krb5_error_code code;

    code = do_traversal_reply(context, ctx, rep);
    if (code != 0) {
        DPRINTF(("tkt_creds_step_reply_initial_tgt: failed to find initial TGT for referral\n"));
    }

    return code;
}

/*
 * Determine KDC options to use based on context options
 */
static krb5_flags
tkt_creds_kdcopt(krb5_tkt_creds_context ctx)
{
    krb5_flags kdcopt;

    kdcopt = ctx->kdcopt;
    kdcopt |= FLAGS2OPTS(ctx->tgtptr->ticket_flags);

    if (ctx->state == TKT_CREDS_REFERRAL_TGT)
        kdcopt |= KDC_OPT_CANONICALIZE;

    if (ctx->in_cred.second_ticket.length != 0 &&
        (kdcopt & KDC_OPT_CNAME_IN_ADDL_TKT) == 0) {
        kdcopt |= KDC_OPT_ENC_TKT_IN_SKEY;
    }

    return kdcopt;
}

static krb5_error_code
tkt_creds_step_request_referral_tgt(krb5_context context,
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
    if (ctx->referral_count == 0) {
        ctx->otgtptr = ctx->tgtptr;
    } else if (ctx->referral_count >= KRB5_REFERRAL_MAXHOPS) {
        code = KRB5_GET_IN_TKT_LOOP; /* XXX */
        goto cleanup;
    }

    assert(ctx->tgtptr != NULL);
    ctx->realm = &ctx->server->realm;

    code = krb5_make_tgs_request(context,
                                 ctx->tgtptr,
                                 tkt_creds_kdcopt(ctx),
                                 ctx->tgtptr->addresses,
                                 NULL,
                                 &ctx->in_cred,
                                 NULL,
                                 NULL,
                                 req,
                                 &ctx->timestamp,
                                 &ctx->subkey);
    if (code != 0)
        goto cleanup;

cleanup:
    return code;
}

static krb5_error_code
tkt_creds_step_reply_referral_tgt(krb5_context context,
                                  krb5_tkt_creds_context ctx,
                                  krb5_data *rep)
{
    krb5_error_code code;
    unsigned int i;

    assert(ctx->subkey);

    code = krb5_process_tgs_response(context,
                                     rep,
                                     ctx->tgtptr,
                                     tkt_creds_kdcopt(ctx),
                                     ctx->tgtptr->addresses,
                                     NULL,
                                     &ctx->in_cred,
                                     ctx->timestamp,
                                     ctx->subkey,
                                     NULL,
                                     NULL,
                                     &ctx->out_cred);
    if (code != 0) {
        if (ctx->referral_count == 0) {
            /* Fall through to non-referral case */
            ctx->state = TKT_CREDS_FALLBACK_INITIAL_TGT;
            code = 0;
        }
        goto cleanup;
    }

    /*
     * Referral request succeeded; let's see what it is
     */
    if (krb5_principal_compare(context, ctx->in_cred.server,
                               ctx->out_cred->server)) {
        DPRINTF(("gc_from_kdc: request generated ticket "
                 "for requested server principal\n"));
        DUMP_PRINC("gc_from_kdc final referred reply",
                   in_cred->server);
        /*
         * Check if the return enctype is one that we requested if
         * needed.
         */
        if (ctx->use_conf_ktypes || !context->tgs_etypes) {
            ctx->state = TKT_CREDS_COMPLETE;
            goto cleanup;
        }
        for (i = 0; context->tgs_etypes[i]; i++) {
            if (ctx->out_cred->keyblock.enctype == context->tgs_etypes[i]) {
                /* Found an allowable etype, so we're done */
                ctx->state = TKT_CREDS_COMPLETE;
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
        if (ctx->referral_count == 0)
            r1 = &ctx->tgtptr->server->data[1];
        else
            r1 = &ctx->referral_tgts[ctx->referral_count-1]->server->data[1];

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
        if (ctx->tgtptr == &ctx->cc_tgt)
            krb5_free_cred_contents(context, ctx->tgtptr);
        ctx->tgtptr = ctx->out_cred;

        /* avoid copying authdata multiple times */
        ctx->out_cred->authdata = ctx->in_cred.authdata;
        ctx->in_cred.authdata = NULL;

        /* Save pointer to tgt in referral_tgts */
        ctx->referral_tgts[ctx->referral_count] = ctx->out_cred;
        ctx->out_cred = NULL;

        /* Copy krbtgt realm to server principal */
        krb5_free_data_contents(context, &ctx->server->realm);
        code = krb5int_copy_data_contents(context,
                                          &ctx->tgtptr->server->data[1],
                                          &ctx->server->realm);
        if (code != 0)
            goto cleanup;

        /* Future work: rewrite SPN in padata */

        ctx->state = TKT_CREDS_REFERRAL_TGT;
    } else {
        /* Not a TGT; punt to fallback */
        krb5_free_creds(context, ctx->out_cred);
        ctx->out_cred = NULL;
        ctx->state = TKT_CREDS_FALLBACK_INITIAL_TGT;
    }

cleanup:
    return code;
}

static void
tkt_creds_clean_context(krb5_context context, krb5_tkt_creds_context ctx)
{
    int i;

    if (ctx->tgtptr == &ctx->cc_tgt)
        krb5_free_cred_contents(context, ctx->tgtptr);
    ctx->tgtptr = NULL;
    if (ctx->tgtptr_isoffpath)
        krb5_free_creds(context, ctx->otgtptr);
    ctx->otgtptr = NULL;
    if (ctx->tgts != NULL) {
        for (i = 0; ctx->tgts[i] != NULL; i++) {
            krb5_free_creds(context, ctx->tgts[i]);
        }
        free(ctx->tgts);
        ctx->tgts = NULL;
    }
    context->use_conf_ktypes = 1;
}

static krb5_error_code
tkt_creds_step_request_fallback_initial_tgt(krb5_context context,
                                            krb5_tkt_creds_context ctx,
                                            krb5_data *req)
{
    krb5_error_code code;
    char **hrealms;

    DUMP_PRINC("gc_from_kdc client at fallback", ctx->client);
    DUMP_PRINC("gc_from_kdc server at fallback", ctx->server);

    /*
     * At this point referrals have been tried and have failed.  Go
     * back to the server principal as originally issued and try the
     * conventional path.
     */

    if (krb5_is_referral_realm(&ctx->in_cred.server->realm)) {
        if (ctx->server->length >= 2) {
            code = krb5_get_fallback_host_realm(context,
                                                &ctx->server->data[1],
                                                &hrealms);
            if (code != 0)
                goto cleanup;
            krb5_free_data_contents(context, &ctx->server->realm);
            ctx->server->realm.data = hrealms[0];
            ctx->server->realm.length = strlen(hrealms[0]);
            free(hrealms);
        } else {
            /*
             * Problem case: Realm tagged for referral but apparently not
             * in a <type>/<host> format that
             * krb5_get_fallback_host_realm can deal with.
             */
            DPRINTF(("gc_from_kdc: referral specified "
                     "but no fallback realm avaiable!\n"));
            code = KRB5_ERR_HOST_REALM_UNKNOWN;
            goto cleanup;
        }
    }

    DUMP_PRINC("gc_from_kdc server at fallback after fallback rewrite",
               server);

    tkt_creds_clean_context(context, ctx);

    /*
     * Get a TGT for the target realm.
     */
    code = tkt_creds_step_request_initial_tgt(context, ctx, req);

cleanup:
    return code;
}

static krb5_error_code
tkt_creds_step_reply_fallback_initial_tgt(krb5_context context,
                                          krb5_tkt_creds_context ctx,
                                          krb5_data *rep)
{
    krb5_error_code code;

    code = tkt_creds_step_reply_initial_tgt(context, ctx, rep);

    return code;
}

static krb5_error_code
tkt_creds_step_request_fallback_final_tkt(krb5_context context,
                                          krb5_tkt_creds_context ctx,
                                          krb5_data *req)
{
    krb5_error_code code;

    assert(ctx->tgtptr);
    ctx->realm = &ctx->server->realm;

    code = krb5_make_tgs_request(context,
                                 ctx->tgtptr,
                                 tkt_creds_kdcopt(ctx),
                                 ctx->tgtptr->addresses,
                                 NULL,
                                 &ctx->in_cred,
                                 NULL,
                                 NULL,
                                 req,
                                 &ctx->timestamp,
                                 &ctx->subkey);

    return code;
}

static krb5_error_code
tkt_creds_step_reply_fallback_final_tkt(krb5_context context,
                                        krb5_tkt_creds_context ctx,
                                        krb5_data *rep)
{
    krb5_error_code code;

    assert(ctx->tgtptr);

    code = krb5_process_tgs_response(context,
                                     rep,
                                     ctx->tgtptr,
                                     tkt_creds_kdcopt(ctx),
                                     ctx->tgtptr->addresses,
                                     NULL,
                                     &ctx->in_cred,
                                     ctx->timestamp,
                                     ctx->subkey,
                                     NULL,
                                     NULL,
                                     &ctx->out_cred);
    return code;
}

static krb5_error_code
tkt_creds_step_request_complete(krb5_context context,
                                krb5_tkt_creds_context ctx,
                                krb5_data *req)
{
    krb5_error_code code = 0;

    DUMP_PRINC("gc_from_kdc: final server after reversion", ctx->server);

    assert(ctx->out_cred);

    /*
     * Deal with ccache TGT management: If tgts has been set from
     * initial non-referral TGT discovery, leave it alone.  Otherwise, if
     * referral_tgts[0] exists return it as the only entry in tgts.
     * (Further referrals are never cached, only the referral from the
     * local KDC.)  This is part of cleanup because useful received TGTs
     * should be cached even if the main request resulted in failure.
     */
    if (ctx->tgts != NULL && ctx->referral_tgts[0] == NULL) {
        /* Allocate returnable TGT list. */
        ctx->tgts = calloc(2, sizeof (krb5_creds *));
        if (ctx->tgts == NULL) {

            code = ENOMEM;
            goto cleanup;
        }
        code = krb5_copy_creds(context, ctx->referral_tgts[0], &ctx->tgts[0]);
        if (code != 0)
            goto cleanup;
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
    enum krb5_tkt_creds_state state;

    context->use_conf_ktypes = 1;

    do {
        krb5_free_cred_contents(context, &ctx->tgtq);

        krb5_free_keyblock(context, ctx->subkey);
        ctx->subkey = NULL;

        switch ((state = ctx->state)) {
        case TKT_CREDS_INITIAL_TGT:
            code = tkt_creds_step_request_initial_tgt(context, ctx, req);
            break;
        case TKT_CREDS_REFERRAL_TGT:
        case TKT_CREDS_REFERRAL_TGT_NOCANON:
            code = tkt_creds_step_request_referral_tgt(context, ctx, req);
            break;
        case TKT_CREDS_FALLBACK_INITIAL_TGT:
            code = tkt_creds_step_request_fallback_initial_tgt(context, ctx, req);
            break;
        case TKT_CREDS_FALLBACK_FINAL_TKT:
            code = tkt_creds_step_request_fallback_final_tkt(context, ctx, req);
            break;
        case TKT_CREDS_COMPLETE:
            code = tkt_creds_step_request_complete(context, ctx, req);
            break;
        default:
            assert(0 && "tkt_creds_step_request invalid state");
            break;
        }
        /* If there has been a state transition, then try again. */
    } while (code == 0 && ctx->state != state);

cleanup:
    context->use_conf_ktypes = ctx->use_conf_ktypes;

    return code;
}

static krb5_error_code
tkt_creds_step_reply(krb5_context context,
                     krb5_tkt_creds_context ctx,
                     krb5_data *rep)
{
    krb5_error_code code;

    context->use_conf_ktypes = 1;

    {
        krb5_free_creds(context, ctx->out_cred);
        ctx->out_cred = NULL;

        assert(ctx->subkey);

        switch (ctx->state) {
        case TKT_CREDS_INITIAL_TGT:
            code = tkt_creds_step_reply_initial_tgt(context, ctx, rep);
            break;
        case TKT_CREDS_REFERRAL_TGT:
        case TKT_CREDS_REFERRAL_TGT_NOCANON:
            code = tkt_creds_step_reply_referral_tgt(context, ctx, rep);
            break;
        case TKT_CREDS_FALLBACK_INITIAL_TGT:
            code = tkt_creds_step_reply_fallback_initial_tgt(context, ctx, rep);
            break;
        case TKT_CREDS_FALLBACK_FINAL_TKT:
            code = tkt_creds_step_reply_fallback_final_tkt(context, ctx, rep);
            break;
        case TKT_CREDS_COMPLETE:
        default:
            assert(0 && "tkt_creds_step_reply invalid state");
            break;
        }
    }

    ctx->referral_count++;

cleanup:
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
        code = tkt_creds_step_reply(context, ctx, in);
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

    code = tkt_creds_step_request(context, ctx, out);
    if (code != 0)
        goto cleanup;

    if (ctx->state == TKT_CREDS_COMPLETE) {
        *flags = 1;
        goto cleanup;
    } else {
        assert(out->length);
    }

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

/*
 * krb5_get_cred_from_kdc_opt()
 * krb5_get_cred_from_kdc()
 * krb5_get_cred_from_kdc_validate()
 * krb5_get_cred_from_kdc_renew()
 *
 * Retrieve credentials for client IN_CRED->CLIENT, server
 * IN_CRED->SERVER, ticket flags IN_CRED->TICKET_FLAGS, possibly
 * second_ticket if needed.
 *
 * Request credentials from the KDC for the server's realm.  Point
 * TGTS to an allocated array of pointers to krb5_creds, containing
 * any intermediate credentials obtained in the process of contacting
 * the server's KDC; if no intermediate credentials were obtained,
 * TGTS is a null pointer.  Return intermediate credentials if
 * intermediate KDCs provided credentials, even if no useful end
 * ticket results.
 *
 * Caller must free TGTS, regardless of whether this function returns
 * success.
 *
 * This function does NOT cache the intermediate TGTs.
 *
 * Do not call this routine if desired credentials are already cached.
 *
 * On success, OUT_CRED contains the desired credentials; the caller
 * must free them.
 *
 * Beware memory management issues if you have modifications in mind.
 * With the addition of referral support, it is now the case that *tgts,
 * referral_tgts, tgtptr, referral_tgts, and *out_cred all may point to
 * the same credential at different times.
 *
 * Returns errors, system errors.
 */

krb5_error_code
krb5_get_cred_from_kdc_opt(krb5_context context, krb5_ccache ccache,
                           krb5_creds *in_cred, krb5_creds **out_cred,
                           krb5_creds ***tgts, int kdcopt)
{
    krb5_error_code code;
    krb5_tkt_creds_context ctx = NULL;

    code = krb5_tkt_creds_init(context, ccache, in_cred, kdcopt, &ctx);
    if (code != 0)
        goto cleanup;

    code = krb5_tkt_creds_get(context, ctx);
    if (code != 0)
        goto cleanup;

    *out_cred = ctx->out_cred;
    ctx->out_cred = NULL;

cleanup:
    if (ctx != NULL) {
        *tgts = ctx->tgts;
        ctx->tgts = NULL;
    }

    krb5_tkt_creds_free(context, ctx);

    return code;
}

krb5_error_code
krb5_get_cred_from_kdc(krb5_context context, krb5_ccache ccache,
                       krb5_creds *in_cred, krb5_creds **out_cred,
                       krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
                                      0);
}

krb5_error_code
krb5_get_cred_from_kdc_validate(krb5_context context, krb5_ccache ccache,
                                krb5_creds *in_cred, krb5_creds **out_cred,
                                krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
                                      KDC_OPT_VALIDATE);
}

krb5_error_code
krb5_get_cred_from_kdc_renew(krb5_context context, krb5_ccache ccache,
                             krb5_creds *in_cred, krb5_creds **out_cred,
                             krb5_creds ***tgts)
{
    return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
                                      KDC_OPT_RENEW);
}
