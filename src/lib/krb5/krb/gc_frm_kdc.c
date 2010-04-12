/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/gc_frm_kdc.c
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
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
 * Neither M.I.T., the Open Computing Security Group, nor
 * CyberSAFE Corporation make any representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * krb5_tkt_creds_step() and related functions:
 *
 * Get credentials from some KDC somewhere, possibly getting (and caching)
 * cross-realm TGTs along the way, and possibly following referrals to other
 * realms.  This is an asynchronous API; it is used by the synchronous API
 * krb5_get_credentials().
 */

#include "k5-int.h"
#include <stdio.h>
#include "int-proto.h"

/*
 * krb5_tkt_creds_step() is implemented using a tail call style.  Every
 * begin_*, step_*, or *_request function is responsible for returning an
 * error, generating the next request, or delegating to another function using
 * a tail call.
 *
 * The process is divided up into states which govern how the next input token
 * should be interpreted.  Each state has a "begin_<state>" function to set up
 * the context fields related to the state, a "step_<state>" function to
 * process a reply and update the related context fields, and possibly a
 * "<state>_request" function (invoked by the begin_ and step_ functions) to
 * generate the next request.  If it's time to advance to another state, any of
 * the three functions can make a tail call to begin_<nextstate> to do so.
 *
 * The overall process is as follows:
 *   1. Get a TGT for the service principal's realm (STATE_GET_TGT).
 *   2. Make one or more referrals queries (STATE_REFERRALS).
 *   3. In some cases, get a TGT for the fallback realm (STATE_GET_TGT again).
 *   4. In some cases, make a non-referral query (STATE_NON_REFERRAL).
 *
 * STATE_GET_TGT can precede either STATE_REFERRALS or STATE_NON_REFERRAL.  The
 * getting_tgt_for field in the context keeps track of what state we will go to
 * after successfully obtaining the TGT, and the end_get_tgt() function
 * advances to the proper next state.
 */

enum state {
    STATE_BEGIN,                /* Initial step (no input token) */
    STATE_GET_TGT,              /* Getting TGT for service realm */
    STATE_GET_TGT_OFFPATH,      /* Getting TGT via off-path referrals */
    STATE_REFERRALS,            /* Retrieving service ticket or referral */
    STATE_NON_REFERRAL,         /* Non-referral service ticket request */
    STATE_COMPLETE              /* Creds ready for retrieval */
};

struct _krb5_tkt_creds_context {
    enum state state;           /* What we should do with the next reply */
    enum state getting_tgt_for; /* STATE_REFERRALS or STATE_NON_REFERRAL */

    /* The following fields are set up at initialization time. */
    krb5_creds *in_creds;       /* Creds requested by caller */
    krb5_principal client;      /* Caller-requested client principal (alias) */
    krb5_principal server;      /* Server principal (alias) */
    krb5_principal req_server;  /* Caller-requested server principal */
    krb5_ccache ccache;         /* Caller-provided ccache (alias) */
    int req_kdcopt;             /* Caller-requested KDC options */
    krb5_authdata **authdata;   /* Caller-requested authdata */

    /* The following fields are used in multiple steps. */
    krb5_creds *cur_tgt;        /* TGT to be used for next query */
    krb5_data *realms_seen;     /* For loop detection */
    krb5_error_code cache_code; /* KRB5_CC_NOTFOUND or KRB5_CC_NOT_KTYPE */

    /* The following fields track state between request and reply. */
    krb5_principal tgt_princ;   /* Storage for TGT principal */
    krb5_creds tgt_in_creds;    /* Container for TGT matching creds */
    krb5_creds *tgs_in_creds;   /* Input credentials of request (alias) */
    krb5_timestamp timestamp;   /* Timestamp of request */
    krb5_int32 nonce;           /* Nonce of request */
    int kdcopt;                 /* KDC options of request */
    krb5_keyblock *subkey;      /* subkey of request */
    krb5_data previous_request; /* Encoded request (for TCP retransmission) */

    /* The following fields are used when acquiring foreign TGTs. */
    krb5_data *realm_path;      /* Path from client to server realm */
    const krb5_data *last_realm;/* Last realm in realm_path */
    const krb5_data *cur_realm; /* Position of cur_tgt in realm_path  */
    const krb5_data *next_realm;/* Current target realm in realm_path */
    unsigned int offpath_count; /* Offpath requests made */

    /* The following fields are used during the referrals loop. */
    unsigned int referral_count;/* Referral requests made */

    /* The following fields are used within a _step call to avoid
     * passing them as parameters everywhere. */
    krb5_creds *reply_creds;    /* Creds from TGS reply */
    krb5_error_code reply_code; /* Error status from TGS reply */
    krb5_data *caller_out;      /* Caller's out parameter */
    krb5_data *caller_realm;    /* Caller's realm parameter */
    unsigned int *caller_flags; /* Caller's flags parameter */
};

/* Convert ticket flags to necessary KDC options */
#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

static krb5_error_code
begin_get_tgt(krb5_context context, krb5_tkt_creds_context ctx);

/*
 * Fill in the caller out, realm, and flags output variables.  out is filled in
 * with ctx->previous_request, which the caller should set, and realm is filled
 * in with the realm of ctx->cur_tgt.
 */
static krb5_error_code
set_caller_request(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    const krb5_data *req = &ctx->previous_request;
    const krb5_data *realm = &ctx->cur_tgt->server->data[1];
    krb5_data out_copy = empty_data(), realm_copy = empty_data();

    code = krb5int_copy_data_contents(context, req, &out_copy);
    if (code != 0)
        goto cleanup;
    code = krb5int_copy_data_contents(context, realm, &realm_copy);
    if (code != 0)
        goto cleanup;

    *ctx->caller_out = out_copy;
    *ctx->caller_realm = realm_copy;
    *ctx->caller_flags = 1;
    return 0;

cleanup:
    krb5_free_data_contents(context, &out_copy);
    krb5_free_data_contents(context, &realm_copy);
    return code;
}

/* Simple wrapper around krb5_cc_retrieve_cred which allocates the result
 * container. */
static krb5_error_code
cache_get(krb5_context context, krb5_ccache ccache, krb5_flags flags,
          krb5_creds *in_creds, krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds *creds;

    *out_creds = NULL;

    creds = malloc(sizeof(*creds));
    if (creds == NULL)
        return ENOMEM;

    code = krb5_cc_retrieve_cred(context, ccache, flags, in_creds, creds);
    if (code != 0) {
        free(creds);
        return code;
    }

    *out_creds = creds;
    return 0;
}

/*
 * Point *TGT at an allocated credentials structure containing a TGT for realm
 * retrieved from ctx->ccache.  If we are retrieving a foreign TGT, accept any
 * issuing realm (i.e. match only the service principal name).  If the TGT is
 * not found in the cache, return successfully but set *tgt to NULL.
 */
static krb5_error_code
get_cached_tgt(krb5_context context, krb5_tkt_creds_context ctx,
               const krb5_data *realm, krb5_creds **tgt)
{
    krb5_creds mcreds;
    krb5_error_code code;
    krb5_principal tgtname = NULL;
    krb5_flags flags;
    krb5_boolean local_realm = data_eq(*realm, ctx->client->realm);

    *tgt = NULL;

    /* Construct the principal krbtgt/<realm>@<client realm>.  The realm
     * won't matter unless we're getting the local TGT. */
    code = krb5int_tgtname(context, realm, &ctx->client->realm, &tgtname);
    if (code != 0)
        goto cleanup;

    /* Match the TGT realm only if we're getting the local TGT. */
    flags = KRB5_TC_SUPPORTED_KTYPES;
    if (local_realm)
        flags |= KRB5_TC_MATCH_SRV_NAMEONLY;

    /* Construct a matching cred for the ccache query. */
    memset(&mcreds, 0, sizeof(mcreds));
    mcreds.client = ctx->client;
    mcreds.server = tgtname;

    /* Fetch the TGT credential. */
    context->use_conf_ktypes = TRUE;
    code = cache_get(context, ctx->ccache, flags, &mcreds, tgt);
    context->use_conf_ktypes = FALSE;

    /* Handle not-found errors.  Make a note if we couldn't find a local TGT
     * because of enctypes. */
    if (local_realm && code == KRB5_CC_NOT_KTYPE)
        ctx->cache_code = KRB5_CC_NOT_KTYPE;
    if (code != 0 && code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
        goto cleanup;
    code = 0;

cleanup:
    krb5_free_principal(context, tgtname);
    return code;
}

/*
 * Set up the request given by ctx->tgs_in_creds, using ctx->cur_tgt.  KDC
 * options for the requests are determined by ctx->cur_tgt->ticket_flags and
 * extra_options.
 */
static krb5_error_code
make_request(krb5_context context, krb5_tkt_creds_context ctx,
             int extra_options)
{
    krb5_error_code code;
    krb5_data request = empty_data();

    ctx->kdcopt = extra_options | FLAGS2OPTS(ctx->cur_tgt->ticket_flags);

    /* XXX This check belongs in gc_via_tgt.c or nowhere. */
    if (!krb5_c_valid_enctype(ctx->cur_tgt->keyblock.enctype))
        return KRB5_PROG_ETYPE_NOSUPP;

    code = krb5int_make_tgs_request(context, ctx->cur_tgt, ctx->kdcopt,
                                    ctx->cur_tgt->addresses, NULL,
                                    ctx->tgs_in_creds, NULL, NULL, &request,
                                    &ctx->timestamp, &ctx->nonce,
                                    &ctx->subkey);
    if (code != 0)
        return code;

    krb5_free_data_contents(context, &ctx->previous_request);
    ctx->previous_request = request;
    return set_caller_request(context, ctx);
}

/* Set up a request for a TGT for realm, using ctx->cur_tgt. */
static krb5_error_code
make_request_for_tgt(krb5_context context, krb5_tkt_creds_context ctx,
                     const krb5_data *realm)
{
    krb5_error_code code;

    /* Construct the principal krbtgt/<realm>@<cur-tgt-realm>. */
    krb5_free_principal(context, ctx->tgt_princ);
    ctx->tgt_princ = NULL;
    code = krb5int_tgtname(context, realm, &ctx->cur_tgt->server->realm,
                           &ctx->tgt_princ);
    if (code != 0)
        return code;

    /* Construct input creds using ctx->tgt_in_creds as a container. */
    memset(&ctx->tgt_in_creds, 0, sizeof(ctx->tgt_in_creds));
    ctx->tgt_in_creds.client = ctx->client;
    ctx->tgt_in_creds.server = ctx->tgt_princ;

    /* Make a request for the above creds with no extra options. */
    ctx->tgs_in_creds = &ctx->tgt_in_creds;
    code = make_request(context, ctx, 0);
    return code;
}

/* Set up a request for the desired service principal, using ctx->cur_tgt.
 * Optionally allow the answer to be a referral. */
static krb5_error_code
make_request_for_service(krb5_context context, krb5_tkt_creds_context ctx,
                         krb5_boolean referral)
{
    krb5_error_code code;
    int extra_options;

    /* Include the caller-specified KDC options in service requests. */
    extra_options = ctx->req_kdcopt;

    /* Automatically set the enc-tkt-in-skey flag for user-to-user requests. */
    if (ctx->in_creds->second_ticket.length != 0 &&
        (extra_options & KDC_OPT_CNAME_IN_ADDL_TKT) == 0)
        extra_options |= KDC_OPT_ENC_TKT_IN_SKEY;

    /* Set the canonicalize flag for referral requests. */
    if (referral)
        extra_options |= KDC_OPT_CANONICALIZE;

    /*
     * Use the profile enctypes for referral requests, since we might get back
     * a TGT.  We'll ask again with context enctypes if we get the actual
     * service ticket and it's not consistent with the context enctypes.
     */
    if (referral)
        context->use_conf_ktypes = TRUE;
    ctx->tgs_in_creds = ctx->in_creds;
    code = make_request(context, ctx, extra_options);
    if (referral)
        context->use_conf_ktypes = FALSE;
    return code;
}

/* Decode and decrypt a TGS reply, and set the reply_code or reply_creds field
 * of ctx with the result.  Also handle too-big errors. */
static krb5_error_code
get_creds_from_tgs_reply(krb5_context context, krb5_tkt_creds_context ctx,
                         krb5_data *reply)
{
    krb5_error_code code;

    krb5_free_creds(context, ctx->reply_creds);
    ctx->reply_creds = NULL;
    code = krb5int_process_tgs_reply(context, reply, ctx->cur_tgt, ctx->kdcopt,
                                     ctx->cur_tgt->addresses, NULL,
                                     ctx->tgs_in_creds, ctx->timestamp,
                                     ctx->nonce, ctx->subkey, NULL, NULL,
                                     &ctx->reply_creds);
    if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG) {
        /* Instruct the caller to re-send the request with TCP. */
        code = set_caller_request(context, ctx);
        if (code != 0)
            return code;
        return KRB5KRB_ERR_RESPONSE_TOO_BIG;
    }

    /* Depending on our state, we may or may not be able to handle an error.
     * For now, store it in the context and return success. */
    ctx->reply_code = code;
    return 0;
}

/* Add realm to ctx->realms_seen so that we can avoid revisiting it later. */
static krb5_error_code
remember_realm(krb5_context context, krb5_tkt_creds_context ctx,
               const krb5_data *realm)
{
    size_t len = 0;
    krb5_data *new_list;

    if (ctx->realms_seen != NULL) {
        for (len = 0; ctx->realms_seen[len].data != NULL; len++);
    }
    new_list = realloc(ctx->realms_seen, (len + 2) * sizeof(krb5_data));
    if (new_list == NULL)
        return ENOMEM;
    ctx->realms_seen = new_list;
    new_list[len] = empty_data();
    new_list[len + 1] = empty_data();
    return krb5int_copy_data_contents(context, realm, &new_list[len]);
}

/* Return TRUE if realm appears to ctx->realms_seen. */
static krb5_boolean
seen_realm_before(krb5_context context, krb5_tkt_creds_context ctx,
                  const krb5_data *realm)
{
    size_t i;

    if (ctx->realms_seen != NULL) {
        for (i = 0; ctx->realms_seen[i].data != NULL; i++) {
            if (data_eq(ctx->realms_seen[i], *realm))
                return TRUE;
        }
    }
    return FALSE;
}

/***** STATE_NON_REFERRAL *****/

/* Process the response to a non-referral request. */
static krb5_error_code
step_non_referral(krb5_context context, krb5_tkt_creds_context ctx)
{
    /* No fallbacks if we didn't get a successful reply. */
    if (ctx->reply_code)
        return ctx->reply_code;

    /* Note the authdata we asked for in the output creds. */
    ctx->reply_creds->authdata = ctx->authdata;
    ctx->authdata = NULL;
    ctx->state = STATE_COMPLETE;
    return 0;
}

/* Make a non-referrals request for the desired service ticket. */
static krb5_error_code
begin_non_referral(krb5_context context, krb5_tkt_creds_context ctx)
{
    ctx->state = STATE_NON_REFERRAL;
    return make_request_for_service(context, ctx, FALSE);
}

/***** STATE_REFERRALS *****/

/*
 * Possibly retry a request in the fallback realm after a referral request
 * failure in the local realm.  Expects ctx->reply_code to be set to the error
 * from a referral request.
 */
static krb5_error_code
try_fallback_realm(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    char **hrealms;

    /* Only fall back if our error was from the first referral request. */
    if (ctx->referral_count > 1)
        return ctx->reply_code;

    /* Only fall back if the original request used the referral realm. */
    if (!krb5_is_referral_realm(&ctx->req_server->realm))
        return ctx->reply_code;

    if (ctx->server->length < 2) {
        /* We need a type/host format principal to find a fallback realm. */
        return KRB5_ERR_HOST_REALM_UNKNOWN;
    }

    /* We expect this to give exactly one answer (XXX clean up interface). */
    code = krb5_get_fallback_host_realm(context, &ctx->server->data[1],
                                        &hrealms);
    if (code != 0)
        return code;

    /* Give up if the fallback realm isn't any different. */
    if (data_eq_string(ctx->server->realm, hrealms[0]))
        return ctx->reply_code;

    /* Rewrite server->realm to be the fallback realm. */
    krb5_free_data_contents(context, &ctx->server->realm);
    ctx->server->realm = string2data(hrealms[0]);
    free(hrealms);

    /* Obtain a TGT for the new service realm. */
    ctx->getting_tgt_for = STATE_NON_REFERRAL;
    return begin_get_tgt(context, ctx);
}

/* Return true if context contains app-provided TGS enctypes and enctype is not
 * one of them. */
static krb5_boolean
wrong_enctype(krb5_context context, krb5_enctype enctype)
{
    size_t i;

    if (context->tgs_etypes == NULL)
        return FALSE;
    for (i = 0; context->tgs_etypes[i] != 0; i++) {
        if (enctype == context->tgs_etypes[i])
            return FALSE;
    }
    return TRUE;
}

/* Advance the referral request loop. */
static krb5_error_code
step_referrals(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    const krb5_data *referral_realm;

    /* Possibly retry with the fallback realm on error. */
    if (ctx->reply_code != 0)
        return try_fallback_realm(context, ctx);

    if (krb5_principal_compare(context, ctx->reply_creds->server,
                               ctx->server)) {
        /* We got the ticket we asked for... but we didn't necessarily ask for
         * it with the right enctypes.  Try a non-referral request if so. */
        if (wrong_enctype(context, ctx->reply_creds->keyblock.enctype))
            return begin_non_referral(context, ctx);

        /* Note the authdata we asked for in the output creds. */
        ctx->reply_creds->authdata = ctx->authdata;
        ctx->authdata = NULL;
        ctx->state = STATE_COMPLETE;
        return 0;
    }

    /* Old versions of Active Directory can rewrite the server name instead of
     * returning a referral.  Try a non-referral query if we see this. */
    if (!IS_TGS_PRINC(context, ctx->reply_creds->server))
        return begin_non_referral(context, ctx);

    if (ctx->referral_count == 1) {
        /* Cache the referral TGT only if it's from the local realm.
         * Make sure to note the associated authdata, if any. */
        code = krb5_copy_authdata(context, ctx->authdata,
                                  &ctx->reply_creds->authdata);
        if (code != 0)
            return code;
        code = krb5_cc_store_cred(context, ctx->ccache, ctx->reply_creds);
        if (code != 0)
            return code;

        /* The authdata in this TGT will be copied into subsequent TGTs or the
         * final credentials, so we don't need to request it again. */
        krb5_free_authdata(context, ctx->in_creds->authdata);
        ctx->in_creds->authdata = NULL;
    }

    /* Give up if we've gotten too many referral TGTs. */
    if (ctx->referral_count++ >= KRB5_REFERRAL_MAXHOPS)
        return KRB5_KDC_UNREACH;

    /* Check for referral loops. */
    referral_realm = &ctx->reply_creds->server->data[1];
    if (seen_realm_before(context, ctx, referral_realm))
        return KRB5_KDC_UNREACH;
    code = remember_realm(context, ctx, referral_realm);
    if (code != 0)
        return code;

    /* Use the referral TGT for the next request. */
    krb5_free_creds(context, ctx->cur_tgt);
    ctx->cur_tgt = ctx->reply_creds;
    ctx->reply_creds = NULL;

    /* Rewrite the server realm to be the referral realm. */
    krb5_free_data_contents(context, &ctx->server->realm);
    code = krb5int_copy_data_contents(context, referral_realm,
                                      &ctx->server->realm);
    if (code != 0)
        return code;

    /* Generate the next referral request. */
    return make_request_for_service(context, ctx, TRUE);
}

/*
 * Begin the referrals request loop.  Expects ctx->cur_tgt to be a TGT for
 * ctx->realm->server.
 */
static krb5_error_code
begin_referrals(krb5_context context, krb5_tkt_creds_context ctx)
{
    ctx->state = STATE_REFERRALS;
    ctx->referral_count = 1;

    /* Empty out the realms-seen list for loop checking. */
    krb5int_free_data_list(context, ctx->realms_seen);
    ctx->realms_seen = NULL;

    /* Generate the first referral request. */
    return make_request_for_service(context, ctx, TRUE);
}

/***** STATE_GET_TGT_OFFPATH *****/

/*
 * Foreign TGT acquisition can happen either before the referrals loop, if the
 * service principal had an explicitly specified foreign realm, or after it
 * fails, if we wind up using the fallback realm.  end_get_tgt() advances to
 * the appropriate state depending on which we were doing.
 */
static krb5_error_code
end_get_tgt(krb5_context context, krb5_tkt_creds_context ctx)
{
    if (ctx->getting_tgt_for == STATE_REFERRALS)
        return begin_referrals(context, ctx);
    else
        return begin_non_referral(context, ctx);
}

/*
 * We enter STATE_GET_TGT_OFFPATH from STATE_GET_TGT if we receive, from one of
 * the KDCs in the expected path, a TGT for a realm not in the path.  This may
 * happen if the KDC has a different idea of the expected path than we do.  If
 * it happens, we repeatedly ask the KDC of the TGT we have for a destination
 * realm TGT, until we get it, fail, or give up.
 */

/* Advance the process of chasing off-path TGTs. */
static krb5_error_code
step_get_tgt_offpath(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    const krb5_data *tgt_realm;

    /* We have no fallback if the last request failed, so just give up. */
    if (ctx->reply_code != 0)
        return ctx->reply_code;

    /* Verify that we got a TGT. */
    if (!IS_TGS_PRINC(context, ctx->reply_creds->server))
        return KRB5_KDCREP_MODIFIED;

    /* Use this tgt for the next request. */
    krb5_free_creds(context, ctx->cur_tgt);
    ctx->cur_tgt = ctx->reply_creds;
    ctx->reply_creds = NULL;

    /* Check if we've seen this realm before, and remember it. */
    tgt_realm = &ctx->cur_tgt->server->data[1];
    if (seen_realm_before(context, ctx, tgt_realm))
        return KRB5_KDC_UNREACH;
    code = remember_realm(context, ctx, tgt_realm);
    if (code != 0)
        return code;

    if (data_eq(*tgt_realm, ctx->server->realm)) {
        /* We received the server realm TGT we asked for. */
        return end_get_tgt(context, ctx);
    } else if (ctx->offpath_count++ >= KRB5_REFERRAL_MAXHOPS) {
        /* Time to give up. */
        return KRB5_KDCREP_MODIFIED;
    }

    return make_request_for_tgt(context, ctx, &ctx->server->realm);
}

/* Begin chasing off-path referrals, starting from ctx->cur_tgt. */
static krb5_error_code
begin_get_tgt_offpath(krb5_context context, krb5_tkt_creds_context ctx)
{
    ctx->state = STATE_GET_TGT_OFFPATH;
    ctx->offpath_count = 1;
    return make_request_for_tgt(context, ctx, &ctx->server->realm);
}

/***** STATE_GET_TGT *****/

/*
 * To obtain a foreign TGT, we first construct a path of realms R1..Rn between
 * the local realm and the target realm, using krb5_walk_realm_tree().  Usually
 * this path is based on the domain hierarchy, but it may be altered by
 * configuration.
 *
 * We begin with cur_realm set to the local realm (R1) and next_realm set to
 * the target realm (Rn).  At each step, we check to see if we have a cached
 * TGT for next_realm; if not, we ask cur_realm to give us a TGT for
 * next_realm.  If that fails, we decrement next_realm until we get a
 * successful answer or reach cur_realm--in which case we've gotten as far as
 * we can, and have to give up.  If we do get back a TGT, it may or may not be
 * for the realm we asked for, so we search for it in the path.  The realm of
 * the TGT we get back becomes cur_realm, and next_realm is reset to the target
 * realm.  Overall, this is an O(n^2) process in the length of the path, but
 * the path length will generally be short and the process will usually end
 * much faster than the worst case.
 *
 * In some cases we may get back a TGT for a realm not in the path.  In that
 * case we enter STATE_GET_TGT_OFFPATH.
 */

/* Initialize the realm path fields for getting a TGT for
 * ctx->server->realm. */
static krb5_error_code
init_realm_path(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    krb5_principal *tgt_princ_list = NULL;
    krb5_data *realm_path;
    size_t nrealms, i;

    /* Construct a list of TGT principals from client to server.  We will throw
     * this away after grabbing the remote realms from each principal. */
    code = krb5_walk_realm_tree(context, &ctx->client->realm,
                                &ctx->server->realm,
                                &tgt_princ_list, KRB5_REALM_BRANCH_CHAR);
    if (code != 0)
        return code;

    /* Count the number of principals and allocate the realm path. */
    for (nrealms = 0; tgt_princ_list[nrealms]; nrealms++);
    assert(nrealms > 1);
    realm_path = k5alloc((nrealms + 1) * sizeof(*realm_path), &code);
    if (realm_path == NULL)
        goto cleanup;

    /* Steal the remote realm field from each TGT principal. */
    for (i = 0; i < nrealms; i++) {
        assert(tgt_princ_list[i]->length == 2);
        realm_path[i] = tgt_princ_list[i]->data[1];
        tgt_princ_list[i]->data[1].data = NULL;
    }
    realm_path[nrealms] = empty_data();

    /* Initialize the realm path fields in ctx. */
    krb5int_free_data_list(context, ctx->realm_path);
    ctx->realm_path = realm_path;
    ctx->last_realm = realm_path + nrealms - 1;
    ctx->cur_realm = realm_path;
    ctx->next_realm = ctx->last_realm;
    realm_path = NULL;

cleanup:
    krb5_free_realm_tree(context, tgt_princ_list);
    return 0;
}

/* Find realm within the portion of ctx->realm_path following
 * ctx->cur_realm.  Return NULL if it is not found. */
static const krb5_data *
find_realm_in_path(krb5_context context, krb5_tkt_creds_context ctx,
                   const krb5_data *realm)
{
    const krb5_data *r;

    for (r = ctx->cur_realm + 1; r->data != NULL; r++) {
        if (data_eq(*r, *realm))
            return r;
    }
    return NULL;
}

/*
 * Generate the next request in the path traversal.  If a cached TGT for the
 * target realm appeared in the ccache since we started the TGT acquisition
 * process, this function may invoke end_get_tgt().
 */
static krb5_error_code
get_tgt_request(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    krb5_creds *cached_tgt;

    while (1) {
        /* Check if we have a cached TGT for the target realm. */
        code = get_cached_tgt(context, ctx, ctx->next_realm, &cached_tgt);
        if (code != 0)
            return code;
        if (cached_tgt != NULL) {
            /* Advance the current realm and keep going. */
            krb5_free_creds(context, ctx->cur_tgt);
            ctx->cur_tgt = cached_tgt;
            if (ctx->next_realm == ctx->last_realm)
                return end_get_tgt(context, ctx);
            ctx->cur_realm = ctx->next_realm;
            ctx->next_realm = ctx->last_realm;
            continue;
        }

        return make_request_for_tgt(context, ctx, ctx->next_realm);
    }
}

/* Process a TGS reply and advance the path traversal to get a foreign TGT. */
static krb5_error_code
step_get_tgt(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    const krb5_data *tgt_realm, *path_realm;

    if (ctx->reply_code != 0) {
        /* The last request failed.  Try the next-closest realm to
         * ctx->cur_realm. */
        ctx->next_realm--;
        if (ctx->next_realm == ctx->cur_realm) {
            /* We've tried all the realms we could and couldn't progress beyond
             * ctx->cur_realm, so it's time to give up. */
            return ctx->reply_code;
        }
    } else {
        /* Verify that we got a TGT. */
        if (!IS_TGS_PRINC(context, ctx->reply_creds->server))
            return KRB5_KDCREP_MODIFIED;

        /* Use this tgt for the next request regardless of what it is. */
        krb5_free_creds(context, ctx->cur_tgt);
        ctx->cur_tgt = ctx->reply_creds;
        ctx->reply_creds = NULL;

        /* Remember that we saw this realm. */
        tgt_realm = &ctx->cur_tgt->server->data[1];
        code = remember_realm(context, ctx, tgt_realm);
        if (code != 0)
            return code;

        /* See where we wound up on the path (or off it). */
        path_realm = find_realm_in_path(context, ctx, tgt_realm);
        if (path_realm != NULL) {
            /* We got a realm on the expected path, so we can cache it. */
            code = krb5_cc_store_cred(context, ctx->ccache, ctx->cur_tgt);
            if (code != 0)
                return code;
            if (path_realm == ctx->last_realm) {
                /* We received a TGT for the target realm. */
                return end_get_tgt(context, ctx);
            } else if (path_realm != NULL) {
                /* We still have further to go; advance the traversal. */
                ctx->cur_realm = path_realm;
                ctx->next_realm = ctx->last_realm;
            }
        } else if (data_eq(*tgt_realm, ctx->client->realm)) {
            /* We were referred back to the local realm, which is bad. */
            return KRB5_KDCREP_MODIFIED;
        } else {
            /* We went off the path; start the off-path chase. */
            return begin_get_tgt_offpath(context, ctx);
        }
    }

    /* Generate the next request in the path traversal. */
    return get_tgt_request(context, ctx);
}

/*
 * Begin the process of getting a foreign TGT, either for the explicitly
 * specified server realm or for the fallback realm.  Expects that
 * ctx->server->realm is the realm of the desired TGT, and that
 * ctx->getting_tgt_for is the state we should advance to after we have the
 * desired TGT.
 */
static krb5_error_code
begin_get_tgt(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;
    krb5_creds *cached_tgt;

    ctx->state = STATE_GET_TGT;

    /* See if we have a cached TGT for the server realm. */
    code = get_cached_tgt(context, ctx, &ctx->server->realm, &cached_tgt);
    if (code != 0)
        return code;
    if (cached_tgt != NULL) {
        krb5_free_creds(context, ctx->cur_tgt);
        ctx->cur_tgt = cached_tgt;
        return end_get_tgt(context, ctx);
    }

    /* Initialize the realm path. */
    code = init_realm_path(context, ctx);
    if (code != 0)
        return code;

    /* Start with the local tgt. */
    krb5_free_creds(context, ctx->cur_tgt);
    ctx->cur_tgt = NULL;
    code = get_cached_tgt(context, ctx, &ctx->client->realm, &ctx->cur_tgt);
    if (code != 0)
        return code;
    if (ctx->cur_tgt == NULL)
        return ctx->cache_code;

    /* Empty out the realms-seen list for loop checking. */
    krb5int_free_data_list(context, ctx->realms_seen);
    ctx->realms_seen = NULL;

    /* Generate the first request. */
    return get_tgt_request(context, ctx);
}

/***** STATE_BEGIN *****/

static krb5_error_code
begin(krb5_context context, krb5_tkt_creds_context ctx)
{
    krb5_error_code code;

    /* If the server realm is unspecified, start with the client realm. */
    if (krb5_is_referral_realm(&ctx->server->realm)) {
        krb5_free_data_contents(context, &ctx->server->realm);
        code = krb5int_copy_data_contents(context, &ctx->client->realm,
                                          &ctx->server->realm);
        if (code != 0)
            return code;
    }

    /* Obtain a TGT for the service realm. */
    ctx->getting_tgt_for = STATE_REFERRALS;
    return begin_get_tgt(context, ctx);
}

/***** API functions *****/

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_init(krb5_context context, krb5_ccache ccache,
                    krb5_creds *in_creds, int kdcopt,
                    krb5_tkt_creds_context *pctx)
{
    krb5_error_code code;
    krb5_tkt_creds_context ctx = NULL;

    ctx = k5alloc(sizeof(*ctx), &code);
    if (ctx == NULL)
        goto cleanup;

    ctx->state = STATE_BEGIN;
    ctx->cache_code = KRB5_CC_NOTFOUND;

    code = krb5_copy_creds(context, in_creds, &ctx->in_creds);
    if (code != 0)
        goto cleanup;
    ctx->client = ctx->in_creds->client;
    ctx->server = ctx->in_creds->server;
    code = krb5_copy_principal(context, ctx->server, &ctx->req_server);
    if (code != 0)
        goto cleanup;
    code = krb5_cc_dup(context, ccache, &ctx->ccache);
    if (code != 0)
        goto cleanup;
    ctx->req_kdcopt = kdcopt;
    code = krb5_copy_authdata(context, in_creds->authdata, &ctx->authdata);
    if (code != 0)
        goto cleanup;

    *pctx = ctx;
    ctx = NULL;

cleanup:
    krb5_tkt_creds_free(context, ctx);
    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_get_creds(krb5_context context, krb5_tkt_creds_context ctx,
                         krb5_creds *creds)
{
    if (ctx->state != STATE_COMPLETE)
        return KRB5_NO_TKT_SUPPLIED;
    return krb5int_copy_creds_contents(context, ctx->reply_creds, creds);
}

/* Store credentials in credentials cache.  If ccache is NULL, the
 * credentials cache associated with the context is used. */
krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_store_creds(krb5_context context, krb5_tkt_creds_context ctx,
                           krb5_ccache ccache)
{
    if (ctx->state != STATE_COMPLETE)
        return KRB5_NO_TKT_SUPPLIED;
    if (ccache == NULL)
        ccache = ctx->ccache;
    return krb5_cc_store_cred(context, ccache, ctx->reply_creds);
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

void KRB5_CALLCONV
krb5_tkt_creds_free(krb5_context context, krb5_tkt_creds_context ctx)
{
    if (ctx == NULL)
        return;
    krb5_free_creds(context, ctx->in_creds);
    krb5_cc_close(context, ctx->ccache);
    krb5_free_principal(context, ctx->req_server);
    krb5_free_authdata(context, ctx->authdata);
    krb5_free_creds(context, ctx->cur_tgt);
    krb5int_free_data_list(context, ctx->realms_seen);
    krb5_free_principal(context, ctx->tgt_princ);
    krb5_free_keyblock(context, ctx->subkey);
    krb5_free_data_contents(context, &ctx->previous_request);
    krb5int_free_data_list(context, ctx->realm_path);
    krb5_free_creds(context, ctx->reply_creds);
    free(ctx);
}

krb5_error_code
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
        if (code == KRB5KRB_ERR_RESPONSE_TOO_BIG && !tcp_only)
            tcp_only = 1;
        else if (code != 0 || (flags & 1) == 0)
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

krb5_error_code KRB5_CALLCONV
krb5_tkt_creds_step(krb5_context context, krb5_tkt_creds_context ctx,
                    krb5_data *in, krb5_data *out, krb5_data *realm,
                    unsigned int *flags)
{
    krb5_error_code code;
    krb5_boolean no_input = (in == NULL || in->length == 0);

    *out = empty_data();
    *realm = empty_data();
    *flags = 0;

    /* We should receive an empty input on the first step only, and should not
     * get called after completion. */
    if (no_input != (ctx->state == STATE_BEGIN) ||
        ctx->state == STATE_COMPLETE)
        return EINVAL;

    ctx->caller_out = out;
    ctx->caller_realm = realm;
    ctx->caller_flags = flags;

    if (!no_input) {
        /* Convert the input token into a credential and store it in ctx. */
        code = get_creds_from_tgs_reply(context, ctx, in);
        if (code != 0)
            return code;
    }

    if (ctx->state == STATE_BEGIN)
        return begin(context, ctx);
    else if (ctx->state == STATE_GET_TGT)
        return step_get_tgt(context, ctx);
    else if (ctx->state == STATE_GET_TGT_OFFPATH)
        return step_get_tgt_offpath(context, ctx);
    else if (ctx->state == STATE_REFERRALS)
        return step_referrals(context, ctx);
    else if (ctx->state == STATE_NON_REFERRAL)
        return step_non_referral(context, ctx);
    else
        return EINVAL;
}
