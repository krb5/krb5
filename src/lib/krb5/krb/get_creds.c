/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/get_creds.c
 *
 * Copyright 1990, 2008 by the Massachusetts Institute of Technology.
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
 *
 * krb5_get_credentials()
 */



/*
  Attempts to use the credentials cache or TGS exchange to get an additional
  ticket for the
  client identified by in_creds->client, the server identified by
  in_creds->server, with options options, expiration date specified in
  in_creds->times.endtime (0 means as long as possible), session key type
  specified in in_creds->keyblock.enctype (if non-zero)

  Any returned ticket and intermediate ticket-granting tickets are
  stored in ccache.

  returns errors from encryption routines, system errors
*/

#include "k5-int.h"
#include "int-proto.h"

/* Using the krb5_tkt_creds interface, get credentials matching in_creds from
 * the KDC using the credentials in ccache. */
static krb5_error_code
get_tkt_creds(krb5_context context, krb5_ccache ccache, krb5_creds *in_creds,
              int kdcopt, krb5_creds *creds)
{
    krb5_error_code retval;
    krb5_tkt_creds_context ctx = NULL;

    retval = krb5_tkt_creds_init(context, ccache, in_creds, kdcopt, &ctx);
    if (retval != 0)
        goto cleanup;
    retval = krb5_tkt_creds_get(context, ctx);
    if (retval != 0)
        goto cleanup;
    retval = krb5_tkt_creds_get_creds(context, ctx, creds);

cleanup:
    krb5_tkt_creds_free(context, ctx);
    return retval;
}

/*
 * Set *mcreds and *fields to a matching credential and field set for
 * use with krb5_cc_retrieve_cred, based on a set of input credentials
 * and options.  The fields of *mcreds will be aliased to the fields
 * of in_creds, so the contents of *mcreds should not be freed.
 */
krb5_error_code
krb5int_construct_matching_creds(krb5_context context, krb5_flags options,
                                 krb5_creds *in_creds, krb5_creds *mcreds,
                                 krb5_flags *fields)
{
    if (!in_creds || !in_creds->server || !in_creds->client)
        return EINVAL;

    memset(mcreds, 0, sizeof(krb5_creds));
    mcreds->magic = KV5M_CREDS;
    if (in_creds->times.endtime != 0) {
        mcreds->times.endtime = in_creds->times.endtime;
    } else {
        krb5_error_code retval;
        retval = krb5_timeofday(context, &mcreds->times.endtime);
        if (retval != 0) return retval;
    }
    mcreds->keyblock = in_creds->keyblock;
    mcreds->authdata = in_creds->authdata;
    mcreds->server = in_creds->server;
    mcreds->client = in_creds->client;

    *fields = KRB5_TC_MATCH_TIMES /*XXX |KRB5_TC_MATCH_SKEY_TYPE */
        | KRB5_TC_MATCH_AUTHDATA
        | KRB5_TC_SUPPORTED_KTYPES;
    if (mcreds->keyblock.enctype) {
        krb5_enctype *ktypes;
        krb5_error_code ret;
        int i;

        *fields |= KRB5_TC_MATCH_KTYPE;
        ret = krb5_get_tgs_ktypes(context, mcreds->server, &ktypes);
        for (i = 0; ktypes[i]; i++)
            if (ktypes[i] == mcreds->keyblock.enctype)
                break;
        if (ktypes[i] == 0)
            ret = KRB5_CC_NOT_KTYPE;
        free (ktypes);
        if (ret)
            return ret;
    }
    if (options & (KRB5_GC_USER_USER | KRB5_GC_CONSTRAINED_DELEGATION)) {
        /* also match on identical 2nd tkt and tkt encrypted in a
           session key */
        *fields |= KRB5_TC_MATCH_2ND_TKT;
        if (options & KRB5_GC_USER_USER) {
            *fields |= KRB5_TC_MATCH_IS_SKEY;
            mcreds->is_skey = TRUE;
        }
        mcreds->second_ticket = in_creds->second_ticket;
        if (!in_creds->second_ticket.length)
            return KRB5_NO_2ND_TKT;
    }

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials(krb5_context context, krb5_flags options,
                     krb5_ccache ccache, krb5_creds *in_creds,
                     krb5_creds **out_creds)
{
    krb5_error_code retval;
    krb5_creds *ncreds = NULL;

    *out_creds = NULL;

    ncreds = k5alloc(sizeof(*ncreds), &retval);
    if (ncreds == NULL)
        goto cleanup;

    /* Get the credential. */
    retval = get_tkt_creds(context, ccache, in_creds, options, ncreds);
    if (retval != 0)
        goto cleanup;

    *out_creds = ncreds;
    ncreds = NULL;

cleanup:
    krb5_free_creds(context, ncreds);
    return retval;
}
