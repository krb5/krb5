/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/ccache/ccfns.c
 *
 * Copyright 2000, 2007, 2008  by the Massachusetts Institute of Technology.
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
 * Dispatch methods for credentials cache code.
 */

#include "k5-int.h"

const char * KRB5_CALLCONV
krb5_cc_get_name (krb5_context context, krb5_ccache cache)
{
    return cache->ops->get_name(context, cache);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_gen_new (krb5_context context, krb5_ccache *cache)
{
    return (*cache)->ops->gen_new(context, cache);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_initialize(krb5_context context, krb5_ccache cache,
                   krb5_principal principal)
{
    return cache->ops->init(context, cache, principal);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_destroy (krb5_context context, krb5_ccache cache)
{
    return cache->ops->destroy(context, cache);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_close (krb5_context context, krb5_ccache cache)
{
    return cache->ops->close(context, cache);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_store_cred (krb5_context context, krb5_ccache cache,
                    krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_ticket *tkt;
    krb5_principal s1, s2;

    /* remove any dups */
    krb5_cc_remove_cred(context, cache, KRB5_TC_MATCH_AUTHDATA, creds);

    ret = cache->ops->store(context, cache, creds);
    if (ret) return ret;

    /*
     * If creds->server and the server in the decoded ticket differ,
     * store both principals.
     */
    s1 = creds->server;
    ret = decode_krb5_ticket(&creds->ticket, &tkt);
    /* Bail out on errors in case someone is storing a non-ticket. */
    if (ret) return 0;
    s2 = tkt->server;
    if (!krb5_principal_compare(context, s1, s2)) {
        creds->server = s2;
        /* remove any dups */
        krb5_cc_remove_cred(context, cache, KRB5_TC_MATCH_AUTHDATA, creds);
        ret = cache->ops->store(context, cache, creds);
        creds->server = s1;
    }
    krb5_free_ticket(context, tkt);
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_cc_retrieve_cred (krb5_context context, krb5_ccache cache,
                       krb5_flags flags, krb5_creds *mcreds,
                       krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_data tmprealm;

    ret = cache->ops->retrieve(context, cache, flags, mcreds, creds);
    if (ret != KRB5_CC_NOTFOUND)
        return ret;
    if (!krb5_is_referral_realm(&mcreds->server->realm))
        return ret;

    /*
     * Retry using client's realm if service has referral realm.
     */
    tmprealm = mcreds->server->realm;
    mcreds->server->realm = mcreds->client->realm;
    ret = cache->ops->retrieve(context, cache, flags, mcreds, creds);
    mcreds->server->realm = tmprealm;
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_cc_get_principal (krb5_context context, krb5_ccache cache,
                       krb5_principal *principal)
{
    return cache->ops->get_princ(context, cache, principal);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_start_seq_get (krb5_context context, krb5_ccache cache,
                       krb5_cc_cursor *cursor)
{
    return cache->ops->get_first(context, cache, cursor);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_next_cred (krb5_context context, krb5_ccache cache,
                   krb5_cc_cursor *cursor, krb5_creds *creds)
{
    return cache->ops->get_next(context, cache, cursor, creds);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_end_seq_get (krb5_context context, krb5_ccache cache,
                     krb5_cc_cursor *cursor)
{
    return cache->ops->end_get(context, cache, cursor);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_remove_cred (krb5_context context, krb5_ccache cache, krb5_flags flags,
                     krb5_creds *creds)
{
    return cache->ops->remove_cred(context, cache, flags, creds);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_set_flags (krb5_context context, krb5_ccache cache, krb5_flags flags)
{
    return cache->ops->set_flags(context, cache, flags);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_get_flags (krb5_context context, krb5_ccache cache, krb5_flags *flags)
{
    return cache->ops->get_flags(context, cache, flags);
}

const char * KRB5_CALLCONV
krb5_cc_get_type (krb5_context context, krb5_ccache cache)
{
    return cache->ops->prefix;
}

krb5_error_code KRB5_CALLCONV
krb5_cc_last_change_time (krb5_context context, krb5_ccache ccache,
                          krb5_timestamp *change_time)
{
    return ccache->ops->lastchange(context, ccache, change_time);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_lock (krb5_context context, krb5_ccache ccache)
{
    return ccache->ops->lock(context, ccache);
}

krb5_error_code KRB5_CALLCONV
krb5_cc_unlock (krb5_context context, krb5_ccache ccache)
{
    return ccache->ops->unlock(context, ccache);
}

static const char conf_realm[] = "X-CACHECONF:";
static const char conf_name[] = "krb5_ccache_conf_data";

static krb5_error_code
build_conf_principals (krb5_context context, krb5_ccache id,
                       krb5_const_principal principal,
                       const char *name, krb5_creds *cred)
{
    krb5_principal client;
    krb5_error_code ret;
    char *pname = NULL;

    memset(cred, 0, sizeof(*cred));

    ret = krb5_cc_get_principal(context, id, &client);
    if (ret)
        return ret;

    if (principal) {
        ret = krb5_unparse_name(context, principal, &pname);
        if (ret)
            return ret;
    }

    ret = krb5_build_principal(context, &cred->server,
                               sizeof(conf_realm) - 1, conf_realm,
                               conf_name, name, pname, (char *)NULL);
    free(pname);
    if (ret) {
        krb5_free_principal(context, client);
        return ret;
    }
    ret = krb5_copy_principal(context, client, &cred->client);
    krb5_free_principal(context, client);
    return ret;
}

/*!
 * \param context a Keberos context
 * \param principal principal to check if it a configuration principal
 *
 * \brief Return TRUE (non zero) if the principal is a configuration
 *        principal (generated part of krb5_cc_set_config()). Returns
 *        FALSE (zero) if not a configuration principal.
 *
 */

krb5_boolean KRB5_CALLCONV
krb5_is_config_principal (krb5_context context,
                          krb5_const_principal principal)
{
    const krb5_data *realm;

    realm = krb5_princ_realm(context, principal);

    if (realm->length != sizeof(conf_realm) - 1 ||
        memcmp(realm->data, conf_realm, sizeof(conf_realm) - 1) != 0)
        return FALSE;

    if (principal->length == 0 ||
        principal->data[0].length != (sizeof(conf_name) - 1) ||
        memcmp(principal->data[0].data, conf_name, sizeof(conf_name) - 1) != 0)
        return FALSE;

    return TRUE;
}

/*!
 * \param context a Keberos context
 * \param id the credential cache to store the data for
 * \param principal configuration for a specific principal, if
 * NULL, global for the whole cache.
 * \param key name under which the configuraion is stored.
 * \param data data to store
 *
 * \brief Store some configuration for the credential cache in the
 *        cache.  Existing configuration under the same key is
 *        over-written.
 *
 */

krb5_error_code KRB5_CALLCONV
krb5_cc_set_config (krb5_context context, krb5_ccache id,
                    krb5_const_principal principal,
                    const char *key, krb5_data *data)
{
    krb5_error_code ret;
    krb5_creds cred;
    memset(&cred, 0, sizeof(cred));

    ret = build_conf_principals(context, id, principal, key, &cred);
    if (ret)
        goto out;

    ret = krb5_cc_remove_cred(context, id, 0, &cred);
    if (ret && ret != KRB5_CC_NOTFOUND && ret != KRB5_CC_NOSUPP)
        goto out;

    cred.ticket.data = malloc(data->length);
    if (cred.ticket.data == NULL) {
        krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
        return ENOMEM;
    }
    cred.ticket.length = data->length;
    memcpy(cred.ticket.data, data->data, data->length);

    ret = krb5_cc_store_cred(context, id, &cred);

out:
    krb5_free_cred_contents(context, &cred);
    return ret;
}

/*!
 * \param context a Keberos context
 * \param id the credential cache to store the data for
 * \param principal configuration for a specific principal, if
 *        NULL, global for the whole cache.
 * \param key name under which the configuraion is stored.
 * \param data data to fetched, free with krb5_data_free()
 *
 * \brief Get some configuration for the credential cache in the cache.
 */


krb5_error_code KRB5_CALLCONV
krb5_cc_get_config (krb5_context context, krb5_ccache id,
                    krb5_const_principal principal,
                    const char *key, krb5_data *data)
{
    krb5_creds mcred, cred;
    krb5_error_code ret;

    memset(&cred, 0, sizeof(cred));
    memset(data, 0, sizeof(*data));

    ret = build_conf_principals(context, id, principal, key, &mcred);
    if (ret)
        goto out;

    ret = krb5_cc_retrieve_cred(context, id, 0, &mcred, &cred);
    if (ret)
        goto out;

    data->data = malloc(cred.ticket.length);
    if (data->data == NULL) {
        ret = ENOMEM;
        krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
        goto out;
    }
    data->length = cred.ticket.length;
    memcpy(data->data, cred.ticket.data, data->length);

out:
    krb5_free_cred_contents(context, &cred);
    krb5_free_cred_contents(context, &mcred);
    return ret;
}
