/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "k5-int.h"
#include "int-proto.h"

/* Return true if configuration demands that a keytab be present.  (By default
 * verification will be skipped if no keytab exists.) */
static krb5_boolean
nofail(krb5_context context, krb5_verify_init_creds_opt *options,
       krb5_creds *creds)
{
    int val;

    if (options &&
        (options->flags & KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL))
        return (options->ap_req_nofail != 0);
    if (krb5int_libdefault_boolean(context, &creds->client->realm,
                                   KRB5_CONF_VERIFY_AP_REQ_NOFAIL,
                                   &val) == 0)
        return (val != 0);
    return FALSE;
}

static krb5_error_code
copy_creds_except(krb5_context context, krb5_ccache incc,
                  krb5_ccache outcc, krb5_principal princ)
{
    krb5_error_code code;
    krb5_flags flags;
    krb5_cc_cursor cur;
    krb5_creds creds;

    flags = 0;                           /* turns off OPENCLOSE mode */
    if ((code = krb5_cc_set_flags(context, incc, flags)))
        return(code);
    if ((code = krb5_cc_set_flags(context, outcc, flags)))
        return(code);

    if ((code = krb5_cc_start_seq_get(context, incc, &cur)))
        goto cleanup;

    while (!(code = krb5_cc_next_cred(context, incc, &cur, &creds))) {
        if (krb5_principal_compare(context, princ, creds.server))
            continue;

        code = krb5_cc_store_cred(context, outcc, &creds);
        krb5_free_cred_contents(context, &creds);
        if (code)
            goto cleanup;
    }

    if (code != KRB5_CC_END)
        goto cleanup;

    code = 0;

cleanup:
    flags = KRB5_TC_OPENCLOSE;

    if (code)
        krb5_cc_set_flags(context, incc, flags);
    else
        code = krb5_cc_set_flags(context, incc, flags);

    if (code)
        krb5_cc_set_flags(context, outcc, flags);
    else
        code = krb5_cc_set_flags(context, outcc, flags);

    return(code);
}

static krb5_error_code
get_vfy_cred(krb5_context context, krb5_creds *creds, krb5_principal server,
             krb5_keytab keytab, krb5_ccache *ccache_arg)
{
    krb5_error_code ret;
    krb5_ccache ccache;
    krb5_creds in_creds, *out_creds;
    krb5_auth_context authcon;
    krb5_data ap_req;

    ccache = NULL;
    out_creds = NULL;
    authcon = NULL;
    ap_req.data = NULL;
    /* If the creds are for the server principal, we're set, just do a mk_req.
     * Otherwise, do a get_credentials first.
     */

    if (krb5_principal_compare(context, server, creds->server)) {
        /* make an ap_req */
        if ((ret = krb5_mk_req_extended(context, &authcon, 0, NULL, creds,
                                        &ap_req)))
            goto cleanup;
    } else {
        /* this is unclean, but it's the easiest way without ripping the
           library into very small pieces.  store the client's initial cred
           in a memory ccache, then call the library.  Later, we'll copy
           everything except the initial cred into the ccache we return to
           the user.  A clean implementation would involve library
           internals with a coherent idea of "in" and "out". */

        /* insert the initial cred into the ccache */

        if ((ret = krb5_cc_new_unique(context, "MEMORY", NULL, &ccache))) {
            ccache = NULL;
            goto cleanup;
        }

        if ((ret = krb5_cc_initialize(context, ccache, creds->client)))
            goto cleanup;

        if ((ret = krb5_cc_store_cred(context, ccache, creds)))
            goto cleanup;

        /* set up for get_creds */
        memset(&in_creds, 0, sizeof(in_creds));
        in_creds.client = creds->client;
        in_creds.server = server;
        if ((ret = krb5_timeofday(context, &in_creds.times.endtime)))
            goto cleanup;
        in_creds.times.endtime += 5*60;

        if ((ret = krb5_get_credentials(context, 0, ccache, &in_creds,
                                        &out_creds)))
            goto cleanup;

        /* make an ap_req */
        if ((ret = krb5_mk_req_extended(context, &authcon, 0, NULL, out_creds,
                                        &ap_req)))
            goto cleanup;
    }

    /* wipe the auth context for mk_req */
    if (authcon) {
        krb5_auth_con_free(context, authcon);
        authcon = NULL;
    }

    /* verify the ap_req */

    if ((ret = krb5_rd_req(context, &authcon, &ap_req, server, keytab,
                           NULL, NULL)))
        goto cleanup;

    /* if we get this far, then the verification succeeded.  We can
       still fail if the library stuff here fails, but that's it */

    if (ccache_arg && ccache) {
        if (*ccache_arg == NULL) {
            krb5_ccache retcc;

            retcc = NULL;

            if ((ret = krb5_cc_resolve(context, "MEMORY:rd_req2", &retcc)) ||
                (ret = krb5_cc_initialize(context, retcc, creds->client)) ||
                (ret = copy_creds_except(context, ccache, retcc,
                                         creds->server))) {
                if (retcc)
                    krb5_cc_destroy(context, retcc);
            } else {
                *ccache_arg = retcc;
            }
        } else {
            ret = copy_creds_except(context, ccache, *ccache_arg,
                                    server);
        }
    }

    /* if any of the above paths returned an errors, then ret is set accordingly.
     * Either that, or it's zero, which is fine, too
     */

cleanup:
    if (ccache)
        krb5_cc_destroy(context, ccache);
    if (out_creds)
        krb5_free_creds(context, out_creds);
    if (authcon)
        krb5_auth_con_free(context, authcon);
    if (ap_req.data)
        free(ap_req.data);

    return(ret);
}

/* Free the principals in plist and plist itself. */
static void
free_princ_list(krb5_context context, krb5_principal *plist)
{
    size_t i;

    if (plist == NULL)
        return;
    for (i = 0; plist[i] != NULL; i++)
        krb5_free_principal(context, plist[i]);
    free(plist);
}

/* Add princ to plist if it isn't already there. */
static krb5_error_code
add_princ_list(krb5_context context, krb5_const_principal princ,
               krb5_principal **plist)
{
    size_t i;
    krb5_principal *newlist;

    /* Check if princ is already in plist, and count the elements. */
    for (i = 0; (*plist) != NULL && (*plist)[i] != NULL; i++) {
        if (krb5_principal_compare(context, princ, (*plist)[i]))
            return 0;
    }

    newlist = realloc(*plist, (i + 2) * sizeof(*newlist));
    if (newlist == NULL)
        return ENOMEM;
    *plist = newlist;
    newlist[i] = newlist[i + 1] = NULL; /* terminate the list */
    return krb5_copy_principal(context, princ, &newlist[i]);
}

/* Return a list of all unique host service princs in keytab. */
static krb5_error_code
get_host_princs_from_keytab(krb5_context context, krb5_keytab keytab,
                            krb5_principal **princ_list_out)
{
    krb5_error_code ret;
    krb5_kt_cursor cursor;
    krb5_keytab_entry kte;
    krb5_principal *plist = NULL, p;

    *princ_list_out = NULL;

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret)
        goto cleanup;

    while ((ret = krb5_kt_next_entry(context, keytab, &kte, &cursor)) == 0) {
        p = kte.principal;
        if (p->length == 2 && data_eq_string(p->data[0], "host"))
            ret = add_princ_list(context, p, &plist);
        krb5_kt_free_entry(context, &kte);
        if (ret)
            break;
    }
    (void)krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret == KRB5_KT_END)
        ret = 0;
    if (ret)
        goto cleanup;

    *princ_list_out = plist;
    plist = NULL;

cleanup:
    free_princ_list(context, plist);
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_verify_init_creds(krb5_context context, krb5_creds *creds,
                       krb5_principal server, krb5_keytab keytab,
                       krb5_ccache *ccache,
                       krb5_verify_init_creds_opt *options)
{
    krb5_error_code ret;
    krb5_principal *host_princs = NULL;
    krb5_keytab defkeytab = NULL;
    krb5_keytab_entry kte;
    krb5_boolean have_keys = FALSE;
    size_t i;

    if (keytab == NULL) {
        ret = krb5_kt_default(context, &defkeytab);
        if (ret)
            goto cleanup;
        keytab = defkeytab;
    }

    if (server != NULL) {
        /* Check if server exists in keytab first. */
        ret = krb5_kt_get_entry(context, keytab, server, 0, 0, &kte);
        if (ret)
            goto cleanup;
        krb5_kt_free_entry(context, &kte);
        have_keys = TRUE;
        ret = get_vfy_cred(context, creds, server, keytab, ccache);
    } else {
        /* Try using the host service principals from the keytab. */
        if (keytab->ops->start_seq_get == NULL) {
            ret = EINVAL;
            goto cleanup;
        }
        ret = get_host_princs_from_keytab(context, keytab, &host_princs);
        if (ret)
            goto cleanup;
        if (host_princs == NULL) {
            ret = KRB5_KT_NOTFOUND;
            goto cleanup;
        }
        have_keys = TRUE;

        /* Try all host principals until one succeeds or they all fail. */
        for (i = 0; host_princs[i] != NULL; i++) {
            ret = get_vfy_cred(context, creds, host_princs[i], keytab, ccache);
            if (ret == 0)
                break;
        }
    }

cleanup:
    /* If we have no key to verify with, pretend to succeed unless
     * configuration directs otherwise. */
    if (!have_keys && !nofail(context, options, creds))
        ret = 0;

    if (defkeytab != NULL)
        krb5_kt_close(context, defkeytab);
    krb5_free_principal(context, server);
    free_princ_list(context, host_princs);

    return ret;
}
