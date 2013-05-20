/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/rd_req_dec.c */
/*
 * Copyright (c) 1994 CyberSAFE Corporation.
 * Copyright 1990,1991,2007,2008 by the Massachusetts Institute of Technology.
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
 *
 * krb5_rd_req_decoded()
 */

#include "k5-int.h"
#include "auth_con.h"
#include "authdata.h"
#include "int-proto.h"

/*
 * essentially the same as krb_rd_req, but uses a decoded AP_REQ as
 * the input rather than an encoded input.
 */
/*
 *  Parses a KRB_AP_REQ message, returning its contents.
 *
 *  server specifies the expected server's name for the ticket; if NULL, then
 *  any server will be accepted if the key can be found, and the caller should
 *  verify that the principal is something it trusts. With the exception of the
 *  kdb keytab, the ticket's server field need not match the name passed in for
 *  server. All that is required is that the ticket be encrypted with a key
 *  from the keytab associated with the specified server principal. This
 *  permits the KDC to have a set of aliases for the server without keeping
 *  this information consistent with the server. So, when server is non-null,
 *  the principal expected by the application needs to be consistent with the
 *  local keytab, but not with the informational name in the ticket.
 *
 *  rcache specifies a replay detection cache used to store authenticators and
 *  server names
 *
 *  keyproc specifies a procedure to generate a decryption key for the
 *  ticket.  If keyproc is non-NULL, keyprocarg is passed to it, and the result
 *  used as a decryption key. If keyproc is NULL, then fetchfrom is checked;
 *  if it is non-NULL, it specifies a parameter name from which to retrieve the
 *  decryption key.  If fetchfrom is NULL, then the default key store is
 *  consulted.
 *
 *  authdat is set to point at allocated storage structures; the caller
 *  should free them when finished.
 *
 *  returns system errors, encryption errors, replay errors
 */

static krb5_error_code
decrypt_authenticator(krb5_context, const krb5_ap_req *,
                      krb5_authenticator **, int);
static krb5_error_code
decode_etype_list(krb5_context context,
                  const krb5_authenticator *authp,
                  krb5_enctype **desired_etypes,
                  int *desired_etypes_len);
static krb5_error_code
negotiate_etype(krb5_context context,
                const krb5_enctype *desired_etypes,
                int desired_etypes_len,
                int mandatory_etypes_index,
                const krb5_enctype *permitted_etypes,
                int permitted_etypes_len,
                krb5_enctype *negotiated_etype);

/* Return true if princ might match multiple principals. */
static inline krb5_boolean
is_matching(krb5_context context, krb5_const_principal princ)
{
    if (princ == NULL)
        return TRUE;
    return (princ->type == KRB5_NT_SRV_HST && princ->length == 2
            && (princ->realm.length == 0 || princ->data[1].length == 0 ||
                context->ignore_acceptor_hostname));
}

/* Decrypt the ticket in req using the key in ent. */
static krb5_error_code
try_one_entry(krb5_context context, const krb5_ap_req *req,
              krb5_keytab_entry *ent, krb5_keyblock *keyblock_out)
{
    krb5_error_code ret;
    krb5_principal tmp = NULL;

    /* Try decrypting the ticket with this entry's key. */
    ret = krb5_decrypt_tkt_part(context, &ent->key, req->ticket);
    if (ret)
        return ret;

    /* Make a copy of the principal for the ticket server field. */
    ret = krb5_copy_principal(context, ent->principal, &tmp);
    if (ret)
        return ret;

    /* Make a copy of the decrypting key if requested by the caller. */
    if (keyblock_out != NULL) {
        ret = krb5_copy_keyblock_contents(context, &ent->key, keyblock_out);
        if (ret) {
            krb5_free_principal(context, tmp);
            return ret;
        }
    }

    /* Make req->ticket->server indicate the actual server principal. */
    krb5_free_principal(context, req->ticket->server);
    req->ticket->server = tmp;

    return 0;
}

/* Decrypt the ticket in req using a principal looked up from keytab. */
static krb5_error_code
try_one_princ(krb5_context context, const krb5_ap_req *req,
              krb5_const_principal princ, krb5_keytab keytab,
              krb5_keyblock *keyblock_out)
{
    krb5_error_code ret;
    krb5_keytab_entry ent;

    ret = krb5_kt_get_entry(context, keytab, princ,
                            req->ticket->enc_part.kvno,
                            req->ticket->enc_part.enctype, &ent);
    if (ret)
        return ret;
    ret = try_one_entry(context, req, &ent, keyblock_out);
    if (ret == 0)
        TRACE_RD_REQ_DECRYPT_SPECIFIC(context, ent.principal, &ent.key);
    (void)krb5_free_keytab_entry_contents(context, &ent);
    if (ret)
        return ret;

    return 0;
}

/*
 * Decrypt the ticket in req using an entry in keytab matching server (if
 * given).  Set req->ticket->server to the principal of the keytab entry used.
 * Store the decrypting key in *keyblock_out if it is not NULL.
 */
static krb5_error_code
decrypt_ticket(krb5_context context, const krb5_ap_req *req,
               krb5_const_principal server, krb5_keytab keytab,
               krb5_keyblock *keyblock_out)
{
    krb5_error_code ret;
    krb5_keytab_entry ent;
    krb5_kt_cursor cursor;

#ifdef LEAN_CLIENT
    return KRB5KRB_AP_WRONG_PRINC;
#else
    /* If we have an explicit server principal, try just that one. */
    if (!is_matching(context, server))
        return try_one_princ(context, req, server, keytab, keyblock_out);

    if (keytab->ops->start_seq_get == NULL) {
        /* We can't iterate over the keytab.  Try the principal asserted by the
         * client if it's allowed by the server parameter. */
        if (!krb5_sname_match(context, server, req->ticket->server))
            return KRB5KRB_AP_WRONG_PRINC;
        return try_one_princ(context, req, req->ticket->server, keytab,
                             keyblock_out);
    }

    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret)
        goto cleanup;

    while ((ret = krb5_kt_next_entry(context, keytab, &ent, &cursor)) == 0) {
        if (ent.key.enctype == req->ticket->enc_part.enctype &&
            krb5_sname_match(context, server, ent.principal)) {
            ret = try_one_entry(context, req, &ent, keyblock_out);
            if (ret == 0) {
                TRACE_RD_REQ_DECRYPT_ANY(context, ent.principal, &ent.key);
                (void)krb5_free_keytab_entry_contents(context, &ent);
                break;
            }
        }

        (void)krb5_free_keytab_entry_contents(context, &ent);
    }

    (void)krb5_kt_end_seq_get(context, keytab, &cursor);

cleanup:
    switch (ret) {
    case KRB5_KT_KVNONOTFOUND:
    case KRB5_KT_NOTFOUND:
    case KRB5_KT_END:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        ret = KRB5KRB_AP_WRONG_PRINC;
        break;
    default:
        break;
    }

    return ret;
#endif /* LEAN_CLIENT */
}

#if 0
#include <syslog.h>
static void
debug_log_authz_data(const char *which, krb5_authdata **a)
{
    if (a) {
        syslog(LOG_ERR|LOG_DAEMON, "%s authz data:", which);
        while (*a) {
            syslog(LOG_ERR|LOG_DAEMON, "  ad_type:%d length:%d '%.*s'",
                   (*a)->ad_type, (*a)->length, (*a)->length,
                   (char *) (*a)->contents);
            a++;
        }
        syslog(LOG_ERR|LOG_DAEMON, "  [end]");
    } else
        syslog(LOG_ERR|LOG_DAEMON, "no %s authz data", which);
}
#else
static void
debug_log_authz_data(const char *which, krb5_authdata **a)
{
}
#endif

static krb5_error_code
rd_req_decoded_opt(krb5_context context, krb5_auth_context *auth_context,
                   const krb5_ap_req *req, krb5_const_principal server,
                   krb5_keytab keytab, krb5_flags *ap_req_options,
                   krb5_ticket **ticket, int check_valid_flag)
{
    krb5_error_code       retval = 0;
    krb5_enctype         *desired_etypes = NULL;
    int                   desired_etypes_len = 0;
    int                   rfc4537_etypes_len = 0;
    krb5_enctype         *permitted_etypes = NULL;
    int                   permitted_etypes_len = 0;
    krb5_keyblock         decrypt_key;

    decrypt_key.enctype = ENCTYPE_NULL;
    decrypt_key.contents = NULL;
    req->ticket->enc_part2 = NULL;

    /* if (req->ap_options & AP_OPTS_USE_SESSION_KEY)
       do we need special processing here ?     */

    /* decrypt the ticket */
    if ((*auth_context)->key) { /* User to User authentication */
        if ((retval = krb5_decrypt_tkt_part(context,
                                            &(*auth_context)->key->keyblock,
                                            req->ticket)))
            goto cleanup;
        if (check_valid_flag) {
            decrypt_key = (*auth_context)->key->keyblock;
            (*auth_context)->key->keyblock.contents = NULL;
        }
        krb5_k_free_key(context, (*auth_context)->key);
        (*auth_context)->key = NULL;
        if (server == NULL)
            server = req->ticket->server;
    } else {
        retval = decrypt_ticket(context, req, server, keytab,
                                check_valid_flag ? &decrypt_key : NULL);
        if (retval)
            goto cleanup;
        /* decrypt_ticket placed the principal of the keytab key in
         * req->ticket->server; always use this for later steps. */
        server = req->ticket->server;
    }
    TRACE_RD_REQ_TICKET(context, req->ticket->enc_part2->client,
                        req->ticket->server, req->ticket->enc_part2->session);

    /* XXX this is an evil hack.  check_valid_flag is set iff the call
       is not from inside the kdc.  we can use this to determine which
       key usage to use */
#ifndef LEAN_CLIENT
    if ((retval = decrypt_authenticator(context, req,
                                        &((*auth_context)->authentp),
                                        check_valid_flag)))
        goto cleanup;
#endif
    if (!krb5_principal_compare(context, (*auth_context)->authentp->client,
                                req->ticket->enc_part2->client)) {
        retval = KRB5KRB_AP_ERR_BADMATCH;
        goto cleanup;
    }

    if ((*auth_context)->remote_addr &&
        !krb5_address_search(context, (*auth_context)->remote_addr,
                             req->ticket->enc_part2->caddrs)) {
        retval = KRB5KRB_AP_ERR_BADADDR;
        goto cleanup;
    }

    /* Get an rcache if necessary. */
    if (((*auth_context)->rcache == NULL)
        && ((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME)
        && server) {
        if ((retval = krb5_get_server_rcache(context,
                                             krb5_princ_component(context,server,0),
                                             &(*auth_context)->rcache)))
            goto cleanup;
    }
    /* okay, now check cross-realm policy */

#if defined(_SINGLE_HOP_ONLY)

    /* Single hop cross-realm tickets only */

    {
        krb5_transited *trans = &(req->ticket->enc_part2->transited);

        /* If the transited list is empty, then we have at most one hop */
        if (trans->tr_contents.length > 0 && trans->tr_contents.data[0])
            retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
    }

#elif defined(_NO_CROSS_REALM)

    /* No cross-realm tickets */

    {
        char            * lrealm;
        krb5_data       * realm;
        krb5_transited  * trans;

        realm = krb5_princ_realm(context, req->ticket->enc_part2->client);
        trans = &(req->ticket->enc_part2->transited);

        /*
         * If the transited list is empty, then we have at most one hop
         * So we also have to check that the client's realm is the local one
         */
        krb5_get_default_realm(context, &lrealm);
        if ((trans->tr_contents.length > 0 && trans->tr_contents.data[0]) ||
            !data_eq_string(*realm, lrealm)) {
            retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
        }
        free(lrealm);
    }

#else

    /* Hierarchical Cross-Realm */

    {
        krb5_data      * realm;
        krb5_transited * trans;

        realm = krb5_princ_realm(context, req->ticket->enc_part2->client);
        trans = &(req->ticket->enc_part2->transited);

        /*
         * If the transited list is not empty, then check that all realms
         * transited are within the hierarchy between the client's realm
         * and the local realm.
         */
        if (trans->tr_contents.length > 0 && trans->tr_contents.data[0]) {
            retval = krb5_check_transited_list(context, &(trans->tr_contents),
                                               realm,
                                               krb5_princ_realm (context,server));
        }
    }

#endif

    if (retval)  goto cleanup;

    /* only check rcache if sender has provided one---some services
       may not be able to use replay caches (such as datagram servers) */

    if ((*auth_context)->rcache) {
        krb5_donot_replay  rep;
        krb5_tkt_authent   tktauthent;

        tktauthent.ticket = req->ticket;
        tktauthent.authenticator = (*auth_context)->authentp;
        if (!(retval = krb5_auth_to_rep(context, &tktauthent, &rep))) {
            retval = krb5_rc_hash_message(context,
                                          &req->authenticator.ciphertext,
                                          &rep.msghash);
            if (!retval) {
                retval = krb5_rc_store(context, (*auth_context)->rcache, &rep);
                free(rep.msghash);
            }
            free(rep.server);
            free(rep.client);
        }

        if (retval)
            goto cleanup;
    }

    retval = krb5int_validate_times(context, &req->ticket->enc_part2->times);
    if (retval != 0)
        goto cleanup;

    if ((retval = krb5_check_clockskew(context, (*auth_context)->authentp->ctime)))
        goto cleanup;

    if (check_valid_flag) {
        if (req->ticket->enc_part2->flags & TKT_FLG_INVALID) {
            retval = KRB5KRB_AP_ERR_TKT_INVALID;
            goto cleanup;
        }

        if ((retval = krb5_authdata_context_init(context,
                                                 &(*auth_context)->ad_context)))
            goto cleanup;
        if ((retval = krb5int_authdata_verify(context,
                                              (*auth_context)->ad_context,
                                              AD_USAGE_MASK,
                                              auth_context,
                                              &decrypt_key,
                                              req)))
            goto cleanup;
    }

    /* read RFC 4537 etype list from sender */
    retval = decode_etype_list(context,
                               (*auth_context)->authentp,
                               &desired_etypes,
                               &rfc4537_etypes_len);
    if (retval != 0)
        goto cleanup;

    if (desired_etypes == NULL)
        desired_etypes = (krb5_enctype *)calloc(4, sizeof(krb5_enctype));
    else
        desired_etypes = (krb5_enctype *)realloc(desired_etypes,
                                                 (rfc4537_etypes_len + 4) *
                                                 sizeof(krb5_enctype));
    if (desired_etypes == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    desired_etypes_len = rfc4537_etypes_len;

    /*
     * RFC 4537:
     *
     *   If the EtypeList is present and the server prefers an enctype from
     *   the client's enctype list over that of the AP-REQ authenticator
     *   subkey (if that is present) or the service ticket session key, the
     *   server MUST create a subkey using that enctype.  This negotiated
     *   subkey is sent in the subkey field of AP-REP message, and it is then
     *   used as the protocol key or base key [RFC3961] for subsequent
     *   communication.
     *
     *   If the enctype of the ticket session key is included in the enctype
     *   list sent by the client, it SHOULD be the last on the list;
     *   otherwise, this enctype MUST NOT be negotiated if it was not included
     *   in the list.
     *
     * The second paragraph does appear to contradict the first with respect
     * to whether it is legal to negotiate the ticket session key type if it
     * is absent in the EtypeList. A literal reading suggests that we can use
     * the AP-REQ subkey enctype. Also a client has no way of distinguishing
     * a server that does not RFC 4537 from one that has chosen the same
     * enctype as the ticket session key for the acceptor subkey, surely.
     */

    if ((*auth_context)->authentp->subkey != NULL) {
        desired_etypes[desired_etypes_len++] = (*auth_context)->authentp->subkey->enctype;
    }
    desired_etypes[desired_etypes_len++] = req->ticket->enc_part2->session->enctype;
    desired_etypes[desired_etypes_len] = ENCTYPE_NULL;

    if (((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_PERMIT_ALL) == 0) {
        if ((*auth_context)->permitted_etypes != NULL) {
            permitted_etypes = (*auth_context)->permitted_etypes;
        } else {
            retval = krb5_get_permitted_enctypes(context, &permitted_etypes);
            if (retval != 0)
                goto cleanup;
        }
        permitted_etypes_len = k5_count_etypes(permitted_etypes);
    } else {
        permitted_etypes = NULL;
        permitted_etypes_len = 0;
    }

    /* check if the various etypes are permitted */
    retval = negotiate_etype(context,
                             desired_etypes, desired_etypes_len,
                             rfc4537_etypes_len,
                             permitted_etypes, permitted_etypes_len,
                             &(*auth_context)->negotiated_etype);
    if (retval != 0)
        goto cleanup;
    TRACE_RD_REQ_NEGOTIATED_ETYPE(context, (*auth_context)->negotiated_etype);

    assert((*auth_context)->negotiated_etype != ENCTYPE_NULL);

    (*auth_context)->remote_seq_number = (*auth_context)->authentp->seq_number;
    if ((*auth_context)->authentp->subkey) {
        TRACE_RD_REQ_SUBKEY(context, (*auth_context)->authentp->subkey);
        if ((retval = krb5_k_create_key(context,
                                        (*auth_context)->authentp->subkey,
                                        &((*auth_context)->recv_subkey))))
            goto cleanup;
        retval = krb5_k_create_key(context, (*auth_context)->authentp->subkey,
                                   &((*auth_context)->send_subkey));
        if (retval) {
            krb5_k_free_key(context, (*auth_context)->recv_subkey);
            (*auth_context)->recv_subkey = NULL;
            goto cleanup;
        }
    } else {
        (*auth_context)->recv_subkey = 0;
        (*auth_context)->send_subkey = 0;
    }

    if ((retval = krb5_k_create_key(context, req->ticket->enc_part2->session,
                                    &((*auth_context)->key))))
        goto cleanup;

    debug_log_authz_data("ticket", req->ticket->enc_part2->authorization_data);

    /*
     * If not AP_OPTS_MUTUAL_REQUIRED then and sequence numbers are used
     * then the default sequence number is the one's complement of the
     * sequence number sent ot us.
     */
    if ((!(req->ap_options & AP_OPTS_MUTUAL_REQUIRED)) &&
        (*auth_context)->remote_seq_number) {
        (*auth_context)->local_seq_number ^=
            (*auth_context)->remote_seq_number;
    }

    if (ticket)
        if ((retval = krb5_copy_ticket(context, req->ticket, ticket)))
            goto cleanup;
    if (ap_req_options) {
        *ap_req_options = req->ap_options & AP_OPTS_WIRE_MASK;
        if (rfc4537_etypes_len != 0)
            *ap_req_options |= AP_OPTS_ETYPE_NEGOTIATION;
        if ((*auth_context)->negotiated_etype !=
            krb5_k_key_enctype(context, (*auth_context)->key))
            *ap_req_options |= AP_OPTS_USE_SUBKEY;
    }

    retval = 0;

cleanup:
    if (desired_etypes != NULL)
        free(desired_etypes);
    if (permitted_etypes != NULL &&
        permitted_etypes != (*auth_context)->permitted_etypes)
        free(permitted_etypes);
    if (retval) {
        /* only free if we're erroring out...otherwise some
           applications will need the output. */
        if (req->ticket->enc_part2)
            krb5_free_enc_tkt_part(context, req->ticket->enc_part2);
        req->ticket->enc_part2 = NULL;
    }
    if (check_valid_flag)
        krb5_free_keyblock_contents(context, &decrypt_key);

    return retval;
}

krb5_error_code
krb5_rd_req_decoded(krb5_context context, krb5_auth_context *auth_context,
                    const krb5_ap_req *req, krb5_const_principal server,
                    krb5_keytab keytab, krb5_flags *ap_req_options,
                    krb5_ticket **ticket)
{
    krb5_error_code retval;
    retval = rd_req_decoded_opt(context, auth_context,
                                req, server, keytab,
                                ap_req_options, ticket,
                                1); /* check_valid_flag */
    return retval;
}

krb5_error_code
krb5_rd_req_decoded_anyflag(krb5_context context,
                            krb5_auth_context *auth_context,
                            const krb5_ap_req *req,
                            krb5_const_principal server, krb5_keytab keytab,
                            krb5_flags *ap_req_options, krb5_ticket **ticket)
{
    krb5_error_code retval;
    retval = rd_req_decoded_opt(context, auth_context,
                                req, server, keytab,
                                ap_req_options, ticket,
                                0); /* don't check_valid_flag */
    return retval;
}

#ifndef LEAN_CLIENT
static krb5_error_code
decrypt_authenticator(krb5_context context, const krb5_ap_req *request,
                      krb5_authenticator **authpp, int is_ap_req)
{
    krb5_authenticator *local_auth;
    krb5_error_code retval;
    krb5_data scratch;
    krb5_keyblock *sesskey;

    sesskey = request->ticket->enc_part2->session;

    scratch.length = request->authenticator.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length)))
        return(ENOMEM);

    if ((retval = krb5_c_decrypt(context, sesskey,
                                 is_ap_req?KRB5_KEYUSAGE_AP_REQ_AUTH:
                                 KRB5_KEYUSAGE_TGS_REQ_AUTH, 0,
                                 &request->authenticator, &scratch))) {
        free(scratch.data);
        return(retval);
    }

#define clean_scratch() {memset(scratch.data, 0, scratch.length);       \
        free(scratch.data);}

    /*  now decode the decrypted stuff */
    if (!(retval = decode_krb5_authenticator(&scratch, &local_auth))) {
        *authpp = local_auth;
        debug_log_authz_data("authenticator", local_auth->authorization_data);
    }
    clean_scratch();
    return retval;
}
#endif

static krb5_error_code
negotiate_etype(krb5_context context,
                const krb5_enctype *desired_etypes,
                int desired_etypes_len,
                int mandatory_etypes_index,
                const krb5_enctype *permitted_etypes,
                int permitted_etypes_len,
                krb5_enctype *negotiated_etype)
{
    int i, j;

    *negotiated_etype = ENCTYPE_NULL;

    /* mandatory segment of desired_etypes must be permitted */
    for (i = mandatory_etypes_index; i < desired_etypes_len; i++) {
        krb5_boolean permitted = FALSE;

        for (j = 0; j < permitted_etypes_len; j++) {
            if (desired_etypes[i] == permitted_etypes[j]) {
                permitted = TRUE;
                break;
            }
        }

        if (permitted == FALSE) {
            char enctype_name[30];

            if (krb5_enctype_to_string(desired_etypes[i],
                                       enctype_name,
                                       sizeof(enctype_name)) == 0)
                krb5_set_error_message(context, KRB5_NOPERM_ETYPE,
                                       _("Encryption type %s not permitted"),
                                       enctype_name);
            return KRB5_NOPERM_ETYPE;
        }
    }

    /*
     * permitted_etypes is ordered from most to least preferred;
     * find first desired_etype that matches.
     */
    for (j = 0; j < permitted_etypes_len; j++) {
        for (i = 0; i < desired_etypes_len; i++) {
            if (desired_etypes[i] == permitted_etypes[j]) {
                *negotiated_etype = permitted_etypes[j];
                return 0;
            }
        }
    }

    /*NOTREACHED*/
    return KRB5_NOPERM_ETYPE;
}

static krb5_error_code
decode_etype_list(krb5_context context,
                  const krb5_authenticator *authp,
                  krb5_enctype **desired_etypes,
                  int *desired_etypes_len)
{
    krb5_error_code code;
    krb5_authdata **ad_if_relevant = NULL;
    krb5_authdata *etype_adata = NULL;
    krb5_etype_list *etype_list = NULL;
    int i, j;
    krb5_data data;

    *desired_etypes = NULL;

    if (authp->authorization_data == NULL)
        return 0;

    /*
     * RFC 4537 says that ETYPE_NEGOTIATION auth data should be wrapped
     * in AD_IF_RELEVANT, but we handle the case where it is mandatory.
     */
    for (i = 0; authp->authorization_data[i] != NULL; i++) {
        switch (authp->authorization_data[i]->ad_type) {
        case KRB5_AUTHDATA_IF_RELEVANT:
            code = krb5_decode_authdata_container(context,
                                                  KRB5_AUTHDATA_IF_RELEVANT,
                                                  authp->authorization_data[i],
                                                  &ad_if_relevant);
            if (code != 0)
                continue;

            for (j = 0; ad_if_relevant[j] != NULL; j++) {
                if (ad_if_relevant[j]->ad_type == KRB5_AUTHDATA_ETYPE_NEGOTIATION) {
                    etype_adata = ad_if_relevant[j];
                    break;
                }
            }
            if (etype_adata == NULL) {
                krb5_free_authdata(context, ad_if_relevant);
                ad_if_relevant = NULL;
            }
            break;
        case KRB5_AUTHDATA_ETYPE_NEGOTIATION:
            etype_adata = authp->authorization_data[i];
            break;
        default:
            break;
        }
        if (etype_adata != NULL)
            break;
    }

    if (etype_adata == NULL)
        return 0;

    data.data = (char *)etype_adata->contents;
    data.length = etype_adata->length;

    code = decode_krb5_etype_list(&data, &etype_list);
    if (code == 0) {
        *desired_etypes = etype_list->etypes;
        *desired_etypes_len = etype_list->length;
        free(etype_list);
    }

    if (ad_if_relevant != NULL)
        krb5_free_authdata(context, ad_if_relevant);

    return code;
}
