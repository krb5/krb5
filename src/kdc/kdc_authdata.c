/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/kdc_authdata.c - Authorization data routines for the KDC */
/*
 * Copyright (C) 2007 Apple Inc.  All Rights Reserved.
 * Copyright (C) 2008, 2009 by the Massachusetts Institute of Technology.
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
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>
#include "adm_proto.h"

#include <syslog.h>

#include <assert.h>
#include <krb5/kdcauthdata_plugin.h>

typedef struct kdcauthdata_handle_st {
    struct krb5_kdcauthdata_vtable_st vt;
    krb5_kdcauthdata_moddata data;
} kdcauthdata_handle;

static kdcauthdata_handle *authdata_modules;
static size_t n_authdata_modules;

/* Load authdata plugin modules. */
krb5_error_code
load_authdata_plugins(krb5_context context)
{
    krb5_error_code ret;
    krb5_plugin_initvt_fn *modules = NULL, *mod;
    kdcauthdata_handle *list, *h;
    size_t count;

    ret = k5_plugin_load_all(context, PLUGIN_INTERFACE_KDCAUTHDATA, &modules);
    if (ret)
        return ret;

    /* Allocate a large enough list of handles. */
    for (count = 0; modules[count] != NULL; count++);
    list = calloc(count + 1, sizeof(*list));
    if (list == NULL) {
        k5_plugin_free_modules(context, modules);
        return ENOMEM;
    }

    /* Initialize each module's vtable and module data. */
    count = 0;
    for (mod = modules; *mod != NULL; mod++) {
        h = &list[count];
        memset(h, 0, sizeof(*h));
        ret = (*mod)(context, 1, 1, (krb5_plugin_vtable)&h->vt);
        if (ret)                /* Version mismatch, keep going. */
            continue;
        if (h->vt.init != NULL) {
            ret = h->vt.init(context, &h->data);
            if (ret) {
                kdc_err(context, ret, _("while loading authdata module %s"),
                        h->vt.name);
                continue;
            }
        }
        count++;
    }

    authdata_modules = list;
    n_authdata_modules = count;
    k5_plugin_free_modules(context, modules);
    return 0;
}

krb5_error_code
unload_authdata_plugins(krb5_context context)
{
    kdcauthdata_handle *h;
    size_t i;

    for (i = 0; i < n_authdata_modules; i++) {
        h = &authdata_modules[i];
        if (h->vt.fini != NULL)
            h->vt.fini(context, h->data);
    }
    free(authdata_modules);
    authdata_modules = NULL;
    return 0;
}

/* Return true if authdata should be filtered when copying from untrusted
 * authdata.  If desired_type is non-zero, look only for that type. */
static krb5_boolean
is_kdc_issued_authdatum(krb5_authdata *authdata,
                        krb5_authdatatype desired_type)
{
    krb5_boolean result = FALSE;
    krb5_authdatatype ad_type;
    unsigned int i, count = 0;
    krb5_authdatatype *ad_types, *containee_types = NULL;

    if (authdata->ad_type == KRB5_AUTHDATA_IF_RELEVANT) {
        if (krb5int_get_authdata_containee_types(NULL, authdata, &count,
                                                 &containee_types) != 0)
            goto cleanup;
        ad_types = containee_types;
    } else {
        ad_type = authdata->ad_type;
        count = 1;
        ad_types = &ad_type;
    }

    for (i = 0; i < count; i++) {
        switch (ad_types[i]) {
        case KRB5_AUTHDATA_SIGNTICKET:
        case KRB5_AUTHDATA_KDC_ISSUED:
        case KRB5_AUTHDATA_WIN2K_PAC:
        case KRB5_AUTHDATA_CAMMAC:
        case KRB5_AUTHDATA_AUTH_INDICATOR:
            result = desired_type ? (desired_type == ad_types[i]) : TRUE;
            break;
        default:
            result = FALSE;
            break;
        }
        if (result)
            break;
    }

cleanup:
    free(containee_types);
    return result;
}

/* Return true if authdata contains any mandatory-for-KDC elements. */
static krb5_boolean
has_mandatory_for_kdc_authdata(krb5_context context, krb5_authdata **authdata)
{
    int i;

    if (authdata == NULL)
        return FALSE;
    for (i = 0; authdata[i] != NULL; i++) {
        if (authdata[i]->ad_type == KRB5_AUTHDATA_MANDATORY_FOR_KDC)
            return TRUE;
    }
    return FALSE;
}

/* Add elements from *new_elements to *existing_list, reallocating as
 * necessary.  On success, release *new_elements and set it to NULL. */
static krb5_error_code
merge_authdata(krb5_authdata ***existing_list, krb5_authdata ***new_elements)
{
    size_t count = 0, ncount = 0;
    krb5_authdata **list = *existing_list, **nlist = *new_elements;

    if (nlist == NULL)
        return 0;

    for (count = 0; list != NULL && list[count] != NULL; count++);
    for (ncount = 0; nlist[ncount] != NULL; ncount++);

    list = realloc(list, (count + ncount + 1) * sizeof(*list));
    if (list == NULL)
        return ENOMEM;

    memcpy(list + count, nlist, ncount * sizeof(*nlist));
    list[count + ncount] = NULL;
    free(nlist);

    if (list[0] == NULL) {
        free(list);
        list = NULL;
    }

    *new_elements = NULL;
    *existing_list = list;
    return 0;
}

/* Add a copy of new_elements to *existing_list, omitting KDC-issued
 * authdata. */
static krb5_error_code
add_filtered_authdata(krb5_authdata ***existing_list,
                      krb5_authdata **new_elements)
{
    krb5_error_code ret;
    krb5_authdata **copy;
    size_t i, j;

    if (new_elements == NULL)
        return 0;

    ret = krb5_copy_authdata(NULL, new_elements, &copy);
    if (ret)
        return ret;

    /* Remove KDC-issued elements from copy. */
    j = 0;
    for (i = 0; copy[i] != NULL; i++) {
        if (is_kdc_issued_authdatum(copy[i], 0)) {
            free(copy[i]->contents);
            free(copy[i]);
        } else {
            copy[j++] = copy[i];
        }
    }
    copy[j] = NULL;

    /* Destructively merge the filtered copy into existing_list. */
    ret = merge_authdata(existing_list, &copy);
    krb5_free_authdata(NULL, copy);
    return ret;
}

/* Copy TGS-REQ authorization data into the ticket authdata. */
static krb5_error_code
copy_request_authdata(krb5_context context, krb5_keyblock *client_key,
                      krb5_kdc_req *req, krb5_enc_tkt_part *enc_tkt_req,
                      krb5_authdata ***tkt_authdata)
{
    krb5_error_code ret;
    krb5_data plaintext;

    assert(enc_tkt_req != NULL);

    ret = alloc_data(&plaintext, req->authorization_data.ciphertext.length);
    if (ret)
        return ret;

    /*
     * RFC 4120 requires authdata in the TGS body to be encrypted in the subkey
     * with usage 5 if a subkey is present, and in the TGS session key with key
     * usage 4 if it is not.  Prior to krb5 1.7, we got this wrong, always
     * decrypting the authorization data with the TGS session key and usage 4.
     * For the sake of conservatism, try the decryption the old way (wrong if
     * client_key is a subkey) first, and then try again the right way (in the
     * case where client_key is a subkey) if the first way fails.
     */
    ret = krb5_c_decrypt(context, enc_tkt_req->session,
                         KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY, 0,
                         &req->authorization_data, &plaintext);
    if (ret) {
        ret = krb5_c_decrypt(context, client_key,
                             KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY, 0,
                             &req->authorization_data, &plaintext);
    }
    if (ret)
        goto cleanup;

    /* Decode the decrypted authdata and make it available to modules in the
     * request. */
    ret = decode_krb5_authdata(&plaintext, &req->unenc_authdata);
    if (ret)
        goto cleanup;

    if (has_mandatory_for_kdc_authdata(context, req->unenc_authdata)) {
        ret = KRB5KDC_ERR_POLICY;
        goto cleanup;
    }

    ret = add_filtered_authdata(tkt_authdata, req->unenc_authdata);

cleanup:
    free(plaintext.data);
    return ret;
}

/* Copy TGT authorization data into the ticket authdata. */
static krb5_error_code
copy_tgt_authdata(krb5_context context, krb5_kdc_req *request,
                  krb5_authdata **tgt_authdata, krb5_authdata ***tkt_authdata)
{
    if (has_mandatory_for_kdc_authdata(context, tgt_authdata))
        return KRB5KDC_ERR_POLICY;

    return add_filtered_authdata(tkt_authdata, tgt_authdata);
}

/* Add authentication indicator authdata to enc_tkt_reply, wrapped in a CAMMAC
 * and an IF-RELEVANT container. */
static krb5_error_code
add_auth_indicators(krb5_context context, krb5_data *const *auth_indicators,
                    krb5_keyblock *server_key, krb5_db_entry *krbtgt,
                    krb5_keyblock *krbtgt_key,
                    krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code ret;
    krb5_data *der_indicators = NULL;
    krb5_authdata ad, *list[2], **cammac = NULL;

    /* Format the authentication indicators into an authdata list. */
    ret = encode_utf8_strings(auth_indicators, &der_indicators);
    if (ret)
        goto cleanup;
    ad.ad_type = KRB5_AUTHDATA_AUTH_INDICATOR;
    ad.length = der_indicators->length;
    ad.contents = (uint8_t *)der_indicators->data;
    list[0] = &ad;
    list[1] = NULL;

    /* Wrap the list in CAMMAC and IF-RELEVANT containers. */
    ret = cammac_create(context, enc_tkt_reply, server_key, krbtgt, krbtgt_key,
                        list, &cammac);
    if (ret)
        goto cleanup;

    /* Add the wrapped authdata to the ticket, without copying or filtering. */
    ret = merge_authdata(&enc_tkt_reply->authorization_data, &cammac);

cleanup:
    krb5_free_data(context, der_indicators);
    krb5_free_authdata(context, cammac);
    return ret;
}

/* Extract any properly verified authentication indicators from the authdata in
 * enc_tkt. */
krb5_error_code
get_auth_indicators(krb5_context context, krb5_enc_tkt_part *enc_tkt,
                    krb5_db_entry *local_tgt, krb5_keyblock *local_tgt_key,
                    krb5_data ***indicators_out)
{
    krb5_error_code ret;
    krb5_authdata **cammacs = NULL, **adp;
    krb5_cammac *cammac = NULL;
    krb5_data **indicators = NULL, der_cammac;

    *indicators_out = NULL;

    ret = krb5_find_authdata(context, enc_tkt->authorization_data, NULL,
                             KRB5_AUTHDATA_CAMMAC, &cammacs);
    if (ret)
        goto cleanup;

    for (adp = cammacs; adp != NULL && *adp != NULL; adp++) {
        der_cammac = make_data((*adp)->contents, (*adp)->length);
        ret = decode_krb5_cammac(&der_cammac, &cammac);
        if (ret)
            goto cleanup;
        if (cammac_check_kdcver(context, cammac, enc_tkt, local_tgt,
                                local_tgt_key)) {
            ret = authind_extract(context, cammac->elements, &indicators);
            if (ret)
                goto cleanup;
        }
        k5_free_cammac(context, cammac);
        cammac = NULL;
    }

    *indicators_out = indicators;
    indicators = NULL;

cleanup:
    krb5_free_authdata(context, cammacs);
    k5_free_cammac(context, cammac);
    k5_free_data_ptr_list(indicators);
    return ret;
}

struct krb5_pac_data *
k5_get_pac(krb5_context context, krb5_authdata **authdata)
{
    size_t i, j;
    krb5_authdata *res = NULL, **decoded_container = NULL;
    struct krb5_pac_data *pac;
    krb5_error_code kerr;

    for (i = 0; authdata == NULL || authdata[i] != NULL; i++) {
        if (authdata[i]->ad_type != KRB5_AUTHDATA_IF_RELEVANT)
            continue;

        kerr = krb5_decode_authdata_container(context,
                                              KRB5_AUTHDATA_IF_RELEVANT,
                                              authdata[i],
                                              &decoded_container);
        if (kerr)
            return NULL;

        for (j = 0; decoded_container[j] != NULL; j++) {
            if (decoded_container[j]->ad_type != KRB5_AUTHDATA_WIN2K_PAC)
                continue;
            res = decoded_container[j];
        }
        if (res != NULL)
            break;

        /* TODO this leaks sometimes - fix it */
        krb5_free_authdata(context, decoded_container);
    }
    if (res == NULL)
        return NULL;

    if (krb5_pac_parse(context, res->contents, res->length, &pac))
        return NULL;

    return pac;
}

static krb5_error_code
update_cd(krb5_context context, unsigned int flags, krb5_db_entry *client,
          krb5_db_entry *server, krb5_pac old_pac, krb5_pac new_pac)
{
    krb5_error_code ret;
    krb5_data data = empty_data();
    struct pac_s4u_delegation_info *di = NULL;
    char *namestr;

    if (!(flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)) {
        ret = 0;
        goto done;
    }

    ret = krb5_pac_get_buffer(context, old_pac, KRB5_PAC_DELEGATION_INFO,
                              &data);
    if (ret) {
        /* Empty - start of delegation. */
        di = k5calloc(1, sizeof(*di), &ret);
        if (di == NULL)
            goto done;
        di->transited_services = k5calloc(1, sizeof(char *), &ret);
    } else {
        ret = ndr_dec_delegation_info(&data, &di);
    }
    if (ret)
        goto done;

    /* Update target to proxy->princ. */
    ret = krb5_unparse_name(context, client->princ, &namestr);
    if (ret)
        goto done;

    free(di->proxy_target);
    di->proxy_target = namestr;

    /* Add entry to transited services. */
    ret = krb5_unparse_name(context, server->princ, &namestr);
    if (ret)
        goto done;

    di->transited_services[di->transited_services_length++] = namestr;

    ret = ndr_enc_delegation_info(di, &data);
    if (ret)
        goto done;

    ret = krb5_pac_add_buffer(context, new_pac, KRB5_PAC_DELEGATION_INFO,
                              &data);
done:
    krb5_free_data_contents(context, &data);
    ndr_free_delegation_info(&di);
    return ret;
}

krb5_error_code
k5_verify_pac_signatures(krb5_context context, unsigned int flags,
                         krb5_ticket *ticket, krb5_const_principal princ,
                         krb5_keyblock *tgt_key)
{
    /*
     * The service key is known to the service, so there's no purpose checking
     * it most of the time - just check the KDC signature.  However, in a
     * cross-realm TGS request, the KDC key is unknown to us, while the
     * service key is the cross-realm key, so the two are "reversed".  Note
     * that in this case, the Ticket Signature will also not be checkable.
     */
    if (isflagset(flags, KRB5_KDB_FLAG_CROSS_REALM))
        return krb5_kdc_verify_ticket(context, ticket, princ, tgt_key, NULL);
    return krb5_kdc_verify_ticket(context, ticket, princ, NULL, tgt_key);
}

/*
 * MS-KILE (3.3.5.3) says to issue a PAC only when requested (but that clients
 * will always request in AS-REQ), and either:
 *
 *   - AS-REQ which preauth and for which PAC generation isn't disabled
 *   - successful TGS-REQ when it wasn't disabled in the incoming PAC
 *
 * MS-KILE (3.3.5.7.2) says that TGS-REQ from a TGT without a PAC "SHOULD"
 * result in a service ticket with a fresh PAC.  (3.3.5.7) says that
 * otherwise, the PAC fields are copied from the TGT.  (Signatures are
 * updated, though it does not mention this.)
 *
 * So if the incoming request had one (TGS), we verify it and attach it,
 * resigned.  Otherwise, we ask the KDB for a fresh one.
 */
static krb5_error_code
handle_pac(krb5_context context, unsigned int flags,
           krb5_db_entry *client, krb5_db_entry *server,
           krb5_db_entry *subject_server, krb5_db_entry *local_tgt,
           krb5_keyblock *local_tgt_key, krb5_keyblock *server_key,
           krb5_keyblock *subject_key, krb5_const_principal altcprinc,
           krb5_timestamp authtime, krb5_ticket *old_ticket,
           krb5_ticket *new_ticket)
{
    krb5_error_code ret;
    krb5_pac old_pac = NULL, new_pac = NULL;
    krb5_const_principal client_princ = NULL, verify_princ = NULL;
    krb5_keyblock *verify_key = subject_key;
    krb5_ui_4 *types;
    size_t num_buffers = 0, i;
    krb5_data data = empty_data();

    if (isflagset(flags, KRB5_KDB_FLAGS_S4U) &&
        isflagset(flags, KRB5_KDB_FLAG_ISSUING_REFERRAL))
        client_princ = altcprinc;

    if (old_ticket != NULL) {
        old_pac = k5_get_pac(context,
                             old_ticket->enc_part2->authorization_data);
    }
    if (old_pac == NULL && (flags & NON_TGT_OPTION)) {
        /* Don't add a PAC during modifications that didn't start with one. */
        ret = 0;
        goto done;
    } else if (old_pac != NULL) {
        if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)
            verify_key = local_tgt_key;

        if (client == NULL)
            verify_princ = altcprinc;

        ret = k5_verify_pac_signatures(context, flags, old_ticket,
                                       verify_princ, verify_key);
        if (ret)
            goto done;
    }

    ret = krb5_pac_init(context, &new_pac);
    if (ret)
        goto done;

    /* Skip the KDB for modifications of tickets with valid PACs.  (Here, all
     * modifications have an old PAC.) */
    if (!(flags & NON_TGT_OPTION)) {
        ret = krb5_db_issue_pac(context, flags,
                                /* TODO: fix this */
                                (client != NULL) ? client->princ : new_ticket->enc_part2->client,
                                client, authtime, old_pac, new_pac);
        if (ret && ret != KRB5_PLUGIN_OP_NOTSUPP)
            goto done;
    }
    if (ret == KRB5_PLUGIN_OP_NOTSUPP || (flags & NON_TGT_OPTION)) {
        if (old_pac != NULL) {
            ret = krb5_pac_get_types(context, old_pac, &num_buffers, &types);
            if (ret)
                goto done;
        }

        for (i = 0; i < num_buffers; i++) {
            if (types[i] == KRB5_PAC_SERVER_CHECKSUM ||
                types[i] == KRB5_PAC_PRIVSVR_CHECKSUM ||
                types[i] == KRB5_PAC_TICKET_CHECKSUM ||
                types[i] == KRB5_PAC_CLIENT_INFO ||
                ((flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) &&
                 types[i] == KRB5_PAC_DELEGATION_INFO))
                continue;

            ret = krb5_pac_get_buffer(context, old_pac, types[i], &data);
            if (ret)
                goto done;

            ret = krb5_pac_add_buffer(context, new_pac, types[i], &data);
            krb5_free_data_contents(context, &data);
            if (ret)
                goto done;
        }
    }

    ret = update_cd(context, flags, client, server, old_pac, new_pac);
    if (ret)
        goto done;

    ret = krb5_kdc_sign_ticket(context, new_ticket, new_pac, client_princ,
                               server_key, local_tgt_key);
    if (ret)
        goto done;

    ret = 0;
done:
    krb5_pac_free(context, old_pac);
    krb5_pac_free(context, new_pac);
    return ret;
}

krb5_error_code
handle_authdata(kdc_realm_t *kdc_active_realm, unsigned int flags,
                krb5_db_entry *client, krb5_db_entry *server,
                krb5_db_entry *subject_server, krb5_db_entry *local_tgt,
                krb5_keyblock *local_tgt_key, krb5_keyblock *client_key,
                krb5_keyblock *server_key, krb5_keyblock *subject_key,
                krb5_data *req_pkt, krb5_kdc_req *req,
                krb5_const_principal altcprinc,
                krb5_enc_tkt_part *enc_tkt_req,
                krb5_data ***auth_indicators,
                krb5_ticket *old_ticket, krb5_ticket *new_ticket)
{
    kdcauthdata_handle *h;
    krb5_error_code ret = 0;
    size_t i;
    krb5_context context = kdc_active_realm->realm_context;
    krb5_enc_tkt_part *enc_tkt_reply = new_ticket->enc_part2;

    if (req->msg_type == KRB5_TGS_REQ &&
        req->authorization_data.ciphertext.data != NULL) {
        /* Copy TGS request authdata.  This must be done first so that modules
         * have access to the unencrypted request authdata. */
        ret = copy_request_authdata(context, client_key, req, enc_tkt_req,
                                    &enc_tkt_reply->authorization_data);
        if (ret)
            return ret;
    }

    /* Invoke loaded module handlers. */
    if (!isflagset(enc_tkt_reply->flags, TKT_FLG_ANONYMOUS)) {
        for (i = 0; i < n_authdata_modules; i++) {
            h = &authdata_modules[i];
            ret = h->vt.handle(context, h->data, flags, client, server,
                               subject_server, client_key, server_key,
                               subject_key, req_pkt, req, altcprinc,
                               enc_tkt_req, enc_tkt_reply);
            if (ret)
                kdc_err(context, ret, "from authdata module %s", h->vt.name);
        }
    }

    if (req->msg_type == KRB5_TGS_REQ) {
        /* Copy authdata from the TGT to the issued ticket. */
        ret = copy_tgt_authdata(context, req, enc_tkt_req->authorization_data,
                                &enc_tkt_reply->authorization_data);
        if (ret)
            return ret;
    }

    /* Add auth indicators if any were given. */
    if (auth_indicators != NULL && *auth_indicators != NULL &&
        !isflagset(server->attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED)) {
        ret = add_auth_indicators(context, *auth_indicators, server_key,
                                  local_tgt, local_tgt_key, enc_tkt_reply);
        if (ret)
            return ret;
    }

    if (!kdc_active_realm->realm_disable_pac &&
        !isflagset(server->attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED)) {
        ret = handle_pac(context, flags, client, server, subject_server,
                         local_tgt, local_tgt_key, server_key, subject_key,
                         altcprinc, enc_tkt_reply->times.authtime, old_ticket,
                         new_ticket);
    }

    return ret;
}
