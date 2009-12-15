/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/hdb/kdb_windc.c
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <utime.h>
#include "kdb5.h"
#include "kdb_hdb.h"

/*
 * WinDC helpers
 */

static krb5_error_code
kh_windc_pac_generate(krb5_context context,
                      kh_db_context *kh,
                      struct hdb_entry_ex *hentry,
                      heim_pac *pac)
{
    if (kh->windc == NULL || kh->windc->pac_generate == NULL)
        return KRB5_KDB_DBTYPE_NOSUP;

    return kh_map_error((*kh->windc->pac_generate)(kh->windc_ctx,
                                                   kh->hcontext,
                                                   hentry,
                                                   pac));
}

static krb5_error_code
kh_windc_pac_verify(krb5_context context,
                    kh_db_context *kh,
                    const Principal *principal,
                    struct hdb_entry_ex *client,
                    struct hdb_entry_ex *server,
                    heim_pac *pac)
{
    if (kh->windc == NULL || kh->windc->pac_verify == NULL)
        return KRB5_KDB_DBTYPE_NOSUP;

    return kh_map_error((*kh->windc->pac_verify)(kh->windc_ctx,
                                                 kh->hcontext,
                                                 principal,
                                                 client,
                                                 server,
                                                 pac));
}

static krb5_error_code
kh_windc_client_access(krb5_context context,
                       kh_db_context *kh,
                       struct hdb_entry_ex *client,
                       KDC_REQ *req,
                       heim_octet_string *e_data)
{
    if (kh->windc == NULL || kh->windc->client_access == NULL)
        return KRB5_KDB_DBTYPE_NOSUP;

    return kh_map_error((*kh->windc->client_access)(kh->windc_ctx,
                                                    kh->hcontext,
                                                    client,
                                                    req,
                                                    e_data));
}

static void
kh_pac_free(krb5_context context, heim_pac pac)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    assert(kh->heim_pac_free != NULL);

    if (pac != NULL)
        (*kh->heim_pac_free)(kh->hcontext, pac);
}

static krb5_error_code
kh_pac_parse(krb5_context context,
             const void *data,
             size_t len,
             heim_pac *pac)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    return kh_map_error((*kh->heim_pac_parse)(kh->hcontext,
                                              data,
                                              len,
                                              pac));
}

static krb5_error_code
kh_pac_verify(krb5_context context,
              const heim_pac pac,
              time_t authtime,
              const Principal *princ,
              const EncryptionKey *server,
              const EncryptionKey *krbtgt)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    assert(kh->heim_pac_verify != NULL);

    return kh_map_error((*kh->heim_pac_verify)(kh->hcontext,
                                               pac,
                                               authtime,
                                               princ,
                                               server,
                                               krbtgt));
}

static krb5_error_code
kh_pac_sign(krb5_context context,
            heim_pac pac,
            time_t authtime,
            Principal *princ,
            const EncryptionKey *server,
            const EncryptionKey *krbtgt,
            heim_octet_string *data)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);

    assert(kh->heim_pac_sign != NULL);

    return kh_map_error((*kh->heim_pac_sign)(kh->hcontext,
                                             pac,
                                             authtime,
                                             princ,
                                             server,
                                             krbtgt,
                                             data));
}

/*
 * Get local TGS key for the realm of the supplied principal.
 */
static krb5_error_code
kh_get_tgs_key(krb5_context context,
               kh_db_context *kh,
               const krb5_principal princ,
               krb5_keyblock *krbtgt_keyblock)
{
    krb5_error_code code;
    krb5_principal tgsname = NULL;
    krb5_key_data *krbtgt_key = NULL;
    krb5_db_entry krbtgt;

    memset(&krbtgt, 0, sizeof(krbtgt));
    krbtgt_keyblock->contents = NULL;

    code = krb5_build_principal_ext(context,
                                    &tgsname,
                                    princ->realm.length,
                                    princ->realm.data,
                                    KRB5_TGS_NAME_SIZE,
                                    KRB5_TGS_NAME,
                                    princ->realm.length,
                                    princ->realm.data,
                                    0);
    if (code != 0)
        goto cleanup;

    code = kh_get_principal(context, kh, tgsname, HDB_F_GET_KRBTGT, &krbtgt);
    if (code != 0)
        goto cleanup;

    code = krb5_dbe_find_enctype(context,
                                 &krbtgt,
                                 -1,    /* ignore enctype */
                                 -1,    /* ignore salttype */
                                 0,     /* highest kvno */
                                 &krbtgt_key);
    if (code != 0)
        goto cleanup;
    else if (krbtgt_key == NULL) {
        code = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        goto cleanup;
    }

    code = kh_decrypt_key(context,
                          KH_DB_CONTEXT(context),
                          krbtgt_key,
                          krbtgt_keyblock,
                          NULL);
    if (code != 0)
        goto cleanup;

cleanup:
    kh_kdb_free_entry(context, KH_DB_CONTEXT(context), &krbtgt);
    krb5_free_principal(context, tgsname);

    return code;
}

krb5_error_code
kh_db_sign_auth_data(krb5_context context,
                     unsigned int method,
                     const krb5_data *req_data,
                     krb5_data *rep_data)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    kdb_sign_auth_data_req *req = (kdb_sign_auth_data_req *)req_data->data;
    kdb_sign_auth_data_rep *rep = (kdb_sign_auth_data_rep *)rep_data->data;
    heim_pac hpac = NULL;
    heim_octet_string pac_data;
    krb5_boolean is_as_req;
    krb5_error_code code;
    krb5_authdata **authdata = NULL;
    Principal *client_hprinc = NULL;
    EncryptionKey server_hkey;
    EncryptionKey krbtgt_hkey;
    krb5_keyblock krbtgt_kkey;

    if (kh->windc == NULL)
        return KRB5_KDB_DBTYPE_NOSUP; /* short circuit */

    memset(rep, 0, sizeof(*rep));
    memset(&krbtgt_kkey, 0, sizeof(krbtgt_kkey));
    pac_data.data = NULL;

    is_as_req = ((req->flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) != 0);

    /* Prefer canonicalised name from client entry */
    if (req->client != NULL) {
        client_hprinc = KH_DB_ENTRY(req->client)->entry.principal;
    } else {
        code = kh_marshal_Principal(context, req->client_princ, &client_hprinc);
        if (code != 0)
            goto cleanup;
    }

    KH_MARSHAL_KEY(req->server_key, &server_hkey);
    KH_MARSHAL_KEY(req->krbtgt_key, &krbtgt_hkey);

    if (!is_as_req) {
        /* find the existing PAC, if present */
        code = krb5int_find_authdata(context,
                                     req->auth_data,
                                     NULL,
                                     KRB5_AUTHDATA_WIN2K_PAC,
                                     &authdata);
        if (code != 0)
            goto cleanup;
    }

    if ((is_as_req && (req->flags & KRB5_KDB_FLAG_INCLUDE_PAC)) ||
        (authdata == NULL && req->client != NULL)) {
        code = kh_windc_pac_generate(context, kh,
                                     KH_DB_ENTRY(req->client), &hpac);
        if (code != 0)
            goto cleanup;
    } else if (authdata != NULL) {
        assert(authdata[0] != NULL);

        if (authdata[1] != NULL) {
            code = KRB5KDC_ERR_BADOPTION; /* XXX */
            goto cleanup;
        }

        pac_data.data   = authdata[0]->contents;
        pac_data.length = authdata[0]->length;

        code = kh_pac_parse(context, pac_data.data, pac_data.length, &hpac);
        if (code != 0)
            goto cleanup;

        /*
         * In the constrained delegation case, the PAC is from a service
         * ticket rather than a TGT; we must verify the server and KDC
         * signatures to assert that the server did not forge the PAC.
         */
        if (req->flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
            code = kh_pac_verify(context, hpac, req->authtime,
                                 client_hprinc, &server_hkey, &krbtgt_hkey);
        } else {
            code = kh_pac_verify(context, hpac, req->authtime,
                                 client_hprinc, &krbtgt_hkey, NULL);
        }
        if (code != 0)
            goto cleanup;

        code = kh_windc_pac_verify(context, kh, client_hprinc,
                                   req->client ?
                                   KH_DB_ENTRY(req->client) : NULL,
                                   KH_DB_ENTRY(req->server),
                                   &hpac);
        if (code != 0)
            goto cleanup;
    } else {
        code = KRB5_KDB_DBTYPE_NOSUP;
        goto cleanup;
    }

    /*
     * In the cross-realm case, krbtgt_hkey refers to the cross-realm
     * TGS key, so we need to explicitly lookup our TGS key.
     */
    if (req->flags & KRB5_KDB_FLAG_CROSS_REALM) {
        assert(!is_as_req);

        code = kh_get_tgs_key(context, kh, req->server->princ, &krbtgt_kkey);
        if (code != 0)
            goto cleanup;

        KH_MARSHAL_KEY(&krbtgt_kkey, &krbtgt_hkey);
    }

    code = kh_pac_sign(context, hpac, req->authtime, client_hprinc,
                       &server_hkey, &krbtgt_hkey, &pac_data);
    if (code != 0)
        goto cleanup;

    if (authdata == NULL) {
        authdata = k5alloc(2 * sizeof(krb5_authdata *), &code);
        if (code != 0)
            goto cleanup;

        authdata[0] = k5alloc(sizeof(krb5_authdata), &code);
        if (code != 0)
            goto cleanup;

        authdata[1] = NULL;
    } else {
        free(authdata[0]->contents);
        authdata[0]->contents = NULL;
        authdata[0]->length = 0;
    }

    /* take ownership of pac_data */
    authdata[0]->magic    = KV5M_AUTHDATA;
    authdata[0]->ad_type  = KRB5_AUTHDATA_WIN2K_PAC;
    authdata[0]->contents = pac_data.data;
    authdata[0]->length   = pac_data.length;

    pac_data.data = NULL;

    code = krb5_encode_authdata_container(context,
                                          KRB5_AUTHDATA_IF_RELEVANT,
                                          authdata,
                                          &rep->auth_data);
    if (code != 0)
        goto cleanup;

cleanup:
    if (req->client == NULL)
        kh_free_Principal(context, client_hprinc);
    kh_pac_free(context, hpac);
    if (pac_data.data != NULL)
        free(pac_data.data);
    krb5_free_authdata(context, authdata);
    krb5_free_keyblock_contents(context, &krbtgt_kkey);

    return code;
}

static krb5_error_code
kh_marshal_KDCOptions(krb5_context context,
                      krb5_flags koptions,
                      KDCOptions *hoptions)
{
    memset(hoptions, 0, sizeof(*hoptions));

    if (koptions & KDC_OPT_FORWARDABLE)
        hoptions->forwardable = 1;
    if (koptions & KDC_OPT_FORWARDED)
        hoptions->forwarded = 1;
    if (koptions & KDC_OPT_PROXIABLE)
        hoptions->proxiable = 1;
    if (koptions & KDC_OPT_PROXY)
        hoptions->proxy = 1;
    if (koptions & KDC_OPT_ALLOW_POSTDATE)
        hoptions->allow_postdate = 1;
    if (koptions & KDC_OPT_POSTDATED)
        hoptions->postdated = 1;
    if (koptions & KDC_OPT_RENEWABLE)
        hoptions->renewable = 1;
    if (koptions & KDC_OPT_REQUEST_ANONYMOUS)
        hoptions->request_anonymous = 1;
    if (koptions & KDC_OPT_CANONICALIZE)
        hoptions->canonicalize = 1;
    if (koptions & KDC_OPT_DISABLE_TRANSITED_CHECK)
        hoptions->disable_transited_check = 1;
    if (koptions & KDC_OPT_RENEWABLE_OK)
        hoptions->renewable_ok = 1;
    if (koptions & KDC_OPT_ENC_TKT_IN_SKEY)
        hoptions->enc_tkt_in_skey = 1;
    if (koptions & KDC_OPT_RENEW)
        hoptions->renew = 1;
    if (koptions & KDC_OPT_VALIDATE)
        hoptions->validate = 1;

    return 0;
}

static krb5_error_code
kh_marshall_HostAddress(krb5_context context,
                        krb5_address *kaddress,
                        HostAddress *haddress)
{
    haddress->addr_type = kaddress->addrtype;
    haddress->address.data = malloc(kaddress->length);
    if (haddress->address.data == NULL)
        return ENOMEM;

    memcpy(haddress->address.data, kaddress->contents, kaddress->length);
    haddress->address.length = kaddress->length;

    return 0;
}

static krb5_error_code
kh_marshall_HostAddresses(krb5_context context,
                          krb5_address **kaddresses,
                          HostAddresses **phaddresses)
{
    krb5_error_code code;
    HostAddresses *haddresses;
    int i;

    *phaddresses = NULL;

    if (kaddresses == NULL)
        return 0;

    for (i = 0; kaddresses[i] != NULL; i++)
        ;

    haddresses = k5alloc(sizeof(*haddresses), &code);
    if (code != 0)
        return code;

    haddresses->len = 0;
    haddresses->val = k5alloc(i * sizeof(HostAddress), &code);
    if (code != 0)
        return code;

    for (i = 0; kaddresses[i] != NULL; i++) {
        code = kh_marshall_HostAddress(context,
                                       kaddresses[i],
                                       &haddresses->val[i]);
        if (code != 0)
            break;

        haddresses->len++;
    }

    if (code != 0) {
        free(haddresses->val);
        free(haddresses);
    } else {
        *phaddresses = haddresses;
    }

    return code;
}

krb5_error_code
kh_db_check_policy_as(krb5_context context,
                      unsigned int method,
                      const krb5_data *req_data,
                      krb5_data *rep_data)
{
    kh_db_context *kh = KH_DB_CONTEXT(context);
    kdb_check_policy_as_req *req = (kdb_check_policy_as_req *)req_data->data;
    kdb_check_policy_as_rep *rep = (kdb_check_policy_as_rep *)rep_data->data;
    krb5_error_code code;
    heim_octet_string e_data;
    krb5_kdc_req *kkdcreq = req->request;
    KDC_REQ hkdcreq;
    Principal *hclient = NULL;
    Principal *hserver = NULL;
    time_t from, till, rtime;

    if (kh->windc == NULL)
        return KRB5_KDB_DBTYPE_NOSUP; /* short circuit */

    memset(&hkdcreq, 0, sizeof(hkdcreq));

    hkdcreq.pvno = KRB5_PVNO;
    hkdcreq.msg_type = kkdcreq->msg_type;
    hkdcreq.padata = NULL; /* FIXME */
    code = kh_marshal_KDCOptions(context,
                                 kkdcreq->kdc_options,
                                 &hkdcreq.req_body.kdc_options);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_Principal(context, kkdcreq->client, &hclient);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_Principal(context, kkdcreq->server, &hserver);
    if (code != 0)
        goto cleanup;

    hkdcreq.req_body.cname = &hclient->name;
    hkdcreq.req_body.realm = hserver->realm;
    hkdcreq.req_body.sname = &hserver->name;

    from  = kkdcreq->from;  hkdcreq.req_body.from = &from;
    till  = kkdcreq->till;  hkdcreq.req_body.till = &till;
    rtime = kkdcreq->rtime; hkdcreq.req_body.rtime = &rtime;

    hkdcreq.req_body.nonce     = kkdcreq->nonce;
    hkdcreq.req_body.etype.len = kkdcreq->nktypes;
    hkdcreq.req_body.etype.val = kkdcreq->ktype;

    code = kh_marshall_HostAddresses(context,
                                     kkdcreq->addresses,
                                     &hkdcreq.req_body.addresses);
    if (code != 0)
        goto cleanup;

    /* FIXME hkdcreq.req_body.enc_authorization_data */
    /* FIXME hkdcreq.req_body.additional_tickets */

    code = kh_windc_client_access(context, kh,
                                  KH_DB_ENTRY(req->client),
                                  &hkdcreq, &e_data);

    rep->e_data.data   = e_data.data;
    rep->e_data.length = e_data.length;

cleanup:
    kh_free_HostAddresses(context, hkdcreq.req_body.addresses);
    kh_free_Principal(context, hclient);
    kh_free_Principal(context, hserver);

    return code;
}

krb5_error_code
kh_hdb_windc_init(krb5_context context,
                  const char *libdir,
                  kh_db_context *kh)
{
    krb5_error_code code;
    const char *objdirs[2];
    void **tables = NULL;
    int i;

    memset(&kh->windc_plugins, 0, sizeof(kh->windc_plugins));

    code = PLUGIN_DIR_OPEN(&kh->windc_plugins);
    if (code != 0)
        return code;

    objdirs[0] = libdir;
    objdirs[1] = NULL;

    code = krb5int_open_plugin_dirs(objdirs, NULL,
                                    &kh->windc_plugins,
                                    &context->err);
    if (code != 0)
        return code;

    code = krb5int_get_plugin_dir_data(&kh->windc_plugins,
                                       "windc",
                                       &tables,
                                       &context->err);
    if (code != 0)
        return code;

    code = KRB5_KDB_DBTYPE_NOSUP;

    for (i = 0; tables[i] != NULL; i++) {
        krb5plugin_windc_ftable *windc = tables[i];

        if (windc->minor_version < KRB5_WINDC_PLUGIN_MINOR)
            continue;

        code = kh_map_error((*windc->init)(kh->hcontext, &kh->windc_ctx));
        if (code != 0)
            continue;

        kh->windc = windc;
        break;
    }

    if (tables != NULL)
        krb5int_free_plugin_dir_data(tables);

    return code;
}
