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
    if (kh->windc == NULL)
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
    if (kh->windc == NULL)
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
    if (kh->windc == NULL)
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

    return kh_map_error((*kh->heim_pac_sign)(kh->hcontext,
                                             pac,
                                             authtime,
                                             princ,
                                             server,
                                             krbtgt,
                                             data));
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
    EncryptionKey privsvr_hkey;

    if (kh->windc == NULL)
        return KRB5_KDB_DBTYPE_NOSUP; /* short circuit */

    memset(rep, 0, sizeof(*rep));

    pac_data.length = 0;
    pac_data.data = NULL;

    is_as_req = ((req->flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) != 0);

    /*
     * Always prefer the client name from the client entry, because we
     * know it will be canonicalised. But, in the TGS case, we won't
     * have access to that.
     */
    if (req->client != NULL) {
        client_hprinc = KH_DB_ENTRY(req->client)->entry.principal;
    } else {
        code = kh_marshal_Principal(context, req->client_princ, &client_hprinc);
        if (code != 0)
            goto cleanup;
    }

    server_hkey.keytype          = req->server_key->enctype;
    server_hkey.keyvalue.data    = req->server_key->contents;
    server_hkey.keyvalue.length  = req->server_key->length;

    privsvr_hkey.keytype         = req->krbtgt_key->enctype;
    privsvr_hkey.keyvalue.data   = req->krbtgt_key->contents;
    privsvr_hkey.keyvalue.length = req->krbtgt_key->length;

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
        EncryptionKey *skey;

        assert(authdata[0] != NULL);

        if (authdata[1] != NULL) {
            code = KRB5KDC_ERR_BADOPTION; /* XXX */
            goto cleanup;
        }

        pac_data.data = authdata[0]->contents;
        pac_data.length = authdata[0]->length;

        code = kh_pac_parse(context, pac_data.data, pac_data.length, &hpac);
        if (code != 0)
            goto cleanup;

        /*
         * In the constrained delegation case, the PAC is from a service
         * ticket rather than a TGT.
         */
        if (req->flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)
            skey = &server_hkey;
        else
            skey = &privsvr_hkey;

        code = kh_pac_verify(context, hpac, req->authtime,
                             client_hprinc, skey, &privsvr_hkey);
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

    code = kh_pac_sign(context, hpac, req->authtime, client_hprinc,
                       &server_hkey, &privsvr_hkey, &pac_data);
    if (code != 0)
        goto cleanup;

    if (authdata == NULL) {
        authdata = k5alloc(2 * sizeof(krb5_authdata *), &code);
        if (code != 0)
            goto cleanup;

        authdata[0] = k5alloc(sizeof(krb5_authdata), &code);
        if (code != 0)
            goto cleanup;
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
    kdb_audit_as_req *req = (kdb_audit_as_req *)req_data->data;
    krb5_error_code code;
    heim_octet_string e_data;
    krb5_kdc_req *kkdcreq = req->request;
    KDC_REQ hkdcreq;
    Principal *client = NULL;
    Principal *server = NULL;
    time_t from, till, rtime;

    memset(&hkdcreq, 0, sizeof(hkdcreq));
    e_data.data = NULL;

    hkdcreq.pvno = KRB5_PVNO;
    hkdcreq.msg_type = kkdcreq->msg_type;
    hkdcreq.padata = NULL; /* FIXME */
    code = kh_marshal_KDCOptions(context,
                                 kkdcreq->kdc_options,
                                 &hkdcreq.req_body.kdc_options);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_Principal(context, kkdcreq->client, &client);
    if (code != 0)
        goto cleanup;

    code = kh_marshal_Principal(context, kkdcreq->server, &server);
    if (code != 0)
        goto cleanup;

    hkdcreq.req_body.cname = &client->name;
    hkdcreq.req_body.realm = server->realm;
    hkdcreq.req_body.sname = &server->name;

    from  = kkdcreq->from;  hkdcreq.req_body.from = &from;
    till  = kkdcreq->till;  hkdcreq.req_body.till = &till;
    rtime = kkdcreq->rtime; hkdcreq.req_body.rtime = &rtime;

    hkdcreq.req_body.nonce = kkdcreq->nonce;
    hkdcreq.req_body.etype.len = kkdcreq->nktypes;
    hkdcreq.req_body.etype.val = kkdcreq->ktype;

    code = kh_marshall_HostAddresses(context,
                                     kkdcreq->addresses,
                                     &hkdcreq.req_body.addresses);
    if (code != 0)
        goto cleanup;

    /* hkdcreq.req_body.enc_authorization_data */
    /* hkdcreq.req_body.additional_tickets */

    code = kh_windc_client_access(context, kh,
                                  KH_DB_ENTRY(req->client),
                                  &hkdcreq, &e_data);
    if (code != 0)
        goto cleanup;

cleanup:
    kh_free_HostAddresses(context, hkdcreq.req_body.addresses);
    kh_free_Principal(context, client);
    kh_free_Principal(context, server);
    if (e_data.data != NULL)
        free(e_data.data);

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

    for (i = 0; tables[i] != NULL; i++) {
        krb5plugin_windc_ftable *windc = tables[i];

        if (windc->minor_version < KRB5_WINDC_PLUGING_MINOR)
            continue;

        (*windc->init)(kh->hcontext, &kh->windc_ctx);
        kh->windc = windc;
        break;
    }

    if (tables != NULL)
        krb5int_free_plugin_dir_data(tables);

    return 0;
}

