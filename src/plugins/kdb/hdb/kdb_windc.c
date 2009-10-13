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
        authdata == NULL) {
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
        authdata = calloc(2, sizeof(krb5_authdata *));
        if (authdata == NULL) {
            code = ENOMEM;
            goto cleanup;
        }

        authdata[0] = calloc(1, sizeof(krb5_authdata));
        if (authdata[0] == NULL) {
            code = ENOMEM;
            goto cleanup;
        }
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

