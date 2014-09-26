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

/*
 * Returns TRUE if authdata should be filtered when copying from
 * untrusted authdata.
 */
static krb5_boolean
is_kdc_issued_authdatum (krb5_context context,
                         krb5_authdata *authdata,
                         krb5_authdatatype desired_type)
{
    krb5_boolean ret = FALSE;
    krb5_authdatatype ad_type;
    unsigned int i, count = 0;
    krb5_authdatatype *ad_types = NULL;

    if (authdata->ad_type == KRB5_AUTHDATA_IF_RELEVANT) {
        if (krb5int_get_authdata_containee_types(context,
                                                 authdata,
                                                 &count,
                                                 &ad_types) != 0)
            goto cleanup;
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
            ret = desired_type ? (desired_type == ad_types[i]) : TRUE;
            break;
        default:
            ret = FALSE;
            break;
        }
        if (ret)
            break;
    }

cleanup:
    if (authdata->ad_type == KRB5_AUTHDATA_IF_RELEVANT &&
        ad_types != NULL)
        free(ad_types);

    return ret;
}

static krb5_boolean
has_kdc_issued_authdata (krb5_context context,
                         krb5_authdata **authdata,
                         krb5_authdatatype desired_type)
{
    int i;
    krb5_boolean ret = FALSE;

    if (authdata != NULL) {
        for (i = 0; authdata[i] != NULL; i++) {
            if (is_kdc_issued_authdatum(context, authdata[i], desired_type)) {
                ret = TRUE;
                break;
            }
        }
    }

    return ret;
}

static krb5_boolean
has_mandatory_for_kdc_authdata (krb5_context context,
                                krb5_authdata **authdata)
{
    int i;
    krb5_boolean ret = FALSE;

    if (authdata != NULL) {
        for (i = 0; authdata[i] != NULL; i++) {
            if (authdata[i]->ad_type == KRB5_AUTHDATA_MANDATORY_FOR_KDC) {
                ret = TRUE;
                break;
            }
        }
    }

    return ret;
}

/*
 * Merge authdata.
 *
 * If copy is FALSE, in_authdata is invalid on successful return.
 * If ignore_kdc_issued is TRUE, KDC-issued authdata is not copied.
 */
static krb5_error_code
merge_authdata (krb5_context context,
                krb5_authdata **in_authdata,
                krb5_authdata ***out_authdata,
                krb5_boolean copy,
                krb5_boolean ignore_kdc_issued)
{
    size_t i, j, nadata = 0;
    krb5_authdata **in_copy = NULL, **authdata = *out_authdata;
    krb5_error_code code;

    if (in_authdata == NULL || in_authdata[0] == NULL)
        return 0;

    if (authdata != NULL) {
        for (nadata = 0; authdata[nadata] != NULL; nadata++)
            ;
    }

    for (i = 0; in_authdata[i] != NULL; i++)
        ;

    if (copy) {
        code = krb5_copy_authdata(context, in_authdata, &in_copy);
        if (code != 0)
            return code;
        in_authdata = in_copy;
    }

    authdata = realloc(authdata, (nadata + i + 1) * sizeof(krb5_authdata *));
    if (authdata == NULL) {
        krb5_free_authdata(context, in_copy);
        return ENOMEM;
    }

    for (i = 0, j = 0; in_authdata[i] != NULL; i++) {
        if (ignore_kdc_issued &&
            is_kdc_issued_authdatum(context, in_authdata[i], 0)) {
            free(in_authdata[i]->contents);
            free(in_authdata[i]);
        } else
            authdata[nadata + j++] = in_authdata[i];
    }

    authdata[nadata + j] = NULL;

    free(in_authdata);

    if (authdata[0] == NULL) {
        free(authdata);
        authdata = NULL;
    }

    *out_authdata = authdata;

    return 0;
}

/* Copy TGS-REQ authorization data into the ticket authdata. */
static krb5_error_code
copy_request_authdata(krb5_context context, krb5_keyblock *client_key,
                      krb5_kdc_req *request,
                      krb5_enc_tkt_part *enc_tkt_request,
                      krb5_authdata ***tkt_authdata)
{
    krb5_error_code code;
    krb5_data scratch;

    assert(enc_tkt_request != NULL);

    scratch.length = request->authorization_data.ciphertext.length;
    scratch.data = malloc(scratch.length);
    if (scratch.data == NULL)
        return ENOMEM;

    /*
     * RFC 4120 requires authdata in the TGS body to be encrypted in
     * the subkey with usage 5 if a subkey is present, and in the TGS
     * session key with key usage 4 if it is not.  Prior to krb5 1.7,
     * we got this wrong, always decrypting the authorization data
     * with the TGS session key and usage 4.  For the sake of
     * conservatism, try the decryption the old way (wrong if
     * client_key is a subkey) first, and then try again the right way
     * (in the case where client_key is a subkey) if the first way
     * fails.
     */
    code = krb5_c_decrypt(context,
                          enc_tkt_request->session,
                          KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY,
                          0, &request->authorization_data,
                          &scratch);
    if (code != 0)
        code = krb5_c_decrypt(context,
                              client_key,
                              KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY,
                              0, &request->authorization_data,
                              &scratch);

    if (code != 0) {
        free(scratch.data);
        return code;
    }

    /* scratch now has the authorization data, so we decode it, and make
     * it available to subsequent authdata plugins
     */
    code = decode_krb5_authdata(&scratch, &request->unenc_authdata);
    if (code != 0) {
        free(scratch.data);
        return code;
    }

    free(scratch.data);

    if (has_mandatory_for_kdc_authdata(context, request->unenc_authdata))
        return KRB5KDC_ERR_POLICY;

    code = merge_authdata(context,
                          request->unenc_authdata,
                          tkt_authdata,
                          TRUE,            /* copy */
                          TRUE);    /* ignore_kdc_issued */

    return code;
}

/* Copy TGT authorization data into the ticket authdata. */
static krb5_error_code
copy_tgt_authdata(krb5_context context, krb5_kdc_req *request,
                  krb5_authdata **tgt_authdata, krb5_authdata ***tkt_authdata)
{
    if (has_mandatory_for_kdc_authdata(context, tgt_authdata))
        return KRB5KDC_ERR_POLICY;

    return merge_authdata(context,
                          tgt_authdata,
                          tkt_authdata,
                          TRUE,            /* copy */
                          TRUE);    /* ignore_kdc_issued */
}

/* Fetch authorization data from KDB module. */
static krb5_error_code
fetch_kdb_authdata(krb5_context context, unsigned int flags,
                   krb5_db_entry *client, krb5_db_entry *server,
                   krb5_db_entry *krbtgt, krb5_keyblock *client_key,
                   krb5_keyblock *server_key, krb5_keyblock *krbtgt_key,
                   krb5_kdc_req *request, krb5_const_principal for_user_princ,
                   krb5_enc_tkt_part *enc_tkt_request,
                   krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code;
    krb5_authdata **tgt_authdata, **db_authdata = NULL;
    krb5_boolean tgs_req = (request->msg_type == KRB5_TGS_REQ);
    krb5_const_principal actual_client;

    /*
     * Check whether KDC issued authorization data should be included.
     * A server can explicitly disable the inclusion of authorization
     * data by setting the KRB5_KDB_NO_AUTH_DATA_REQUIRED flag on its
     * principal entry. Otherwise authorization data will be included
     * if it was present in the TGT, the client is from another realm
     * or protocol transition/constrained delegation was used, or, in
     * the AS-REQ case, if the pre-auth data indicated the PAC should
     * be present.
     */
    if (tgs_req) {
        assert(enc_tkt_request != NULL);

        if (isflagset(server->attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED))
            return 0;

        if (enc_tkt_request->authorization_data == NULL &&
            !isflagset(flags, KRB5_KDB_FLAG_CROSS_REALM | KRB5_KDB_FLAGS_S4U))
            return 0;

        assert(enc_tkt_reply->times.authtime == enc_tkt_request->times.authtime);
    } else {
        if (!isflagset(flags, KRB5_KDB_FLAG_INCLUDE_PAC))
            return 0;
    }

    /*
     * We have this special case for protocol transition, because for
     * cross-realm protocol transition the ticket reply client will
     * not be changed until the final hop.
     */
    if (isflagset(flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION))
        actual_client = for_user_princ;
    else
        actual_client = enc_tkt_reply->client;

    tgt_authdata = tgs_req ? enc_tkt_request->authorization_data : NULL;
    code = krb5_db_sign_authdata(context, flags, actual_client, client,
                                 server, krbtgt, client_key, server_key,
                                 krbtgt_key, enc_tkt_reply->session,
                                 enc_tkt_reply->times.authtime, tgt_authdata,
                                 &db_authdata);
    if (code == 0) {
        code = merge_authdata(context,
                              db_authdata,
                              &enc_tkt_reply->authorization_data,
                              FALSE,        /* !copy */
                              FALSE);        /* !ignore_kdc_issued */
        if (code != 0)
            krb5_free_authdata(context, db_authdata);
    } else if (code == KRB5_PLUGIN_OP_NOTSUPP)
        code = 0;

    return code;
}

static krb5_error_code
make_ad_signedpath_data(krb5_context context,
                        krb5_const_principal client,
                        krb5_timestamp authtime,
                        krb5_principal *deleg_path,
                        krb5_pa_data **method_data,
                        krb5_authdata **authdata,
                        krb5_data **data)
{
    krb5_ad_signedpath_data         sp_data;
    krb5_authdata                 **sign_authdata = NULL;
    int                             i, j;
    krb5_error_code                 code;

    memset(&sp_data, 0, sizeof(sp_data));

    if (authdata != NULL) {
        for (i = 0; authdata[i] != NULL; i++)
            ;
    } else
        i = 0;

    if (i != 0) {
        sign_authdata = k5calloc(i + 1, sizeof(krb5_authdata *), &code);
        if (sign_authdata == NULL)
            return code;

        for (i = 0, j = 0; authdata[i] != NULL; i++) {
            if (is_kdc_issued_authdatum(context, authdata[i],
                                        KRB5_AUTHDATA_SIGNTICKET))
                continue;

            sign_authdata[j++] = authdata[i];
        }

        sign_authdata[j] = NULL;
    }

    sp_data.client = (krb5_principal)client;
    sp_data.authtime = authtime;
    sp_data.delegated = deleg_path;
    sp_data.method_data = method_data;
    sp_data.authorization_data = sign_authdata;

    code = encode_krb5_ad_signedpath_data(&sp_data, data);

    if (sign_authdata != NULL)
        free(sign_authdata);

    return code;
}

static krb5_error_code
verify_ad_signedpath_checksum(krb5_context context,
                              krb5_keyblock *krbtgt_key,
                              krb5_enc_tkt_part *enc_tkt_part,
                              krb5_principal *deleg_path,
                              krb5_pa_data **method_data,
                              krb5_checksum *cksum,
                              krb5_boolean *valid)
{
    krb5_error_code                 code;
    krb5_data                      *data;

    *valid = FALSE;

    if (!krb5_c_is_keyed_cksum(cksum->checksum_type))
        return KRB5KRB_AP_ERR_INAPP_CKSUM;

    code = make_ad_signedpath_data(context,
                                   enc_tkt_part->client,
                                   enc_tkt_part->times.authtime,
                                   deleg_path,
                                   method_data,
                                   enc_tkt_part->authorization_data,
                                   &data);
    if (code != 0)
        return code;

    code = krb5_c_verify_checksum(context,
                                  krbtgt_key,
                                  KRB5_KEYUSAGE_AD_SIGNEDPATH,
                                  data,
                                  cksum,
                                  valid);

    krb5_free_data(context, data);
    return code;
}


static krb5_error_code
verify_ad_signedpath(krb5_context context,
                     krb5_keyblock *krbtgt_key,
                     krb5_enc_tkt_part *enc_tkt_part,
                     krb5_principal **pdelegated,
                     krb5_boolean *path_is_signed)
{
    krb5_error_code                 code;
    krb5_ad_signedpath             *sp = NULL;
    krb5_authdata                 **sp_authdata = NULL;
    krb5_data                       enc_sp;

    *pdelegated = NULL;
    *path_is_signed = FALSE;

    code = krb5_find_authdata(context, enc_tkt_part->authorization_data, NULL,
                              KRB5_AUTHDATA_SIGNTICKET, &sp_authdata);
    if (code != 0)
        goto cleanup;

    if (sp_authdata == NULL ||
        sp_authdata[0]->ad_type != KRB5_AUTHDATA_SIGNTICKET ||
        sp_authdata[1] != NULL)
        goto cleanup;

    enc_sp.data = (char *)sp_authdata[0]->contents;
    enc_sp.length = sp_authdata[0]->length;

    code = decode_krb5_ad_signedpath(&enc_sp, &sp);
    if (code != 0) {
        /* Treat an invalid signedpath authdata element as a missing one, since
         * we believe MS is using the same number for something else. */
        code = 0;
        goto cleanup;
    }

    code = verify_ad_signedpath_checksum(context,
                                         krbtgt_key,
                                         enc_tkt_part,
                                         sp->delegated,
                                         sp->method_data,
                                         &sp->checksum,
                                         path_is_signed);
    if (code != 0)
        goto cleanup;

    if (*path_is_signed) {
        *pdelegated = sp->delegated;
        sp->delegated = NULL;
    }

cleanup:
    krb5_free_ad_signedpath(context, sp);
    krb5_free_authdata(context, sp_authdata);

    return code;
}

static krb5_error_code
make_ad_signedpath_checksum(krb5_context context,
                            krb5_const_principal for_user_princ,
                            krb5_keyblock *krbtgt_key,
                            krb5_enc_tkt_part *enc_tkt_part,
                            krb5_principal *deleg_path,
                            krb5_pa_data **method_data,
                            krb5_checksum *cksum)
{
    krb5_error_code                 code;
    krb5_data                      *data;
    krb5_cksumtype                  cksumtype;
    krb5_const_principal            client;

    if (for_user_princ != NULL)
        client = for_user_princ;
    else
        client = enc_tkt_part->client;

    code = make_ad_signedpath_data(context,
                                   client,
                                   enc_tkt_part->times.authtime,
                                   deleg_path,
                                   method_data,
                                   enc_tkt_part->authorization_data,
                                   &data);
    if (code != 0)
        return code;

    code = krb5int_c_mandatory_cksumtype(context,
                                         krbtgt_key->enctype,
                                         &cksumtype);
    if (code != 0) {
        krb5_free_data(context, data);
        return code;
    }

    if (!krb5_c_is_keyed_cksum(cksumtype)) {
        krb5_free_data(context, data);
        return KRB5KRB_AP_ERR_INAPP_CKSUM;
    }

    code = krb5_c_make_checksum(context, cksumtype, krbtgt_key,
                                KRB5_KEYUSAGE_AD_SIGNEDPATH, data,
                                cksum);

    krb5_free_data(context, data);

    return code;
}

static krb5_error_code
make_ad_signedpath(krb5_context context,
                   krb5_const_principal for_user_princ,
                   krb5_principal server,
                   krb5_keyblock *krbtgt_key,
                   krb5_principal *deleg_path,
                   krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code                 code;
    krb5_ad_signedpath              sp;
    int                             i;
    krb5_data                      *data = NULL;
    krb5_authdata                   ad_datum, *ad_data[2];
    krb5_authdata                 **if_relevant = NULL;

    memset(&sp, 0, sizeof(sp));

    sp.enctype = krbtgt_key->enctype;

    if (deleg_path != NULL) {
        for (i = 0; deleg_path[i] != NULL; i++)
            ;
    } else
        i = 0;

    sp.delegated = k5calloc(i + (server ? 1 : 0) + 1, sizeof(krb5_principal),
                            &code);
    if (code != 0)
        goto cleanup;

    /* Combine existing and new transited services, if any */
    if (deleg_path != NULL)
        memcpy(sp.delegated, deleg_path, i * sizeof(krb5_principal));
    if (server != NULL)
        sp.delegated[i++] = server;
    sp.delegated[i] = NULL;
    sp.method_data = NULL;

    code = make_ad_signedpath_checksum(context,
                                       for_user_princ,
                                       krbtgt_key,
                                       enc_tkt_reply,
                                       sp.delegated,
                                       sp.method_data,
                                       &sp.checksum);
    if (code != 0) {
        if (code == KRB5KRB_AP_ERR_INAPP_CKSUM) {
            /*
             * In the hopefully unlikely case the TGS key enctype
             * has an unkeyed mandatory checksum type, do not fail
             * so we do not prevent the KDC from servicing requests.
             */
            code = 0;
        }
        goto cleanup;
    }

    code = encode_krb5_ad_signedpath(&sp, &data);
    if (code != 0)
        goto cleanup;

    ad_datum.ad_type = KRB5_AUTHDATA_SIGNTICKET;
    ad_datum.contents = (krb5_octet *)data->data;
    ad_datum.length = data->length;

    ad_data[0] = &ad_datum;
    ad_data[1] = NULL;

    code = krb5_encode_authdata_container(context,
                                          KRB5_AUTHDATA_IF_RELEVANT,
                                          ad_data,
                                          &if_relevant);
    if (code != 0)
        goto cleanup;

    code = merge_authdata(context,
                          if_relevant,
                          &enc_tkt_reply->authorization_data,
                          FALSE,        /* !copy */
                          FALSE);       /* !ignore_kdc_issued */
    if (code != 0)
        goto cleanup;

    if_relevant = NULL; /* merge_authdata() freed */

cleanup:
    if (sp.delegated != NULL)
        free(sp.delegated);
    krb5_free_authdata(context, if_relevant);
    krb5_free_data(context, data);
    krb5_free_checksum_contents(context, &sp.checksum);
    krb5_free_pa_data(context, sp.method_data);

    return code;
}

static void
free_deleg_path(krb5_context context, krb5_principal *deleg_path)
{
    if (deleg_path != NULL) {
        int i;

        for (i = 0; deleg_path[i] != NULL; i++)
            krb5_free_principal(context, deleg_path[i]);
        free(deleg_path);
    }
}

/*
 * Returns TRUE if the Windows 2000 PAC is the only element in the
 * supplied authorization data.
 */
static krb5_boolean
only_pac_p(krb5_context context, krb5_authdata **authdata)
{
    return has_kdc_issued_authdata(context,
                                   authdata, KRB5_AUTHDATA_WIN2K_PAC) &&
        (authdata[1] == NULL);
}

/* Verify AD-SIGNTICKET authdata if we need to, and insert an AD-SIGNEDPATH
 * element if we should. */
static krb5_error_code
handle_signticket(krb5_context context, unsigned int flags,
                  krb5_db_entry *client, krb5_db_entry *server,
                  krb5_keyblock *krbtgt_key, krb5_kdc_req *request,
                  krb5_const_principal for_user_princ,
                  krb5_enc_tkt_part *enc_tkt_request,
                  krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code = 0;
    krb5_principal *deleg_path = NULL;
    krb5_boolean signed_path = FALSE;
    krb5_boolean s4u2proxy;

    s4u2proxy = isflagset(flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION);

    /*
     * The Windows PAC fulfils the same role as the signed path
     * if it is the only authorization data element.
     */
    if (request->msg_type == KRB5_TGS_REQ &&
        !only_pac_p(context, enc_tkt_request->authorization_data)) {
        code = verify_ad_signedpath(context,
                                    krbtgt_key,
                                    enc_tkt_request,
                                    &deleg_path,
                                    &signed_path);
        if (code != 0)
            goto cleanup;

        if (s4u2proxy && signed_path == FALSE) {
            code = KRB5KDC_ERR_BADOPTION;
            goto cleanup;
        }
    }

    /* No point in including signedpath authdata for a cross-realm TGT, since
     * it will be presented to a different KDC. */
    if (!isflagset(server->attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED) &&
        !is_cross_tgs_principal(server->princ) &&
        !only_pac_p(context, enc_tkt_reply->authorization_data)) {
        code = make_ad_signedpath(context,
                                  for_user_princ,
                                  s4u2proxy ? client->princ : NULL,
                                  krbtgt_key,
                                  deleg_path,
                                  enc_tkt_reply);
        if (code != 0)
            goto cleanup;
    }

cleanup:
    free_deleg_path(context, deleg_path);

    return code;
}

krb5_error_code
handle_authdata (krb5_context context,
                 unsigned int flags,
                 krb5_db_entry *client,
                 krb5_db_entry *server,
                 krb5_db_entry *krbtgt,
                 krb5_keyblock *client_key,
                 krb5_keyblock *server_key,
                 krb5_keyblock *krbtgt_key,
                 krb5_data *req_pkt,
                 krb5_kdc_req *request,
                 krb5_const_principal for_user_princ,
                 krb5_enc_tkt_part *enc_tkt_request,
                 krb5_enc_tkt_part *enc_tkt_reply)
{
    kdcauthdata_handle *h;
    krb5_error_code code = 0;
    size_t i;

    if (request->msg_type == KRB5_TGS_REQ &&
        request->authorization_data.ciphertext.data != NULL) {
        /* Copy TGS request authdata.  This must be done first so that modules
         * have access to the unencrypted request authdata. */
        code = copy_request_authdata(context, client_key, request,
                                     enc_tkt_request,
                                     &enc_tkt_reply->authorization_data);
        if (code)
            return code;
    }

    /* Invoke loaded module handlers. */
    if (!isflagset(enc_tkt_reply->flags, TKT_FLG_ANONYMOUS)) {
        for (i = 0; i < n_authdata_modules; i++) {
            h = &authdata_modules[i];
            code = h->vt.handle(context, h->data, flags, client, server,
                                krbtgt, client_key, server_key, krbtgt_key,
                                req_pkt, request, for_user_princ,
                                enc_tkt_request, enc_tkt_reply);
            if (code)
                kdc_err(context, code, "from authdata module %s", h->vt.name);
        }
    }

    if (request->msg_type == KRB5_TGS_REQ) {
        /* Copy authdata from the TGT to the issued ticket. */
        code = copy_tgt_authdata(context, request,
                                 enc_tkt_request->authorization_data,
                                 &enc_tkt_reply->authorization_data);
        if (code)
            return code;
    }

    if (!isflagset(enc_tkt_reply->flags, TKT_FLG_ANONYMOUS)) {
        /* Fetch authdata from the KDB if appropriate. */
        code = fetch_kdb_authdata(context, flags, client, server, krbtgt,
                                  client_key, server_key, krbtgt_key, request,
                                  for_user_princ, enc_tkt_request,
                                  enc_tkt_reply);
        if (code)
            return code;

        /* Validate and insert AD-SIGNTICKET authdata.  This must happen last
         * since it contains a signature over the other authdata. */
        code = handle_signticket(context, flags, client, server, krbtgt_key,
                                 request, for_user_princ, enc_tkt_request,
                                 enc_tkt_reply);
        if (code)
            return code;
    }

    return 0;
}
