/*
 * plugins/authdata/saml_server/saml_kdc.cpp
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 * Sample authorization data plugin
 */

#include <string.h>
#include <errno.h>

#include "saml_kdc.h"

krb5_error_code
saml_init(krb5_context ctx, void **data)
{
    SAMLConfig &config = SAMLConfig::getConfig();

    if (!config.init()) {
	return KRB5KDC_ERR_SVC_UNAVAILABLE;
    }

    *data = &config;

    return 0;
}

void
saml_fini(krb5_context ctx, void *data)
{
    SAMLConfig *config = (SAMLConfig *)data;

    config->term();
}

static krb5_error_code
saml_kdc_issue(krb5_context context,
               unsigned int flags,
               krb5_const_principal client_princ,
               krb5_db_entry *client,
               krb5_db_entry *server,
               krb5_enc_tkt_part *enc_tkt_request,
               krb5_enc_tkt_part *enc_tkt_reply,
               krb5_data **assertion)
{
    krb5_error_code code;

    if (client == NULL)
        return 0;

    code = saml_kdc_ldap_issue(context, flags, client_princ, client,
                               server, enc_tkt_reply->times.authtime,
                               assertion);

    return code;
}

static krb5_error_code
saml_kdc_verify(krb5_context context,
                krb5_enc_tkt_part *enc_tkt_request,
                krb5_data **assertion)
{
    krb5_error_code code;
    krb5_authdata **tgt_authdata = NULL;
    krb5_authdata **kdc_issued = NULL;
    krb5_authdata **greet = NULL;

    code = krb5int_find_authdata(context,
                                 enc_tkt_request->authorization_data,
                                 NULL,
                                 KRB5_AUTHDATA_KDC_ISSUED,
                                 &tgt_authdata);
    if (code != 0 || tgt_authdata == NULL)
        return 0;

    code = krb5_verify_authdata_kdc_issued(context,
                                           enc_tkt_request->session,
                                           tgt_authdata[0],
                                           NULL,
                                           &kdc_issued);
    if (code != 0) {
        krb5_free_authdata(context, tgt_authdata);
        return code;
    }

    code = krb5int_find_authdata(context,
                                 kdc_issued,
                                 NULL,
                                 KRB5_AUTHDATA_SAML,
                                 &greet);
    if (code == 0 && greet != NULL) {
        krb5_data tmp;

        tmp.data = (char *)greet[0]->contents;
        tmp.length = greet[0]->length;

        code = krb5_copy_data(context, &tmp, assertion);
    } else
        code = 0;

    krb5_free_authdata(context, tgt_authdata);
    krb5_free_authdata(context, kdc_issued);
    krb5_free_authdata(context, greet);

    return code;
}

static krb5_error_code
saml_kdc_sign(krb5_context context,
              krb5_enc_tkt_part *enc_tkt_reply,
              krb5_const_principal tgs,
              krb5_data *assertion)
{
    krb5_error_code code;
    krb5_authdata ad_datum, *ad_data[2], **kdc_issued = NULL;
    krb5_authdata **if_relevant = NULL;
    krb5_authdata **tkt_authdata;

    ad_datum.ad_type = KRB5_AUTHDATA_SAML;
    ad_datum.contents = (krb5_octet *)assertion->data;
    ad_datum.length = assertion->length;

    ad_data[0] = &ad_datum;
    ad_data[1] = NULL;

#if 0
    code = krb5_make_authdata_kdc_issued(context,
                                         enc_tkt_reply->session,
                                         tgs,
                                         ad_data,
                                         &kdc_issued);
    if (code != 0)
        return code;
#endif

    code = krb5_encode_authdata_container(context,
                                          KRB5_AUTHDATA_IF_RELEVANT,
                                          ad_data,
                                          &if_relevant);
    if (code != 0) {
        krb5_free_authdata(context, kdc_issued);
        return code;
    }

    code = krb5_merge_authdata(context,
                               if_relevant,
                               enc_tkt_reply->authorization_data,
                               &tkt_authdata);
    if (code == 0) {
        krb5_free_authdata(context, enc_tkt_reply->authorization_data);
        enc_tkt_reply->authorization_data = tkt_authdata;
    } else {
        krb5_free_authdata(context, if_relevant);
    }

    krb5_free_authdata(context, kdc_issued);

    return code;
}

krb5_error_code
saml_authdata(krb5_context context,
              unsigned int flags,
              krb5_db_entry *client,
              krb5_db_entry *server,
              krb5_db_entry *tgs,
              krb5_keyblock *client_key,
              krb5_keyblock *server_key,
              krb5_keyblock *tgs_key,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_const_principal for_user_princ,
              krb5_enc_tkt_part *enc_tkt_request,
              krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code code;
    krb5_data *assertion = NULL;
    krb5_const_principal client_princ;

    if (request->msg_type != KRB5_TGS_REQ)
        return 0;

    code = saml_kdc_verify(context, enc_tkt_request, &assertion);
    if (code != 0)
        return code;

    if (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION)
        client_princ = for_user_princ;
    else
        client_princ = enc_tkt_reply->client;

    if (assertion == NULL) {
        code = saml_kdc_issue(context, flags, client_princ, client,
                              server, enc_tkt_request, enc_tkt_reply,
                              &assertion);
        if (code != 0)
            return code;
    }

    code = saml_kdc_sign(context, enc_tkt_reply, tgs->princ, assertion);

    krb5_free_data(context, assertion);

    return code;
}

krb5plugin_authdata_server_ftable_v2 authdata_server_2 = {
    "saml",
    saml_init,
    saml_fini,
    saml_authdata,
};
