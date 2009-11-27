/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/send_tgs.c
 *
 * Copyright 1990,1991,2009 by the Massachusetts Institute of Technology.
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
 * krb5_send_tgs()
 */

#include "k5-int.h"
#include "int-proto.h"

/*
  Constructs a TGS request
  options is used for the options in the KRB_TGS_REQ.
  timestruct values are used for from, till, rtime " " "
  enctype is used for enctype " " ", and to encrypt the authorization data,
  sname is used for sname " " "
  addrs, if non-NULL, is used for addresses " " "
  authorization_dat, if non-NULL, is used for authorization_dat " " "
  second_ticket, if required by options, is used for the 2nd ticket in the req.
  in_cred is used for the ticket & session key in the KRB_AP_REQ header " " "
  (the KDC realm is extracted from in_cred->server's realm)

  The response is placed into *rep.
  rep->response.data is set to point at allocated storage which should be
  freed by the caller when finished.

  returns system errors
*/
static krb5_error_code
tgs_construct_tgsreq(krb5_context context, krb5_data *in_data,
                     krb5_creds *in_cred, krb5_data *outbuf, krb5_keyblock *subkey)
{
    krb5_cksumtype cksumtype;
    krb5_error_code       retval;
    krb5_checksum         checksum;
    krb5_authenticator    authent;
    krb5_ap_req           request;
    krb5_data           * scratch = NULL;
    krb5_data           * toutbuf = NULL;

    checksum.contents = NULL;
    request.authenticator.ciphertext.data = NULL;
    request.authenticator.kvno = 0;
    request.ap_options = 0;
    request.ticket = 0;
    switch (in_cred->keyblock.enctype) {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_ARCFOUR_HMAC:
    case ENCTYPE_ARCFOUR_HMAC_EXP:
        cksumtype = context->kdc_req_sumtype;
        break;
    default:
        retval = krb5int_c_mandatory_cksumtype(context, in_cred->keyblock.enctype, &cksumtype);
        if (retval)
            goto cleanup;
    }

    /* Generate checksum */
    if ((retval = krb5_c_make_checksum(context, cksumtype,
                                       &in_cred->keyblock,
                                       KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
                                       in_data, &checksum))) {
        free(checksum.contents);
        goto cleanup;
    }

    /* gen authenticator */
    authent.subkey = subkey; /*owned by caller*/
    authent.seq_number = 0;
    authent.checksum = &checksum;
    authent.client = in_cred->client;
    authent.authorization_data = in_cred->authdata;
    if ((retval = krb5_us_timeofday(context, &authent.ctime,
                                    &authent.cusec)))
        goto cleanup;


    /* encode the authenticator */
    if ((retval = encode_krb5_authenticator(&authent, &scratch)))
        goto cleanup;

    free(checksum.contents);
    checksum.contents = NULL;


    if ((retval = decode_krb5_ticket(&(in_cred)->ticket, &request.ticket)))
        /* Cleanup scratch and scratch data */
        goto cleanup;

    /* call the encryption routine */
    if ((retval = krb5_encrypt_helper(context, &in_cred->keyblock,
                                      KRB5_KEYUSAGE_TGS_REQ_AUTH,
                                      scratch, &request.authenticator)))
        goto cleanup;

    if (!(retval = encode_krb5_ap_req(&request, &toutbuf))) {
        *outbuf = *toutbuf;
        free(toutbuf);
    }

    memset(request.authenticator.ciphertext.data, 0,
           request.authenticator.ciphertext.length);
    free(request.authenticator.ciphertext.data);
    request.authenticator.ciphertext.length = 0;
    request.authenticator.ciphertext.data = 0;


cleanup:
    if (request.ticket)
        krb5_free_ticket(context, request.ticket);

    if (scratch != NULL && scratch->data != NULL) {
        zap(scratch->data,  scratch->length);
        free(scratch->data);
    }
    free(scratch);

    return retval;
}
/*
 * Note that this function fills in part of rep even on failure.
 *
 * The pacb_fct callback allows the caller access to the nonce
 * and request subkey, for binding preauthentication data
 */

krb5_error_code
krb5int_make_tgs_request_ext(krb5_context context,
                             krb5_flags kdcoptions,
                             const krb5_ticket_times *timestruct,
                             const krb5_enctype *ktypes,
                             krb5_const_principal sname,
                             krb5_address *const *addrs,
                             krb5_authdata *const *authorization_data,
                             krb5_pa_data *const *padata,
                             const krb5_data *second_ticket,
                             krb5_creds *in_cred,
                             krb5_error_code (*pacb_fct)(krb5_context,
                                                         krb5_keyblock *,
                                                         krb5_kdc_req *,
                                                         void *),
                             void *pacb_data,
                             krb5_data *request_data,
                             krb5_timestamp *timestamp,
                             krb5_int32 *nonce,
                             krb5_keyblock **subkey)
{
    krb5_error_code retval;
    krb5_kdc_req tgsreq;
    krb5_data *scratch, scratch2;
    krb5_ticket *sec_ticket = 0;
    krb5_ticket *sec_ticket_arr[2];
    krb5_timestamp time_now;
    krb5_pa_data **combined_padata = NULL;
    krb5_pa_data ap_req_padata;
    krb5_keyblock *local_subkey = NULL;

    assert (subkey != NULL);
    *subkey  = NULL;

    /*
     * in_creds MUST be a valid credential NOT just a partially filled in
     * place holder for us to get credentials for the caller.
     */
    if (!in_cred->ticket.length)
        return(KRB5_NO_TKT_SUPPLIED);

    memset(&tgsreq, 0, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime ? timestruct->endtime :    in_cred->times.endtime;
    tgsreq.authorization_data.ciphertext.data = NULL;
    tgsreq.rtime = timestruct->renew_till;
    if ((retval = krb5_timeofday(context, &time_now)))
        return(retval);
    /* XXX we know they are the same size... */
    *nonce = tgsreq.nonce = (krb5_int32)time_now;
    *timestamp = time_now;

    tgsreq.addresses = (krb5_address **) addrs;

    /* Generate subkey*/
    if ((retval = krb5_generate_subkey( context, &in_cred->keyblock,
                                        &local_subkey)) != 0)
        return retval;

    if (authorization_data) {
        /* need to encrypt it in the request */

        if ((retval = encode_krb5_authdata(authorization_data, &scratch)))
            goto send_tgs_error_1;

        if ((retval = krb5_encrypt_helper(context, local_subkey,
                                          KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY,
                                          scratch,
                                          &tgsreq.authorization_data))) {
            free(tgsreq.authorization_data.ciphertext.data);
            krb5_free_data(context, scratch);
            goto send_tgs_error_1;
        }

        krb5_free_data(context, scratch);
    }

    /* Get the encryption types list */
    if (ktypes) {
        /* Check passed ktypes and make sure they're valid. */
        for (tgsreq.nktypes = 0; ktypes[tgsreq.nktypes]; tgsreq.nktypes++) {
            if (!krb5_c_valid_enctype(ktypes[tgsreq.nktypes]))
                return KRB5_PROG_ETYPE_NOSUPP;
        }
        tgsreq.ktype = (krb5_enctype *)ktypes;
    } else {
        /* Get the default ktypes */
        krb5_get_tgs_ktypes(context, sname, &(tgsreq.ktype));
        for(tgsreq.nktypes = 0; tgsreq.ktype[tgsreq.nktypes]; tgsreq.nktypes++);
    }

    if (second_ticket) {
        if ((retval = decode_krb5_ticket(second_ticket, &sec_ticket)))
            goto send_tgs_error_1;
        sec_ticket_arr[0] = sec_ticket;
        sec_ticket_arr[1] = 0;
        tgsreq.second_ticket = sec_ticket_arr;
    } else
        tgsreq.second_ticket = 0;

    ap_req_padata.contents = NULL;

    /* encode the body; then checksum it */
    if ((retval = encode_krb5_kdc_req_body(&tgsreq, &scratch)))
        goto send_tgs_error_2;

    /*
     * Get an ap_req.
     */
    if ((retval = tgs_construct_tgsreq(context, scratch, in_cred,
                                       &scratch2, local_subkey))) {
        krb5_free_data(context, scratch);
        goto send_tgs_error_2;
    }
    krb5_free_data(context, scratch);

    tgsreq.padata = (krb5_pa_data **)calloc(2, sizeof(krb5_pa_data *));
    if (tgsreq.padata == NULL) {
        free(scratch2.data);
        goto send_tgs_error_2;
    }
    tgsreq.padata[0] = (krb5_pa_data *)malloc(sizeof(krb5_pa_data));
    if (tgsreq.padata[0] == NULL) {
        free(scratch2.data);
        goto send_tgs_error_2;
    }
    tgsreq.padata[0]->pa_type = KRB5_PADATA_AP_REQ;
    tgsreq.padata[0]->length = scratch2.length;
    tgsreq.padata[0]->contents = (krb5_octet *)scratch2.data;
    tgsreq.padata[1] = NULL;

    /* combine in any other supplied padata, unfortunately now it is
     * necessary to copy it as the callback function might modify the
     * padata, and having a separate path for the non-callback case,
     * or attempting to determine which elements were changed by the
     * callback, would have complicated the code significantly.
     */
    if (padata) {
        krb5_pa_data **tmp;
        int i;

        for (i = 0; padata[i]; i++)
            ;

        tmp = (krb5_pa_data **)realloc(tgsreq.padata,
                                       (i + 2) * sizeof(*combined_padata));
        if (tmp == NULL)
            goto send_tgs_error_2;

        tgsreq.padata = tmp;

        for (i = 0; padata[i]; i++) {
            krb5_pa_data *pa;

            pa = tgsreq.padata[1 + i] = (krb5_pa_data *)malloc(sizeof(krb5_pa_data));
            if (tgsreq.padata == NULL) {
                retval = ENOMEM;
                goto send_tgs_error_2;
            }

            pa->pa_type = padata[i]->pa_type;
            pa->length = padata[i]->length;
            pa->contents = (krb5_octet *)malloc(padata[i]->length);
            if (pa->contents == NULL) {
                retval = ENOMEM;
                goto send_tgs_error_2;
            }
            memcpy(pa->contents, padata[i]->contents, padata[i]->length);
        }
        tgsreq.padata[1 + i] = NULL;
    }

    if (pacb_fct != NULL) {
        if ((retval = (*pacb_fct)(context, local_subkey, &tgsreq, pacb_data)))
            goto send_tgs_error_2;
    }
    /* the TGS_REQ is assembled in tgsreq, so encode it */
    if ((retval = encode_krb5_tgs_req(&tgsreq, &scratch)))
        goto send_tgs_error_2;

    /* now send request & get response from KDC */
    krb5_free_pa_data(context, tgsreq.padata);
    tgsreq.padata = NULL;

    *request_data = *scratch;
    free(scratch);
    scratch = NULL;

send_tgs_error_2:;
    if (tgsreq.padata)
        krb5_free_pa_data(context, tgsreq.padata);
    if (sec_ticket)
        krb5_free_ticket(context, sec_ticket);

send_tgs_error_1:;
    if (ktypes == NULL)
        free(tgsreq.ktype);
    if (tgsreq.authorization_data.ciphertext.data) {
        memset(tgsreq.authorization_data.ciphertext.data, 0,
               tgsreq.authorization_data.ciphertext.length);
        free(tgsreq.authorization_data.ciphertext.data);
    }

    if (retval)
        krb5_free_keyblock(context, local_subkey);
    else
        *subkey = local_subkey;

    return retval;

}

krb5_error_code
krb5int_send_tgs(krb5_context context, krb5_flags kdcoptions,
                 const krb5_ticket_times *timestruct,
                 const krb5_enctype *ktypes,
                 krb5_const_principal sname, krb5_address *const *addrs,
                 krb5_authdata *const *authorization_data,
                 krb5_pa_data *const *padata, const krb5_data *second_ticket,
                 krb5_creds *in_cred,
                 krb5_error_code (*pacb_fct)(krb5_context,
                                             krb5_keyblock *,
                                             krb5_kdc_req *,
                                             void *),
                 void *pacb_data,
                 krb5_response *rep, krb5_keyblock **subkey_out)
{
    krb5_error_code retval;
    krb5_data request;
    int tcp_only = 0, use_master;
    krb5_timestamp now;
    krb5_int32 nonce;
    krb5_keyblock *subkey;
    krb5_error *err_reply = NULL;
    krb5_ui_4 err;

    *subkey_out = NULL;
    rep->message_type = KRB5_ERROR;

    retval = krb5int_make_tgs_request_ext(context, kdcoptions, timestruct,
                                          ktypes, sname, addrs,
                                          authorization_data, padata,
                                          second_ticket, in_cred,
                                          pacb_fct, pacb_data, &request, &now,
                                          &nonce, &subkey);
    if (retval != 0)
        return retval;

    rep->expected_nonce = nonce;
    rep->request_time = now;

    for (tcp_only = 0; tcp_only <= 1; tcp_only++) {
        use_master = 0;
        retval = krb5_sendto_kdc(context, &request,
                                 krb5_princ_realm(context, sname),
                                 &rep->response, &use_master, tcp_only);
        if (retval != 0)
            break;

        if (krb5_is_tgs_rep(&rep->response)) {
            /* Successful response; set the output subkey. */
            rep->message_type = KRB5_TGS_REP;
            *subkey_out = subkey;
            subkey = NULL;
            break;
        } else if (krb5_is_krb_error(&rep->response) && !tcp_only) {
            /* Decode the error response to extract the code. */
            retval = decode_krb5_error(&rep->response, &err_reply);
            err = (retval == 0) ? err_reply->error : 0;
            krb5_free_error(context, err_reply);
            if (err == KRB_ERR_RESPONSE_TOO_BIG) {
                /* Try again with TCP. */
                krb5_free_data_contents(context, &rep->response);
                continue;
            }
        }
        /* Unexpected message type, or an error other than RESPONSE_TOO_BIG. */
        rep->message_type = KRB5_ERROR;
        break;
    }

    krb5_free_data_contents(context, &request);
    krb5_free_keyblock(context, subkey);
    return retval;
}
