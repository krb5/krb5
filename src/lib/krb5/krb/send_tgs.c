/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/send_tgs.c */
/*
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
 */

#include "k5-int.h"
#include "int-proto.h"
#include "fast.h"

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
                             struct krb5int_fast_request_state *fast_state,
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
    krb5_data *scratch, scratch2 = empty_data();
    krb5_ticket *sec_ticket = NULL;
    krb5_ticket *sec_ticket_arr[2];
    krb5_timestamp time_now;
    krb5_pa_data **combined_padata = NULL;
    krb5_keyblock *local_subkey = NULL;

    assert (subkey != NULL);
    *subkey  = NULL;

    /*
     * in_creds MUST be a valid credential NOT just a partially filled in
     * place holder for us to get credentials for the caller.
     */
    if (!in_cred->ticket.length)
        return KRB5_NO_TKT_SUPPLIED;

    memset(&tgsreq, 0, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime ? timestruct->endtime :    in_cred->times.endtime;
    tgsreq.authorization_data.ciphertext.data = NULL;
    tgsreq.rtime = timestruct->renew_till;
    if ((retval = krb5_timeofday(context, &time_now)))
        return retval;
    /* XXX we know they are the same size... */
    *nonce = tgsreq.nonce = (krb5_int32)time_now;
    *timestamp = time_now;

    tgsreq.addresses = (krb5_address **) addrs;

    /* Generate subkey*/
    if ((retval = krb5_generate_subkey( context, &in_cred->keyblock,
                                        &local_subkey)) != 0)
        return retval;
    TRACE_SEND_TGS_SUBKEY(context, local_subkey);

    retval = krb5int_fast_tgs_armor(context, fast_state, local_subkey,
                                    &in_cred->keyblock, NULL, NULL);
    if (retval)
        goto cleanup;
    if (authorization_data) {
        /* need to encrypt it in the request */

        if ((retval = encode_krb5_authdata(authorization_data, &scratch)))
            goto cleanup;

        retval = krb5_encrypt_helper(context, local_subkey,
                                     KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY,
                                     scratch, &tgsreq.authorization_data);
        krb5_free_data(context, scratch);
        if (retval)
            goto cleanup;
    }

    /* Get the encryption types list */
    if (ktypes) {
        /* Check passed ktypes and make sure they're valid. */
        for (tgsreq.nktypes = 0; ktypes[tgsreq.nktypes]; tgsreq.nktypes++) {
            if (!krb5_c_valid_enctype(ktypes[tgsreq.nktypes])) {
                retval = KRB5_PROG_ETYPE_NOSUPP;
                goto cleanup;
            }
        }
        tgsreq.ktype = (krb5_enctype *)ktypes;
    } else {
        /* Get the default ktypes */
        krb5_get_tgs_ktypes(context, sname, &(tgsreq.ktype));
        for(tgsreq.nktypes = 0; tgsreq.ktype[tgsreq.nktypes]; tgsreq.nktypes++);
    }
    TRACE_SEND_TGS_ETYPES(context, tgsreq.ktype);

    if (second_ticket) {
        if ((retval = decode_krb5_ticket(second_ticket, &sec_ticket)))
            goto cleanup;
        sec_ticket_arr[0] = sec_ticket;
        sec_ticket_arr[1] = 0;
        tgsreq.second_ticket = sec_ticket_arr;
    } else
        tgsreq.second_ticket = 0;

    /* encode the body; then checksum it */
    retval = krb5int_fast_prep_req_body(context, fast_state, &tgsreq,
                                        &scratch);
    if (retval)
        goto cleanup;

    /*
     * Get an ap_req.
     */
    if ((retval = tgs_construct_tgsreq(context, scratch, in_cred,
                                       &scratch2, local_subkey))) {
        krb5_free_data(context, scratch);
        goto cleanup;
    }
    krb5_free_data(context, scratch);

    tgsreq.padata = k5alloc(2 * sizeof(krb5_pa_data *), &retval);
    if (tgsreq.padata == NULL) {
        free(scratch2.data);
        goto cleanup;
    }
    tgsreq.padata[0] = k5alloc(sizeof(krb5_pa_data), &retval);
    if (tgsreq.padata[0] == NULL) {
        free(scratch2.data);
        goto cleanup;
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

        tmp = realloc(tgsreq.padata, (i + 2) * sizeof(*combined_padata));
        if (tmp == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }

        tgsreq.padata = tmp;

        for (i = 0; padata[i]; i++) {
            krb5_pa_data *pa;

            pa = tgsreq.padata[1 + i] = k5alloc(sizeof(krb5_pa_data), &retval);
            if (tgsreq.padata == NULL)
                goto cleanup;

            pa->pa_type = padata[i]->pa_type;
            pa->length = padata[i]->length;
            pa->contents = k5alloc(padata[i]->length, &retval);
            if (pa->contents == NULL)
                goto cleanup;
            memcpy(pa->contents, padata[i]->contents, padata[i]->length);
        }
        tgsreq.padata[1 + i] = NULL;
    }

    if (pacb_fct != NULL) {
        if ((retval = (*pacb_fct)(context, local_subkey, &tgsreq, pacb_data)))
            goto cleanup;
    }
    /* the TGS_REQ is assembled in tgsreq, so encode it */
    retval = krb5int_fast_prep_req(context, fast_state, &tgsreq, &scratch2,
                                   encode_krb5_tgs_req, &scratch);
    if (retval)
        goto cleanup;

    *request_data = *scratch;
    free(scratch);
    scratch = NULL;

    *subkey = local_subkey;
    local_subkey = NULL;

cleanup:
    krb5_free_pa_data(context, tgsreq.padata);
    krb5_free_ticket(context, sec_ticket);
    if (ktypes == NULL)
        free(tgsreq.ktype);
    zapfree(tgsreq.authorization_data.ciphertext.data,
            tgsreq.authorization_data.ciphertext.length);
    krb5_free_keyblock(context, local_subkey);
    return retval;
}
