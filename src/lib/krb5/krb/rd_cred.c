/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/rd_cred.c - definition of krb5_rd_cred() */
/*
 * Copyright 1994-2009 by the Massachusetts Institute of Technology.
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
#include "cleanup.h"
#include "auth_con.h"

#include <stddef.h>           /* NULL */
#include <stdlib.h>           /* malloc */
#include <errno.h>            /* ENOMEM */

/*-------------------- decrypt_credencdata --------------------*/

/*
 * decrypt the enc_part of a krb5_cred
 */
static krb5_error_code
decrypt_credencdata(krb5_context context, krb5_cred *pcred,
                    krb5_key pkey, krb5_cred_enc_part *pcredenc)
{
    krb5_cred_enc_part  * ppart = NULL;
    krb5_error_code       retval = 0;
    krb5_data             scratch;

    scratch.length = pcred->enc_part.ciphertext.length;
    if (!(scratch.data = (char *)malloc(scratch.length)))
        return ENOMEM;

    if (pkey != NULL) {
        if ((retval = krb5_k_decrypt(context, pkey,
                                     KRB5_KEYUSAGE_KRB_CRED_ENCPART, 0,
                                     &pcred->enc_part, &scratch)))
            goto cleanup;
    } else {
        memcpy(scratch.data, pcred->enc_part.ciphertext.data, scratch.length);
    }

    /*  now decode the decrypted stuff */
    if ((retval = decode_krb5_enc_cred_part(&scratch, &ppart)))
        goto cleanup;

    *pcredenc = *ppart;

cleanup:
    if (ppart != NULL) {
        memset(ppart, 0, sizeof(*ppart));
        free(ppart);
    }
    memset(scratch.data, 0, scratch.length);
    free(scratch.data);

    return retval;
}
/*----------------------- krb5_rd_cred_basic -----------------------*/

static krb5_error_code
krb5_rd_cred_basic(krb5_context context, krb5_data *pcreddata,
                   krb5_key pkey, krb5_replay_data *replaydata,
                   krb5_creds ***pppcreds)
{
    krb5_error_code       retval = 0;
    krb5_cred           * pcred = NULL;
    krb5_int32            ncreds = 0;
    krb5_int32            i = 0;
    krb5_cred_enc_part    encpart;

    /* decode cred message */
    if ((retval = decode_krb5_cred(pcreddata, &pcred)))
        return retval;

    memset(&encpart, 0, sizeof(encpart));

    if ((retval = decrypt_credencdata(context, pcred, pkey, &encpart)))
        goto cleanup_cred;


    replaydata->timestamp = encpart.timestamp;
    replaydata->usec = encpart.usec;
    replaydata->seq = encpart.nonce;

    /*
     * Allocate the list of creds.  The memory is allocated so that
     * krb5_free_tgt_creds can be used to free the list.
     */
    for (ncreds = 0; pcred->tickets[ncreds]; ncreds++);

    if ((*pppcreds =
         (krb5_creds **)malloc((size_t)(sizeof(krb5_creds *) *
                                        (ncreds + 1)))) == NULL) {
        retval = ENOMEM;
        goto cleanup_cred;
    }
    (*pppcreds)[0] = NULL;

    /*
     * For each credential, create a strcture in the list of
     * credentials and copy the information.
     */
    while (i < ncreds) {
        krb5_cred_info  * pinfo;
        krb5_creds      * pcur;
        krb5_data       * pdata;

        if ((pcur = (krb5_creds *)calloc(1, sizeof(krb5_creds))) == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }

        (*pppcreds)[i] = pcur;
        (*pppcreds)[i+1] = 0;
        pinfo = encpart.ticket_info[i++];

        if ((retval = krb5_copy_principal(context, pinfo->client,
                                          &pcur->client)))
            goto cleanup;

        if ((retval = krb5_copy_principal(context, pinfo->server,
                                          &pcur->server)))
            goto cleanup;

        if ((retval = krb5_copy_keyblock_contents(context, pinfo->session,
                                                  &pcur->keyblock)))
            goto cleanup;

        if ((retval = krb5_copy_addresses(context, pinfo->caddrs,
                                          &pcur->addresses)))
            goto cleanup;

        if ((retval = encode_krb5_ticket(pcred->tickets[i - 1], &pdata)))
            goto cleanup;

        pcur->ticket = *pdata;
        free(pdata);


        pcur->is_skey = FALSE;
        pcur->magic = KV5M_CREDS;
        pcur->times = pinfo->times;
        pcur->ticket_flags = pinfo->flags;
        pcur->authdata = NULL;   /* not used */
        memset(&pcur->second_ticket, 0, sizeof(pcur->second_ticket));
    }

    /*
     * NULL terminate the list
     */
    (*pppcreds)[i] = NULL;

cleanup:
    if (retval)
        krb5_free_tgt_creds(context, *pppcreds);

cleanup_cred:
    krb5_free_cred(context, pcred);
    krb5_free_cred_enc_part(context, &encpart);

    return retval;
}

/*----------------------- krb5_rd_cred -----------------------*/

/*
 * This functions takes as input an KRB_CRED message, validates it, and
 * outputs the array of the forwarded credentials and replay cache information
 */
krb5_error_code KRB5_CALLCONV
krb5_rd_cred(krb5_context context, krb5_auth_context auth_context,
             krb5_data *pcreddata, krb5_creds ***pppcreds,
             krb5_replay_data *outdata)
{
    krb5_error_code       retval = 0;
    krb5_replay_data      replaydata;

    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
         (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
        (outdata == NULL))
        /* Need a better error */
        return KRB5_RC_REQUIRED;

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) &&
        (auth_context->rcache == NULL))
        return KRB5_RC_REQUIRED;

    /*
     * If decrypting with the subsession key fails, perhaps the
     * credentials are stored in the session key so try decrypting with that.
     */
    if (auth_context->recv_subkey == NULL ||
        (retval = krb5_rd_cred_basic(context, pcreddata,
                                     auth_context->recv_subkey,
                                     &replaydata, pppcreds))) {
        retval = krb5_rd_cred_basic(context, pcreddata,
                                    auth_context->key,
                                    &replaydata, pppcreds);
        if (retval)
            return retval;
    }

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) {
        krb5_donot_replay replay;

        if ((retval = krb5_check_clockskew(context, replaydata.timestamp)))
            goto error;

        if ((retval = krb5_gen_replay_name(context, auth_context->remote_addr,
                                           "_forw", &replay.client)))
            goto error;

        replay.server = "";             /* XXX */
        replay.msghash = NULL;
        replay.cusec = replaydata.usec;
        replay.ctime = replaydata.timestamp;
        if ((retval = krb5_rc_store(context, auth_context->rcache, &replay))) {
            free(replay.client);
            goto error;
        }
        free(replay.client);
    }

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
        if (auth_context->remote_seq_number != replaydata.seq) {
            retval =  KRB5KRB_AP_ERR_BADORDER;
            goto error;
        }
        auth_context->remote_seq_number++;
    }

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
        (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) {
        outdata->timestamp = replaydata.timestamp;
        outdata->usec = replaydata.usec;
        outdata->seq = replaydata.seq;
    }

error:;
    if (retval) {
        krb5_free_tgt_creds(context, *pppcreds);
        *pppcreds = NULL;
    }
    return retval;
}
