/*
 * lib/krb5/krb/send_tgs.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_send_tgs()
 */

#include "k5-int.h"

/*
 Sends a request to the TGS and waits for a response.
 options is used for the options in the KRB_TGS_REQ.
 timestruct values are used for from, till, rtime " " "
 etype is used for etype " " ", and to encrypt the authorization data, 
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
extern krb5_cksumtype krb5_kdc_req_sumtype;

static krb5_error_code 
krb5_send_tgs_basic(context, in_data, in_cred, outbuf)
    krb5_context          context;
    krb5_data           * in_data;
    krb5_creds          * in_cred;
    krb5_data           * outbuf;
{   
    krb5_error_code       retval;
    krb5_checksum         checksum;
    krb5_authenticator 	  authent;
    krb5_ap_req 	  request;
    krb5_encrypt_block 	  eblock;
    krb5_data		* scratch;
    krb5_data           * toutbuf;

    /* Generate checksum */
    if ((checksum.contents = (krb5_octet *)
	 malloc(krb5_checksum_size(context, krb5_kdc_req_sumtype))) == NULL) 
        return(ENOMEM);

    if ((retval = krb5_calculate_checksum(context, krb5_kdc_req_sumtype,
					  in_data->data, in_data->length,
					  (krb5_pointer) in_cred->keyblock.contents,
					  in_cred->keyblock.length,
					  &checksum))) {
        free(checksum.contents);
	return(retval);
    }

    /* gen authenticator */
    authent.subkey = 0;
    authent.seq_number = 0;
    authent.checksum = &checksum;
    authent.client = in_cred->client;
    authent.authorization_data = in_cred->authdata;
    if ((retval = krb5_us_timeofday(context, &authent.ctime,
				    &authent.cusec))) {
        free(checksum.contents);
	return(retval);
    }

    /* encode the authenticator */
    if ((retval = encode_krb5_authenticator(&authent, &scratch))) {
        free(checksum.contents);
	return(retval);
    }

    free(checksum.contents);

    request.authenticator.ciphertext.data = 0;
    request.authenticator.kvno = 0;
    request.ap_options = 0;
    request.ticket = 0;

    if ((retval = decode_krb5_ticket(&(in_cred)->ticket, &request.ticket)))
	/* Cleanup scratch and scratch data */
        goto cleanup_data;

    /* put together an eblock for this encryption */
    krb5_use_cstype(context, &eblock, request.ticket->enc_part.etype);
    request.authenticator.etype = request.ticket->enc_part.etype;
    request.authenticator.ciphertext.length =
        krb5_encrypt_size(scratch->length, eblock.crypto_entry);

    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
                                  request.authenticator.ciphertext.length))) {
        /* may destroy scratch->data */ 
        krb5_free_ticket(context, request.ticket);
        retval = ENOMEM;
        goto cleanup_scratch;
    }
    memset(scratch->data + scratch->length, 0,
          request.authenticator.ciphertext.length - scratch->length);

    if (!(request.authenticator.ciphertext.data =
          malloc(request.authenticator.ciphertext.length))) {
        retval = ENOMEM;
        goto cleanup_ticket;
    }

    /* do any necessary key pre-processing */
    if ((retval = krb5_process_key(context, &eblock, &(in_cred)->keyblock)))
        goto cleanup;

    /* call the encryption routine */ 
    if ((retval=krb5_encrypt(context, (krb5_pointer) scratch->data,
			     (krb5_pointer)request.authenticator.ciphertext.data,
			     scratch->length, &eblock, 0))) {
        krb5_finish_key(context, &eblock);
        goto cleanup;
    }
    
    if ((retval = krb5_finish_key(context, &eblock)))
        goto cleanup;

    retval = encode_krb5_ap_req(&request, &toutbuf);
    *outbuf = *toutbuf;
    krb5_xfree(toutbuf);

cleanup:
    memset(request.authenticator.ciphertext.data, 0,
           request.authenticator.ciphertext.length);
    free(request.authenticator.ciphertext.data);

cleanup_ticket:
    krb5_free_ticket(context, request.ticket);

cleanup_data:
    memset(scratch->data, 0, scratch->length);
    free(scratch->data);

cleanup_scratch:
    free(scratch);

    return retval;
}

krb5_error_code
krb5_send_tgs(context, kdcoptions, timestruct, etypes, sname, addrs,
	      authorization_data, padata, second_ticket, in_cred, rep)
    krb5_context context;
    const krb5_flags kdcoptions;
    const krb5_ticket_times * timestruct;
    const krb5_enctype * etypes;
    krb5_const_principal sname;
    krb5_address * const * addrs;
    krb5_authdata * const * authorization_data;
    krb5_pa_data * const * padata;
    const krb5_data * second_ticket;
    krb5_creds * in_cred;
    krb5_response * rep;
{
    krb5_error_code retval;
    krb5_kdc_req tgsreq;
    krb5_data *scratch, scratch2;
    krb5_ticket *sec_ticket = 0;
    krb5_ticket *sec_ticket_arr[2];
    krb5_timestamp time_now;
    krb5_pa_data **combined_padata;
    krb5_pa_data ap_req_padata;

    /* 
     * in_creds MUST be a valid credential NOT just a partially filled in
     * place holder for us to get credentials for the caller.
     */
    if (!in_cred->ticket.length)
        return(KRB5_NO_TKT_SUPPLIED);

    memset((char *)&tgsreq, 0, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime;
    tgsreq.rtime = timestruct->renew_till;
#if 0
    if ((retval = krb5_timeofday(context, &time_now)))
	return(retval);
#else
{long usec;
	if ((retval = krb5_us_timeofday(context, &time_now, &usec)))
	return(retval);
}
#endif
    /* XXX we know they are the same size... */
    tgsreq.nonce = (krb5_int32) time_now;

    tgsreq.addresses = (krb5_address **) addrs;

    if (authorization_data) {
	/* need to encrypt it in the request */
	krb5_encrypt_block eblock;

	if ((retval = encode_krb5_authdata((const krb5_authdata**)authorization_data,
					   &scratch)))
	    return(retval);
	krb5_use_cstype(context, &eblock, in_cred->keyblock.etype);
	tgsreq.authorization_data.etype = in_cred->keyblock.etype;
	tgsreq.authorization_data.kvno = 0; /* ticket session key has */
					    /* no version */
	tgsreq.authorization_data.ciphertext.length =
	    krb5_encrypt_size(scratch->length, eblock.crypto_entry);
	/* add padding area, and zero it */
	if (!(scratch->data = realloc(scratch->data,
			      tgsreq.authorization_data.ciphertext.length))) {
	    /* may destroy scratch->data */
	    krb5_xfree(scratch);
	    return ENOMEM;
	}
	memset(scratch->data + scratch->length, 0,
	       tgsreq.authorization_data.ciphertext.length - scratch->length);
	if (!(tgsreq.authorization_data.ciphertext.data =
	      malloc(tgsreq.authorization_data.ciphertext.length))) {
	    krb5_free_data(context, scratch);
	    return ENOMEM;
	}
	if ((retval = krb5_process_key(context, &eblock,
				       &in_cred->keyblock))) {
	    krb5_free_data(context, scratch);
	    return retval;
	}
	/* call the encryption routine */
	if ((retval = krb5_encrypt(context, (krb5_pointer) scratch->data,
		   (krb5_pointer) tgsreq.authorization_data.ciphertext.data,
				   scratch->length, &eblock, 0))) {
	    (void) krb5_finish_key(context, &eblock);
	    krb5_xfree(tgsreq.authorization_data.ciphertext.data);
	    krb5_free_data(context, scratch);
	    return retval;
	}	    
	krb5_free_data(context, scratch);
	if ((retval = krb5_finish_key(context, &eblock))) {
	    krb5_xfree(tgsreq.authorization_data.ciphertext.data);
	    return retval;
	}
    }

    /* Get the encryption types list */
    if (etypes) {
	/* Check passed etypes and make sure they're valid. */
   	for (tgsreq.netypes = 0; etypes[tgsreq.netypes]; tgsreq.netypes++) {
    	    if (!valid_etype(etypes[tgsreq.netypes]))
		return KRB5_PROG_ETYPE_NOSUPP;
	}
    	tgsreq.etype = (krb5_enctype *)etypes;
    } else {
        /* Get the default etypes */
        krb5_get_default_in_tkt_etypes(context, &(tgsreq.etype));
	for(tgsreq.netypes = 0; tgsreq.etype[tgsreq.netypes]; tgsreq.netypes++);
    }

    if (second_ticket) {
	if ((retval = decode_krb5_ticket(second_ticket, &sec_ticket)))
	    goto send_tgs_error_1;
	sec_ticket_arr[0] = sec_ticket;
	sec_ticket_arr[1] = 0;
	tgsreq.second_ticket = sec_ticket_arr;
    } else
	tgsreq.second_ticket = 0;

    /* encode the body; then checksum it */
    if ((retval = encode_krb5_kdc_req_body(&tgsreq, &scratch)))
	goto send_tgs_error_2;

    /*
     * Get an ap_req.
     */
    if ((retval = krb5_send_tgs_basic(context, scratch, in_cred, &scratch2))) {
        krb5_free_data(context, scratch);
	goto send_tgs_error_2;
    }
    krb5_free_data(context, scratch);

    ap_req_padata.pa_type = KRB5_PADATA_AP_REQ;
    ap_req_padata.length = scratch2.length;
    ap_req_padata.contents = (krb5_octet *)scratch2.data;

    /* combine in any other supplied padata */
    if (padata) {
	krb5_pa_data * const * counter;
	register int i = 0;
	for (counter = padata; *counter; counter++, i++);
	combined_padata = (krb5_pa_data **)malloc(i+2);
	if (!combined_padata) {
	    krb5_xfree(ap_req_padata.contents);
	    retval = ENOMEM;
	    goto send_tgs_error_2;
	}
	combined_padata[0] = &ap_req_padata;
	for (i = 1, counter = padata; *counter; counter++, i++)
	    combined_padata[i] = (krb5_pa_data *) *counter;
	combined_padata[i] = 0;
    } else {
	combined_padata = (krb5_pa_data **)malloc(2*sizeof(*combined_padata));
	if (!combined_padata) {
	    krb5_xfree(ap_req_padata.contents);
	    retval = ENOMEM;
	    goto send_tgs_error_2;
	}
	combined_padata[0] = &ap_req_padata;
	combined_padata[1] = 0;
    }
    tgsreq.padata = combined_padata;

    /* the TGS_REQ is assembled in tgsreq, so encode it */
    if ((retval = encode_krb5_tgs_req(&tgsreq, &scratch))) {
	krb5_xfree(ap_req_padata.contents);
	krb5_xfree(combined_padata);
	goto send_tgs_error_2;
    }
    krb5_xfree(ap_req_padata.contents);
    krb5_xfree(combined_padata);

    /* now send request & get response from KDC */
    retval = krb5_sendto_kdc(context, scratch, 
			     krb5_princ_realm(context, sname),
			     &rep->response);
    krb5_free_data(context, scratch);

    if (retval == 0) {
        if (krb5_is_tgs_rep(&rep->response))
	    rep->message_type = KRB5_TGS_REP;
        else /* assume it's an error */
	    rep->message_type = KRB5_ERROR;
    }

send_tgs_error_2:;
    if (sec_ticket) 
	krb5_free_ticket(context, sec_ticket);

send_tgs_error_1:;
    if (etypes == NULL)
	krb5_xfree(tgsreq.etype);
    if (tgsreq.authorization_data.ciphertext.data) {
	memset(tgsreq.authorization_data.ciphertext.data, 0,
               tgsreq.authorization_data.ciphertext.length); 
	krb5_xfree(tgsreq.authorization_data.ciphertext.data);
    }


    return retval;
}
