/*
 * lib/krb5/krb/get_in_tkt.c
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
 * krb5_get_in_tkt()
 */

#include "k5-int.h"

/*
 All-purpose initial ticket routine, usually called via
 krb5_get_in_tkt_with_password or krb5_get_in_tkt_with_skey.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, and using creds->times.starttime, creds->times.endtime,
 creds->times.renew_till as from, till, and rtime.  
 creds->times.renew_till is ignored unless the RENEWABLE option is requested.

 key_proc is called to fill in the key to be used for decryption.
 keyseed is passed on to key_proc.

 decrypt_proc is called to perform the decryption of the response (the
 encrypted part is in dec_rep->enc_part; the decrypted part should be
 allocated and filled into dec_rep->enc_part2
 arg is passed on to decrypt_proc.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 A succesful call will place the ticket in the credentials cache ccache
 and fill in creds with the ticket information used/returned..

 returns system errors, encryption errors

 */


extern krb5_deltat krb5_clockskew;
#define in_clock_skew(date) (labs((date)-request.nonce) < krb5_clockskew)

/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) PROTOTYPE((krb5_context,
						   const krb5_keytype,
						   krb5_data *,
						   krb5_const_pointer,
						   krb5_keyblock **));

typedef krb5_error_code (*git_decrypt_proc) PROTOTYPE((krb5_context,
						       const krb5_keyblock *,
						       krb5_const_pointer,
						       krb5_kdc_rep * ));
krb5_error_code
krb5_get_in_tkt(context, options, addrs, etypes, ptypes, key_proc, keyseed,
		decrypt_proc, decryptarg, creds, ccache, ret_as_reply)
    krb5_context context;
    const krb5_flags options;
    krb5_address * const * addrs;
    krb5_enctype * etypes;
    krb5_preauthtype * ptypes;
    git_key_proc key_proc;
    krb5_const_pointer keyseed;
    git_decrypt_proc decrypt_proc;
    krb5_const_pointer decryptarg;
    krb5_creds * creds;
    krb5_ccache ccache;
    krb5_kdc_rep ** ret_as_reply;
{
    krb5_keytype keytype;
    krb5_enctype etype;
    krb5_kdc_req request;
    krb5_kdc_rep *as_reply = 0;
    krb5_error *err_reply;
    krb5_error_code retval;
    krb5_data *packet;
    krb5_data reply;
    krb5_keyblock *decrypt_key = 0;
    krb5_timestamp time_now;
/*    krb5_pa_data	*padata; */
    int f_salt = 0, use_salt = 0;
    krb5_data salt;
    char k4_version;		/* same type as *(krb5_data::data) */

    if (! krb5_realm_compare(context, creds->client, creds->server))
	return KRB5_IN_TKT_REALM_MISMATCH;

    if (ret_as_reply)
	*ret_as_reply = 0;
    
    request.msg_type = KRB5_AS_REQ;
    if (!addrs)
	krb5_os_localaddr(context, &request.addresses);
    else
	request.addresses = (krb5_address **) addrs;

    reply.data = 0;

    if (1) {
	    decrypt_key = 0;
	    request.padata = 0;
    } else {
    	    /* Pre authentication is not yet supported */

	    /*
	     * First, we get the user's key.  We assume we will need
	     * it for the pre-authentication.  Actually, this could
	     * possibly not be the case, but it's usually true.
	     *
	     * XXX Problem here: if we're doing preauthentication,
	     * we're getting the key before we get the KDC hit as to
	     * which salting algorithm to use; hence, we're using the
	     * default.  But if we're changing salts, because of a
	     * realm renaming, or some such, this won't work.
	     */
/*    retval = (*key_proc)(context, keytype, &decrypt_key, keyseed, 0); */
	    if (retval)
		    return retval;
	    request.padata = (krb5_pa_data **) malloc(sizeof(krb5_pa_data *)
						      * 2);
	    if (!request.padata) {
		retval = ENOMEM;
		goto cleanup;
	    }
	    
	  /*  retval = krb5_obtain_padata(context, ptypes[0], creds->client,
					request.addresses, decrypt_key,
					&padata); */
	    if (retval)
		goto cleanup;
/*	    request.padata[0] = padata; */
	    request.padata[1] = 0;
    }
    
    request.kdc_options = options;
    request.client = creds->client;
    request.server = creds->server;

    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;
    if ((retval = krb5_timeofday(context, &time_now)))
	goto cleanup;

    /* XXX we know they are the same size... */
    request.nonce = (krb5_int32) time_now;

    if (etypes) 
	request.etype = etypes;
    else 
    	krb5_get_default_in_tkt_etypes(context, &request.etype);
    for (request.netypes = 0;request.etype[request.netypes];request.netypes++);
    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /* encode & send to KDC */
    retval = encode_krb5_as_req(&request, &packet);
    if (!etypes)
      free(request.etype);
    if (retval)
      goto cleanup;

    k4_version = packet->data[0];
    retval = krb5_sendto_kdc(context, packet, 
			     krb5_princ_realm(context, creds->client), &reply);
    krb5_free_data(context, packet);
    if (retval)
	goto cleanup;

    /* now decode the reply...could be error or as_rep */

    if (krb5_is_krb_error(&reply)) {
	if ((retval = decode_krb5_error(&reply, &err_reply)))
	    /* some other error code--??? */	    
	    goto cleanup;
    
	/* it was an error */

	if ((err_reply->ctime != request.nonce) ||
	    !krb5_principal_compare(context, err_reply->server, request.server) ||
	    !krb5_principal_compare(context, err_reply->client, request.client))
	    retval = KRB5_KDCREP_MODIFIED;
	else
	    retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	/* XXX somehow make error msg text available to application? */

	krb5_free_error(context, err_reply);
	goto cleanup;
    }

    if (!krb5_is_as_rep(&reply)) {
/* these are in <kerberosIV/prot.h> as well but it isn't worth including. */
#define V4_KRB_PROT_VERSION	4
#define V4_AUTH_MSG_ERR_REPLY	(5<<1)
	/* check here for V4 reply */
	unsigned int t_switch;

	/* From v4 g_in_tkt.c: This used to be
	   switch (pkt_msg_type(rpkt) & ~1) {
	   but SCO 3.2v4 cc compiled that incorrectly.  */
	t_switch = reply.data[1];
	t_switch &= ~1;

	if (t_switch == V4_AUTH_MSG_ERR_REPLY
	    && (reply.data[0] == V4_KRB_PROT_VERSION
		|| reply.data[0] == k4_version)) {
	    retval = KRB5KRB_AP_ERR_V4_REPLY;
	} else {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	}
	goto cleanup;
    }
    if ((retval = decode_krb5_as_rep(&reply, &as_reply)))
	/* some other error code ??? */
	goto cleanup;

    if (as_reply->msg_type != KRB5_AS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto cleanup;
    }

    /* Encryption type, keytype, */
    etype = as_reply->ticket->enc_part.etype;
    keytype = krb5_csarray[etype]->system->proto_keytype;

    /* and salt */
    if (as_reply->padata) {
	krb5_pa_data **ptr;

        for (ptr = as_reply->padata; *ptr; ptr++) {
            if ((*ptr)->pa_type == KRB5_PADATA_PW_SALT) {
                /* use KDC-supplied salt, instead of default */
                salt.data = (char *)(*ptr)->contents;
                salt.length = (*ptr)->length;
                use_salt = 1;
                break;
            }
        }
    } 
    if (!use_salt) {
        /* need to use flattened principal */
        if ((retval = krb5_principal2salt(context, creds->client, &salt)))
            return(retval);
        f_salt = 1;
    }

    /* it was a kdc_rep--decrypt & check */
    /* Generate the key, if we haven't done so already. */
    if (!decrypt_key) {
	    if ((retval = (*key_proc)(context, keytype, & salt, keyseed,
				      &decrypt_key)))
		goto cleanup;
    }
    
    if ((retval = (*decrypt_proc)(context, decrypt_key, decryptarg, as_reply)))
	goto cleanup;

    krb5_free_keyblock(context, decrypt_key);
    decrypt_key = 0;
    
    /* check the contents for sanity: */
    if (!as_reply->enc_part2->times.starttime)
	as_reply->enc_part2->times.starttime =
	    as_reply->enc_part2->times.authtime;
    if (!krb5_principal_compare(context, as_reply->client, request.client)
	|| !krb5_principal_compare(context, as_reply->enc_part2->server, request.server)
	|| !krb5_principal_compare(context, as_reply->ticket->server, request.server)
	|| (request.nonce != as_reply->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(context, addrs, as_reply->enc_part2->caddrs)) */
	|| ((request.from != 0) &&
	    (request.from != as_reply->enc_part2->times.starttime))
	|| ((request.till != 0) &&
	    (as_reply->enc_part2->times.endtime > request.till))
	|| ((request.kdc_options & KDC_OPT_RENEWABLE) &&
	    (request.rtime != 0) &&
	    (as_reply->enc_part2->times.renew_till > request.rtime))
	|| ((request.kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request.till != 0) &&
	    (as_reply->enc_part2->times.renew_till > request.till))
	) {
	retval = KRB5_KDCREP_MODIFIED;
	goto cleanup;
    }
    if ((request.from == 0) &&
	!in_clock_skew(as_reply->enc_part2->times.starttime)) {
	retval = KRB5_KDCREP_SKEW;
	goto cleanup;
    }
    

    /* XXX issue warning if as_reply->enc_part2->key_exp is nearby */
	
    /* fill in the credentials */
    if ((retval = krb5_copy_keyblock_contents(context, 
					      as_reply->enc_part2->session,
					      &creds->keyblock)))
	goto cleanup;
    creds->keyblock.etype = as_reply->ticket->enc_part.etype;

    creds->times = as_reply->enc_part2->times;
    creds->is_skey = FALSE;		/* this is an AS_REQ, so cannot
					   be encrypted in skey */
    creds->ticket_flags = as_reply->enc_part2->flags;
    if ((retval = krb5_copy_addresses(context, as_reply->enc_part2->caddrs,
				      &creds->addresses)))
	goto cred_cleanup;

    creds->second_ticket.length = 0;
    creds->second_ticket.data = 0;

    if ((retval = encode_krb5_ticket(as_reply->ticket, &packet)))
	goto cred_cleanup;

    creds->ticket = *packet;
    krb5_xfree(packet);

    /* store it in the ccache! */
    if (ccache) {
      if ((retval = krb5_cc_store_cred(context, ccache, creds)))
	goto cred_cleanup;
    }

    if (ret_as_reply) {
	*ret_as_reply = as_reply;
	as_reply = 0;
    }

    retval = 0;
    
cleanup:
    if (f_salt)
	krb5_xfree(salt.data);
    if (as_reply)
	krb5_free_kdc_rep(context, as_reply);
    if (reply.data)
	free(reply.data);
    if (decrypt_key)
	krb5_free_keyblock(context, decrypt_key);
    if (request.padata)
	free(request.padata);
    if (!addrs)
	krb5_free_addresses(context, request.addresses);
    return retval;
    
    /*
     * Clean up left over mess in credentials structure, in case of 
     * error
     */
cred_cleanup:
    if (creds->keyblock.contents) {
	memset((char *)creds->keyblock.contents, 0, creds->keyblock.length);
	krb5_xfree(creds->keyblock.contents);
	creds->keyblock.contents = 0;
	creds->keyblock.length = 0;
    }
    if (creds->ticket.data) {
	krb5_xfree(creds->ticket.data);
	creds->ticket.data = 0;
    }
    if (creds->addresses) {
	krb5_free_addresses(context, creds->addresses);
	creds->addresses = 0;
    }
    goto cleanup;
}

