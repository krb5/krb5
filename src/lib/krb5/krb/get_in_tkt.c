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


/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) PROTOTYPE((krb5_context,
						   const krb5_enctype,
						   krb5_data *,
						   krb5_const_pointer,
						   krb5_keyblock **));

typedef krb5_error_code (*git_decrypt_proc) PROTOTYPE((krb5_context,
						       const krb5_keyblock *,
						       krb5_const_pointer,
						       krb5_kdc_rep * ));
/*
 * This function sends a request to the KDC, and gets back a response;
 * the response is parsed into ret_err_reply or ret_as_reply if the
 * reponse is a KRB_ERROR or a KRB_AS_REP packet.  If it is some other
 * unexpected response, an error is returned.
 */
static krb5_error_code
send_as_request(context, request, time_now, ret_err_reply, ret_as_reply)
    krb5_context 		context;
    krb5_kdc_req		*request;
    krb5_timestamp 		*time_now;
    krb5_error ** 		ret_err_reply;
    krb5_kdc_rep ** 		ret_as_reply;
{
    krb5_kdc_rep *as_reply = 0;
    krb5_error_code retval;
    krb5_data *packet;
    krb5_data reply;
    char k4_version;		/* same type as *(krb5_data::data) */

    reply.data = 0;
    
    if ((retval = krb5_timeofday(context, time_now)))
	goto cleanup;

    /*
     * XXX we know they are the same size... and we should do
     * something better than just the current time
     */
    request->nonce = (krb5_int32) *time_now;

    /* encode & send to KDC */
    if ((retval = encode_krb5_as_req(request, &packet)) != 0)
	goto cleanup;

    k4_version = packet->data[0];
    retval = krb5_sendto_kdc(context, packet, 
			     krb5_princ_realm(context, request->client), &reply);
    krb5_free_data(context, packet);
    if (retval)
	goto cleanup;

    /* now decode the reply...could be error or as_rep */
    if (krb5_is_krb_error(&reply)) {
	krb5_error *err_reply;

	if ((retval = decode_krb5_error(&reply, &err_reply)))
	    /* some other error code--??? */	    
	    goto cleanup;
    
	if (ret_err_reply)
	    *ret_err_reply = err_reply;
	else
	    krb5_free_error(context, err_reply);
	goto cleanup;
    }

    /*
     * Check to make sure it isn't a V4 reply.
     */
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

    /* It must be a KRB_AS_REP message, or an bad returned packet */
    if ((retval = decode_krb5_as_rep(&reply, &as_reply)))
	/* some other error code ??? */
	goto cleanup;

    if (as_reply->msg_type != KRB5_AS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	krb5_free_kdc_rep(context, as_reply);
	goto cleanup;
    }

    if (ret_as_reply)
	*ret_as_reply = as_reply;
    else
	krb5_free_kdc_rep(context, as_reply);

cleanup:
    if (reply.data)
	free(reply.data);
    return retval;
}

static krb5_error_code
decrypt_as_reply(context, request, as_reply, key_proc, keyseed,
		 decrypt_proc, decryptarg)
    krb5_context 		context;
    krb5_kdc_req		*request;
    krb5_kdc_rep		*as_reply;
    git_key_proc 		key_proc;
    krb5_const_pointer 		keyseed;
    git_decrypt_proc 		decrypt_proc;
    krb5_const_pointer 		decryptarg;
{
    krb5_error_code		retval;
    krb5_keyblock *		decrypt_key = 0;
    krb5_data 			salt;
    int				use_salt = 0;
    int				f_salt = 0;
    
    if (as_reply->enc_part2)
	return 0;
    
    /* Temp kludge to get salt */
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
	if ((retval = krb5_principal2salt(context, request->client, &salt)))
	    return(retval);
	f_salt = 1;
    }
    
    if ((retval = (*key_proc)(context, as_reply->ticket->enc_part.enctype,
			      &salt, keyseed, &decrypt_key)))
	goto cleanup;
    
    if ((retval = (*decrypt_proc)(context, decrypt_key, decryptarg, as_reply)))
	goto cleanup;

cleanup:
    if (f_salt)
	krb5_xfree(salt.data);
    if (decrypt_key)
	krb5_free_keyblock(context, decrypt_key);
    return (retval);
}

static krb5_error_code
verify_as_reply(context, time_now, request, as_reply)
    krb5_context 		context;
    krb5_timestamp 		time_now;
    krb5_kdc_req		*request;
    krb5_kdc_rep		*as_reply;
{
    /* check the contents for sanity: */
    if (!as_reply->enc_part2->times.starttime)
	as_reply->enc_part2->times.starttime =
	    as_reply->enc_part2->times.authtime;
    
    if (!krb5_principal_compare(context, as_reply->client, request->client)
	|| !krb5_principal_compare(context, as_reply->enc_part2->server, request->server)
	|| !krb5_principal_compare(context, as_reply->ticket->server, request->server)
	|| (request->nonce != as_reply->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(context, addrs, as_reply->enc_part2->caddrs)) */
	|| ((request->from != 0) &&
	    (request->from != as_reply->enc_part2->times.starttime))
	|| ((request->till != 0) &&
	    (as_reply->enc_part2->times.endtime > request->till))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE) &&
	    (request->rtime != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->rtime))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request->till != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->till))
	)
	return KRB5_KDCREP_MODIFIED;

    if ((request->from == 0) &&
	(labs(as_reply->enc_part2->times.starttime - time_now)
	 > context->clockskew))
	return (KRB5_KDCREP_SKEW);

    return 0;
}

static krb5_error_code
stash_as_reply(context, time_now, request, as_reply, creds, ccache)
    krb5_context 		context;
    krb5_timestamp 		time_now;
    krb5_kdc_req		*request;
    krb5_kdc_rep		*as_reply;
    krb5_creds * 		creds;
    krb5_ccache 		ccache;
{
    krb5_error_code 		retval;
    krb5_data *			packet;

   if (context->library_options & KRB5_LIBOPT_SYNC_KDCTIME)
       krb5_set_time_offsets(context,
			     (as_reply->enc_part2->times.authtime -
			      time_now),
			     0);

    /* XXX issue warning if as_reply->enc_part2->key_exp is nearby */
	
    /* fill in the credentials */
    if ((retval = krb5_copy_keyblock_contents(context, 
					      as_reply->enc_part2->session,
					      &creds->keyblock)))
	return (retval);

    creds->times = as_reply->enc_part2->times;
    creds->is_skey = FALSE;		/* this is an AS_REQ, so cannot
					   be encrypted in skey */
    creds->ticket_flags = as_reply->enc_part2->flags;
    if ((retval = krb5_copy_addresses(context, as_reply->enc_part2->caddrs,
				      &creds->addresses)))
	goto cleanup;

    creds->second_ticket.length = 0;
    creds->second_ticket.data = 0;

    if ((retval = encode_krb5_ticket(as_reply->ticket, &packet)))
	goto cleanup;

    creds->ticket = *packet;
    krb5_xfree(packet);

    /* store it in the ccache! */
    if (ccache) {
      if ((retval = krb5_cc_store_cred(context, ccache, creds)))
	goto cleanup;
    }

cleanup:
    if (retval) {
	if (creds->keyblock.contents) {
	    memset((char *)creds->keyblock.contents, 0,
		   creds->keyblock.length);
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
    }
    return (retval);
}

static krb5_error_code
make_preauth_list(context, ptypes, ret_list)
    krb5_context	context;
    krb5_preauthtype *	ptypes;
    krb5_pa_data ***	ret_list;
{
    krb5_preauthtype *		ptypep;
    krb5_pa_data **		preauthp;
    krb5_pa_data **		preauth_to_use;
    int				i;

    for (i=1, ptypep = ptypes; *ptypep; ptypep++, i++)
	;
    preauth_to_use = malloc(i * sizeof(krb5_pa_data *));
    if (preauth_to_use == NULL)
	return (ENOMEM);
    for (preauthp = preauth_to_use, ptypep = ptypes;
	 *ptypep;
	 preauthp++, ptypep++) {
	*preauthp = malloc(sizeof(krb5_pa_data));
	if (*preauthp == NULL) {
	    krb5_free_pa_data(context, preauth_to_use);
	    return (ENOMEM);
	}
	(*preauthp)->magic = KV5M_PA_DATA;
	(*preauthp)->pa_type = *ptypep;
	(*preauthp)->length = 0;
	(*preauthp)->contents = 0;
    }
    *ret_list = preauth_to_use;
    return 0;
}

#define MAX_IN_TKT_LOOPS 16

krb5_error_code
krb5_get_in_tkt(context, options, addrs, ktypes, ptypes, key_proc, keyseed,
		decrypt_proc, decryptarg, creds, ccache, ret_as_reply)
    krb5_context context;
    const krb5_flags options;
    krb5_address * const * addrs;
    krb5_enctype * ktypes;
    krb5_preauthtype * ptypes;
    git_key_proc key_proc;
    krb5_const_pointer keyseed;
    git_decrypt_proc decrypt_proc;
    krb5_const_pointer decryptarg;
    krb5_creds * creds;
    krb5_ccache ccache;
    krb5_kdc_rep ** ret_as_reply;
{
    krb5_error_code	retval;
    krb5_timestamp	time_now;
    krb5_kdc_req	request;
    krb5_pa_data	**padata = 0;
    krb5_error *	err_reply;
    krb5_kdc_rep *	as_reply;
    krb5_pa_data  **	preauth_to_use = 0;
    int			loopcount = 0;
    int			do_more = 0;

    if (! krb5_realm_compare(context, creds->client, creds->server))
	return KRB5_IN_TKT_REALM_MISMATCH;

    if (ret_as_reply)
	*ret_as_reply = 0;
    
    /*
     * Set up the basic request structure
     */
    request.magic = KV5M_KDC_REQ;
    request.msg_type = KRB5_AS_REQ;
    request.addresses = 0;
    request.ktype = 0;
    if (addrs)
	request.addresses = (krb5_address **) addrs;
    else
	if ((retval = krb5_os_localaddr(context, &request.addresses)))
	    goto cleanup;
    request.padata = 0;
    request.kdc_options = options;
    request.client = creds->client;
    request.server = creds->server;
    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;
    if (ktypes)
	request.ktype = ktypes;
    else
    	if ((retval = krb5_get_default_in_tkt_ktypes(context, &request.ktype)))
	    goto cleanup;
    for (request.nktypes = 0;request.ktype[request.nktypes];request.nktypes++);
    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /*
     * If a list of preauth types are passed in, convert it to a
     * preauth_to_use list.
     */
    if (ptypes) {
	retval = make_preauth_list(context, ptypes, &preauth_to_use);
	if (retval)
	    goto cleanup;
    }
	    
    while (1) {
	if (loopcount++ > MAX_IN_TKT_LOOPS) {
	    retval = KRB5_GET_IN_TKT_LOOP;
	    goto cleanup;
	}

	if ((retval = krb5_obtain_padata(context, preauth_to_use, key_proc,
					 keyseed, creds, &request)) != 0)
	    goto cleanup;
	if (preauth_to_use)
	    krb5_free_pa_data(context, preauth_to_use);
	preauth_to_use = 0;
	
	err_reply = 0;
	as_reply = 0;
	if ((retval = send_as_request(context, &request, &time_now, &err_reply,
				      &as_reply)))
	    goto cleanup;

	if (err_reply) {
	    if (err_reply->error == KDC_ERR_PREAUTH_REQUIRED &&
		err_reply->e_data.length > 0) {
		retval = decode_krb5_padata_sequence(&err_reply->e_data,
						     &preauth_to_use);
		krb5_free_error(context, err_reply);
		if (retval)
		    goto cleanup;
		continue;
	    } else {
		retval = err_reply->error + ERROR_TABLE_BASE_krb5;
		krb5_free_error(context, err_reply);
		goto cleanup;
	    }
	} else if (!as_reply) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto cleanup;
	}
	if ((retval = krb5_process_padata(context, &request, as_reply,
					  key_proc, keyseed, creds,
					  &do_more)) != 0)
	    goto cleanup;

	if (!do_more)
	    break;
    }
    
    if ((retval = decrypt_as_reply(context, &request, as_reply, key_proc,
				   keyseed, decrypt_proc, decryptarg)))
	goto cleanup;

    if ((retval = verify_as_reply(context, time_now, &request, as_reply)))
	goto cleanup;

    if ((retval = stash_as_reply(context, time_now, &request, as_reply,
				 creds, ccache)))
	goto cleanup;

cleanup:
    if (!ktypes && request.ktype)
	free(request.ktype);
    if (!addrs && request.addresses)
	krb5_free_addresses(context, request.addresses);
    if (request.padata)
	krb5_free_pa_data(context, request.padata);
    if (padata)
	krb5_free_pa_data(context, padata);
    if (preauth_to_use)
	krb5_free_pa_data(context, preauth_to_use);
    if (as_reply) {
	if (ret_as_reply)
	    *ret_as_reply = as_reply;
	else
	    krb5_free_kdc_rep(context, as_reply);
    }
    return (retval);
}
