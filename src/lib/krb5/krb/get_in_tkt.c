/*
 * lib/krb5/krb/get_in_tkt.c
 *
 * Copyright 1990,1991, 2003, 2008 by the Massachusetts Institute of Technology.
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
 * krb5_get_in_tkt()
 */

#include <string.h>

#include "k5-int.h"
#include "int-proto.h"
#include "os-proto.h"
#include "fast.h"

#if APPLE_PKINIT
#define     IN_TKT_DEBUG    0
#if	    IN_TKT_DEBUG
#define     inTktDebug(args...)       printf(args)
#else
#define     inTktDebug(args...)
#endif
#endif /* APPLE_PKINIT */

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

typedef krb5_error_code (*git_key_proc) (krb5_context,
						   krb5_enctype,
						   krb5_data *,
						   krb5_const_pointer,
						   krb5_keyblock **);

typedef krb5_error_code (*git_decrypt_proc) (krb5_context,
						       const krb5_keyblock *,
						       krb5_const_pointer,
						       krb5_kdc_rep * );

static krb5_error_code make_preauth_list (krb5_context, 
						    krb5_preauthtype *,
						    int, krb5_pa_data ***);
static krb5_error_code sort_krb5_padata_sequence(krb5_context context,
						 krb5_data *realm,
						 krb5_pa_data **padata);

/*
 * This function performs 32 bit bounded addition so we can generate
 * lifetimes without overflowing krb5_int32
 */
static krb5_int32 krb5int_addint32 (krb5_int32 x, krb5_int32 y)
{
    if ((x > 0) && (y > (KRB5_INT32_MAX - x))) {
        /* sum will be be greater than KRB5_INT32_MAX */
        return KRB5_INT32_MAX;
    } else if ((x < 0) && (y < (KRB5_INT32_MIN - x))) {
        /* sum will be less than KRB5_INT32_MIN */
        return KRB5_INT32_MIN;
    }
    
    return x + y;
}

#if APPLE_PKINIT
/*
 * Common code to generate krb5_kdc_req.nonce. Like the original MIT code this
 * just uses krb5_timeofday(); it should use a PRNG. Even more unfortunately this
 * value is used interchangeably with an explicit now_time throughout this module...
 */
static krb5_error_code  
gen_nonce(krb5_context  context,
          krb5_int32    *nonce)
{
    krb5_int32 time_now;
    krb5_error_code retval = krb5_timeofday(context, &time_now);
    if(retval) {
	return retval;
    }
    *nonce = time_now;
    return 0;
}
#endif /* APPLE_PKINIT */

/*
 * This function sends a request to the KDC, and gets back a response;
 * the response is parsed into ret_err_reply or ret_as_reply if the
 * reponse is a KRB_ERROR or a KRB_AS_REP packet.  If it is some other
 * unexpected response, an error is returned.
 */
static krb5_error_code
send_as_request(krb5_context 		context,
		krb5_data *packet, const krb5_data *realm,
		krb5_error ** 		ret_err_reply,
		krb5_kdc_rep ** 	ret_as_reply,
		int 			    *use_master)
{
    krb5_kdc_rep *as_reply = 0;
    krb5_error_code retval;
    krb5_data reply;
    char k4_version;		/* same type as *(krb5_data::data) */
    int tcp_only = 0;

    reply.data = 0;

    /* set the nonce if the caller expects us to do it */

    k4_version = packet->data[0];
send_again:
    retval = krb5_sendto_kdc(context, packet, 
			     realm,
			     &reply, use_master, tcp_only);
#if APPLE_PKINIT
    inTktDebug("krb5_sendto_kdc returned %d\n", (int)retval);
#endif /* APPLE_PKINIT */

    if (retval)
	goto cleanup;

    /* now decode the reply...could be error or as_rep */
    if (krb5_is_krb_error(&reply)) {
	krb5_error *err_reply;

	if ((retval = decode_krb5_error(&reply, &err_reply)))
	    /* some other error code--??? */	    
	    goto cleanup;
    
	if (ret_err_reply) {
	    if (err_reply->error == KRB_ERR_RESPONSE_TOO_BIG
		&& tcp_only == 0) {
		tcp_only = 1;
		krb5_free_error(context, err_reply);
		free(reply.data);
		reply.data = 0;
		goto send_again;
	    }
	    *ret_err_reply = err_reply;
	} else
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
decrypt_as_reply(krb5_context 		context,
		 krb5_kdc_req		*request,
		 krb5_kdc_rep		*as_reply,
		 git_key_proc 		key_proc,
		 krb5_const_pointer 	keyseed,
		 krb5_keyblock *	key,
		 git_decrypt_proc 	decrypt_proc,
		 krb5_const_pointer 	decryptarg)
{
    krb5_error_code		retval;
    krb5_keyblock *		decrypt_key = 0;
    krb5_data 			salt;
    
    if (as_reply->enc_part2)
	return 0;

    if (key)
	    decrypt_key = key;
    else {
	/*
	 * Use salt corresponding to the client principal supplied by
	 * the KDC, which may differ from the requested principal if
	 * canonicalization is in effect.  We will check
	 * as_reply->client later in verify_as_reply.
	 */
	if ((retval = krb5_principal2salt(context, as_reply->client, &salt)))
	    return(retval);
    
	retval = (*key_proc)(context, as_reply->enc_part.enctype,
			     &salt, keyseed, &decrypt_key);
	free(salt.data);
	if (retval)
	    goto cleanup;
    }
    
    if ((retval = (*decrypt_proc)(context, decrypt_key, decryptarg, as_reply)))
	goto cleanup;

cleanup:
    if (!key && decrypt_key)
	krb5_free_keyblock(context, decrypt_key);
    return (retval);
}

static krb5_error_code
verify_as_reply(krb5_context 		context,
		krb5_timestamp 		time_now,
		krb5_kdc_req		*request,
		krb5_kdc_rep		*as_reply)
{
    krb5_error_code		retval;
    int				canon_req;
    int				canon_ok;

    /* check the contents for sanity: */
    if (!as_reply->enc_part2->times.starttime)
	as_reply->enc_part2->times.starttime =
	    as_reply->enc_part2->times.authtime;

    /*
     * We only allow the AS-REP server name to be changed if the
     * caller set the canonicalize flag (or requested an enterprise
     * principal) and we requested (and received) a TGT.
     */
    canon_req = ((request->kdc_options & KDC_OPT_CANONICALIZE) != 0) ||
	(krb5_princ_type(context, request->client) == KRB5_NT_ENTERPRISE_PRINCIPAL);
    if (canon_req) {
	canon_ok = IS_TGS_PRINC(context, request->server) &&
		   IS_TGS_PRINC(context, as_reply->enc_part2->server);
    } else
	canon_ok = 0;
 
    if ((!canon_ok &&
	 (!krb5_principal_compare(context, as_reply->client, request->client) ||
	  !krb5_principal_compare(context, as_reply->enc_part2->server, request->server)))
	|| !krb5_principal_compare(context, as_reply->enc_part2->server, as_reply->ticket->server)
	|| (request->nonce != as_reply->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(context, addrs, as_reply->enc_part2->caddrs)) */
	|| ((request->kdc_options & KDC_OPT_POSTDATED) &&
	    (request->from != 0) &&
	    (request->from != as_reply->enc_part2->times.starttime))
	|| ((request->till != 0) &&
	    (as_reply->enc_part2->times.endtime > request->till))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE) &&
	    (request->rtime != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->rtime))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    !(request->kdc_options & KDC_OPT_RENEWABLE) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request->till != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->till))
	) {
#if APPLE_PKINIT
	inTktDebug("verify_as_reply: KDCREP_MODIFIED\n");
	#if IN_TKT_DEBUG
	if(request->client->realm.length && request->client->data->length)
	    inTktDebug("request: name %s realm %s\n", 
		request->client->realm.data, request->client->data->data);
	if(as_reply->client->realm.length && as_reply->client->data->length)
	    inTktDebug("reply  : name %s realm %s\n", 
		as_reply->client->realm.data, as_reply->client->data->data);
	#endif
#endif /* APPLE_PKINIT */
	return KRB5_KDCREP_MODIFIED;
    }

    if (context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) {
	retval = krb5_set_real_time(context,
				    as_reply->enc_part2->times.authtime, -1);
	if (retval)
	    return retval;
    } else {
	if ((request->from == 0) &&
	    (labs(as_reply->enc_part2->times.starttime - time_now)
	     > context->clockskew))
	    return (KRB5_KDCREP_SKEW);
    }
    return 0;
}

static krb5_error_code
stash_as_reply(krb5_context 		context,
	       krb5_timestamp 		time_now,
	       krb5_kdc_req		*request,
	       krb5_kdc_rep		*as_reply,
	       krb5_creds * 		creds,
	       krb5_ccache 		ccache)
{
    krb5_error_code 		retval;
    krb5_data *			packet;
    krb5_principal		client;
    krb5_principal		server;

    client = NULL;
    server = NULL;

    if (!creds->client)
        if ((retval = krb5_copy_principal(context, as_reply->client, &client)))
	    goto cleanup;

    if (!creds->server)
	if ((retval = krb5_copy_principal(context, as_reply->enc_part2->server,
					  &server)))
	    goto cleanup;

    /* fill in the credentials */
    if ((retval = krb5_copy_keyblock_contents(context, 
					      as_reply->enc_part2->session,
					      &creds->keyblock)))
	goto cleanup;

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
    free(packet);

    /* store it in the ccache! */
    if (ccache)
	if ((retval = krb5_cc_store_cred(context, ccache, creds)))
	    goto cleanup;

    if (!creds->client)
	creds->client = client;
    if (!creds->server)
	creds->server = server;

cleanup:
    if (retval) {
	if (client)
	    krb5_free_principal(context, client);
	if (server)
	    krb5_free_principal(context, server);
	if (creds->keyblock.contents) {
	    memset(creds->keyblock.contents, 0,
		   creds->keyblock.length);
	    free(creds->keyblock.contents);
	    creds->keyblock.contents = 0;
	    creds->keyblock.length = 0;
	}
	if (creds->ticket.data) {
	    free(creds->ticket.data);
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
make_preauth_list(krb5_context	context,
		  krb5_preauthtype *	ptypes,
		  int			nptypes,
		  krb5_pa_data ***	ret_list)
{
    krb5_preauthtype *		ptypep;
    krb5_pa_data **		preauthp;
    int				i;

    if (nptypes < 0) {
 	for (nptypes=0, ptypep = ptypes; *ptypep; ptypep++, nptypes++)
 	    ;
    }
 
    /* allocate space for a NULL to terminate the list */
 
    if ((preauthp =
 	 (krb5_pa_data **) malloc((nptypes+1)*sizeof(krb5_pa_data *))) == NULL)
 	return(ENOMEM);
 
    for (i=0; i<nptypes; i++) {
 	if ((preauthp[i] =
 	     (krb5_pa_data *) malloc(sizeof(krb5_pa_data))) == NULL) {
 	    for (; i>=0; i--)
 		free(preauthp[i]);
 	    free(preauthp);
	    return (ENOMEM);
	}
 	preauthp[i]->magic = KV5M_PA_DATA;
 	preauthp[i]->pa_type = ptypes[i];
 	preauthp[i]->length = 0;
 	preauthp[i]->contents = 0;
    }
     
    /* fill in the terminating NULL */
 
    preauthp[nptypes] = NULL;
 
    *ret_list = preauthp;
    return 0;
}

#define MAX_IN_TKT_LOOPS 16
static const krb5_enctype get_in_tkt_enctypes[] = {
    ENCTYPE_DES3_CBC_SHA1,
    ENCTYPE_ARCFOUR_HMAC,
    ENCTYPE_DES_CBC_MD5,
    ENCTYPE_DES_CBC_MD4,
    ENCTYPE_DES_CBC_CRC,
    0
};

static krb5_error_code
rewrite_server_realm(krb5_context context,
		     krb5_const_principal old_server,
		     const krb5_data *realm,
		     krb5_boolean tgs,
		     krb5_principal *server)
{
    krb5_error_code retval;

    assert(*server == NULL);

    retval = krb5_copy_principal(context, old_server, server);
    if (retval)
	return retval;

    krb5_free_data_contents(context, &(*server)->realm);
    (*server)->realm.data = NULL;

    retval = krb5int_copy_data_contents(context, realm, &(*server)->realm);
    if (retval)
	goto cleanup;

    if (tgs) {
	krb5_free_data_contents(context, &(*server)->data[1]);
	(*server)->data[1].data = NULL;

	retval = krb5int_copy_data_contents(context, realm, &(*server)->data[1]);
	if (retval)
	    goto cleanup;
    }

cleanup:
    if (retval) {
	krb5_free_principal(context, *server);
	*server = NULL;
    }

    return retval;
}

static inline int
tgt_is_local_realm(krb5_creds *tgt)
{
    return (tgt->server->length == 2
            && data_eq_string(tgt->server->data[0], KRB5_TGS_NAME)
            && data_eq(tgt->server->data[1], tgt->client->realm)
            && data_eq(tgt->server->realm, tgt->client->realm));
}

krb5_error_code KRB5_CALLCONV
krb5_get_in_tkt(krb5_context context,
		krb5_flags options,
		krb5_address * const * addrs,
		krb5_enctype * ktypes,
		krb5_preauthtype * ptypes,
		git_key_proc key_proc,
		krb5_const_pointer keyseed,
		git_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds * creds,
		krb5_ccache ccache,
		krb5_kdc_rep ** ret_as_reply)
{
    krb5_error_code	retval;
    krb5_timestamp	time_now;
    krb5_keyblock *	decrypt_key = 0;
    krb5_kdc_req	request;
    krb5_data *encoded_request;
    krb5_error *	err_reply;
    krb5_kdc_rep *	as_reply = 0;
    krb5_pa_data  **	preauth_to_use = 0;
    int			loopcount = 0;
    krb5_int32		do_more = 0;
    int			canon_flag;
    int             use_master = 0;
    int			referral_count = 0;
    krb5_principal_data	referred_client;
    krb5_principal	referred_server = NULL;
    krb5_boolean	is_tgt_req;

#if APPLE_PKINIT
    inTktDebug("krb5_get_in_tkt top\n");
#endif /* APPLE_PKINIT */

    if (! krb5_realm_compare(context, creds->client, creds->server))
	return KRB5_IN_TKT_REALM_MISMATCH;

    if (ret_as_reply)
	*ret_as_reply = 0;

    referred_client = *(creds->client);
    referred_client.realm.data = NULL;
    referred_client.realm.length = 0;

    /* per referrals draft, enterprise principals imply canonicalization */
    canon_flag = ((options & KDC_OPT_CANONICALIZE) != 0) ||
	creds->client->type == KRB5_NT_ENTERPRISE_PRINCIPAL;
 
    /*
     * Set up the basic request structure
     */
    request.magic = KV5M_KDC_REQ;
    request.msg_type = KRB5_AS_REQ;
    request.addresses = 0;
    request.ktype = 0;
    request.padata = 0;
    if (addrs)
	request.addresses = (krb5_address **) addrs;
    else
	if ((retval = krb5_os_localaddr(context, &request.addresses)))
	    goto cleanup;
    request.kdc_options = options;
    request.client = creds->client;
    request.server = creds->server;
    request.nonce = 0;
    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;
#if APPLE_PKINIT
    retval = gen_nonce(context, (krb5_int32 *)&time_now);
    if(retval) {
	goto cleanup;
    }
    request.nonce = time_now;
#endif /* APPLE_PKINIT */

    request.ktype = malloc (sizeof(get_in_tkt_enctypes));
    if (request.ktype == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy(request.ktype, get_in_tkt_enctypes, sizeof(get_in_tkt_enctypes));
    for (request.nktypes = 0;request.ktype[request.nktypes];request.nktypes++);
    if (ktypes) {
	int i, req, next = 0;
	for (req = 0; ktypes[req]; req++) {
	    if (ktypes[req] == request.ktype[next]) {
		next++;
		continue;
	    }
	    for (i = next + 1; i < request.nktypes; i++)
		if (ktypes[req] == request.ktype[i]) {
		    /* Found the enctype we want, but not in the
		       position we want.  Move it, but keep the old
		       one from the desired slot around in case it's
		       later in our requested-ktypes list.  */
		    krb5_enctype t;
		    t = request.ktype[next];
		    request.ktype[next] = request.ktype[i];
		    request.ktype[i] = t;
		    next++;
		    break;
		}
	    /* If we didn't find it, don't do anything special, just
	       drop it.  */
	}
	request.ktype[next] = 0;
	request.nktypes = next;
    }
    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /*
     * If a list of preauth types are passed in, convert it to a
     * preauth_to_use list.
     */
    if (ptypes) {
	retval = make_preauth_list(context, ptypes, -1, &preauth_to_use);
	if (retval)
	    goto cleanup;
    }
	    
    is_tgt_req = tgt_is_local_realm(creds);

    while (1) {
	if (loopcount++ > MAX_IN_TKT_LOOPS) {
	    retval = KRB5_GET_IN_TKT_LOOP;
	    goto cleanup;
	}

#if APPLE_PKINIT
	inTktDebug("krb5_get_in_tkt calling krb5_obtain_padata\n");
#endif /* APPLE_PKINIT */
	if ((retval = krb5_obtain_padata(context, preauth_to_use, key_proc,
					 keyseed, creds, &request)) != 0)
	    goto cleanup;
	if (preauth_to_use)
	    krb5_free_pa_data(context, preauth_to_use);
	preauth_to_use = 0;
	
	err_reply = 0;
	as_reply = 0;

        if ((retval = krb5_timeofday(context, &time_now)))
	    goto cleanup;

        /*
         * XXX we know they are the same size... and we should do
         * something better than just the current time
         */
	request.nonce = (krb5_int32) time_now;

	if ((retval = encode_krb5_as_req(&request, &encoded_request)) != 0)
	    goto cleanup;
	retval = send_as_request(context, encoded_request,
				 krb5_princ_realm(context, request.client), &err_reply,
				 &as_reply, &use_master);
	krb5_free_data(context, encoded_request);
	if (retval != 0)
	    goto cleanup;

	if (err_reply) {
	    if (err_reply->error == KDC_ERR_PREAUTH_REQUIRED &&
		err_reply->e_data.length > 0) {
		retval = decode_krb5_padata_sequence(&err_reply->e_data,
						     &preauth_to_use);
		krb5_free_error(context, err_reply);
		if (retval)
		    goto cleanup;
                retval = sort_krb5_padata_sequence(context,
						   &request.server->realm,
						   preauth_to_use);
		if (retval)
		    goto cleanup;
		continue;
	    } else if (canon_flag && err_reply->error == KDC_ERR_WRONG_REALM) {
		if (++referral_count > KRB5_REFERRAL_MAXHOPS ||
		    err_reply->client == NULL ||
		    err_reply->client->realm.length == 0) {
		    retval = KRB5KDC_ERR_WRONG_REALM;
		    krb5_free_error(context, err_reply);
		    goto cleanup;
		}
		/* Rewrite request.client with realm from error reply */
		if (referred_client.realm.data) {
		    krb5_free_data_contents(context, &referred_client.realm);
		    referred_client.realm.data = NULL;
		}
		retval = krb5int_copy_data_contents(context,
						    &err_reply->client->realm,
						    &referred_client.realm);
		krb5_free_error(context, err_reply);		
		if (retval)
		    goto cleanup;
		request.client = &referred_client;

		if (referred_server != NULL) {
		    krb5_free_principal(context, referred_server);
		    referred_server = NULL;
		}

		retval = rewrite_server_realm(context,
					      creds->server,
					      &referred_client.realm,
					      is_tgt_req,
					      &referred_server);
		if (retval)
		    goto cleanup;
		request.server = referred_server;

		continue;
	    } else {
		retval = (krb5_error_code) err_reply->error 
		    + ERROR_TABLE_BASE_krb5;
		krb5_free_error(context, err_reply);
		goto cleanup;
	    }
	} else if (!as_reply) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto cleanup;
	}
	if ((retval = krb5_process_padata(context, &request, as_reply,
					  key_proc, keyseed, decrypt_proc, 
					  &decrypt_key, creds,
					  &do_more)) != 0)
	    goto cleanup;

	if (!do_more)
	    break;
    }
    
    if ((retval = decrypt_as_reply(context, &request, as_reply, key_proc,
				   keyseed, decrypt_key, decrypt_proc,
				   decryptarg)))
	goto cleanup;

    if ((retval = verify_as_reply(context, time_now, &request, as_reply)))
	goto cleanup;

    if ((retval = stash_as_reply(context, time_now, &request, as_reply,
				 creds, ccache)))
	goto cleanup;

cleanup:
    if (request.ktype)
	free(request.ktype);
    if (!addrs && request.addresses)
	krb5_free_addresses(context, request.addresses);
    if (request.padata)
	krb5_free_pa_data(context, request.padata);
    if (preauth_to_use)
	krb5_free_pa_data(context, preauth_to_use);
    if (decrypt_key)
    	krb5_free_keyblock(context, decrypt_key);
    if (as_reply) {
	if (ret_as_reply)
	    *ret_as_reply = as_reply;
	else
	    krb5_free_kdc_rep(context, as_reply);
    }
    if (referred_client.realm.data)
	krb5_free_data_contents(context, &referred_client.realm);
    if (referred_server)
	krb5_free_principal(context, referred_server);
    return (retval);
}

/* begin libdefaults parsing code.  This should almost certainly move
   somewhere else, but I don't know where the correct somewhere else
   is yet. */

/* XXX Duplicating this is annoying; try to work on a better way.*/
static const char *const conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    0,
};

static const char *const conf_no[] = {
    "n", "no", "false", "nil", "0", "off",
    0,
};

int
_krb5_conf_boolean(const char *s)
{
    const char *const *p;

    for(p=conf_yes; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 1;
    }

    for(p=conf_no; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 0;
    }

    /* Default to "no" */
    return 0;
}

static krb5_error_code
krb5_libdefault_string(krb5_context context, const krb5_data *realm,
		       const char *option, char **ret_value)
{
    profile_t profile;
    const char *names[5];
    char **nameval = NULL;
    krb5_error_code retval;
    char realmstr[1024];

    if (realm->length > sizeof(realmstr)-1)
	return(EINVAL);

    strncpy(realmstr, realm->data, realm->length);
    realmstr[realm->length] = '\0';

    if (!context || (context->magic != KV5M_CONTEXT)) 
	return KV5M_CONTEXT;

    profile = context->profile;
	    
    names[0] = KRB5_CONF_LIBDEFAULTS;

    /*
     * Try number one:
     *
     * [libdefaults]
     *		REALM = {
     *			option = <boolean>
     *		}
     */

    names[1] = realmstr;
    names[2] = option;
    names[3] = 0;
    retval = profile_get_values(profile, names, &nameval);
    if (retval == 0 && nameval && nameval[0])
	goto goodbye;

    /*
     * Try number two:
     *
     * [libdefaults]
     *		option = <boolean>
     */
    
    names[1] = option;
    names[2] = 0;
    retval = profile_get_values(profile, names, &nameval);
    if (retval == 0 && nameval && nameval[0])
	goto goodbye;

goodbye:
    if (!nameval) 
	return(ENOENT);

    if (!nameval[0]) {
        retval = ENOENT;
    } else {
        *ret_value = strdup(nameval[0]);
        if (!*ret_value)
            retval = ENOMEM;
    }

    profile_free_list(nameval);

    return retval;
}

/* not static so verify_init_creds() can call it */
/* as well as the DNS code */

krb5_error_code
krb5_libdefault_boolean(krb5_context context, const krb5_data *realm,
			const char *option, int *ret_value)
{
    char *string = NULL;
    krb5_error_code retval;

    retval = krb5_libdefault_string(context, realm, option, &string);

    if (retval)
	return(retval);

    *ret_value = _krb5_conf_boolean(string);
    free(string);

    return(0);
}

/* Sort a pa_data sequence so that types named in the "preferred_preauth_types"
 * libdefaults entry are listed before any others. */
static krb5_error_code
sort_krb5_padata_sequence(krb5_context context, krb5_data *realm,
			  krb5_pa_data **padata)
{
    int i, j, base;
    krb5_error_code ret;
    const char *p;
    long l;
    char *q, *preauth_types = NULL;
    krb5_pa_data *tmp;
    int need_free_string = 1;

    if ((padata == NULL) || (padata[0] == NULL)) {
	return 0;
    }

    ret = krb5_libdefault_string(context, realm, KRB5_CONF_PREFERRED_PREAUTH_TYPES,
				 &preauth_types);
    if ((ret != 0) || (preauth_types == NULL)) {
	/* Try to use PKINIT first. */
	preauth_types = "17, 16, 15, 14";
	need_free_string = 0;
    }

#ifdef DEBUG
    fprintf (stderr, "preauth data types before sorting:");
    for (i = 0; padata[i]; i++) {
	fprintf (stderr, " %d", padata[i]->pa_type);
    }
    fprintf (stderr, "\n");
#endif

    base = 0;
    for (p = preauth_types; *p != '\0';) {
	/* skip whitespace to find an entry */
	p += strspn(p, ", ");
	if (*p != '\0') {
	    /* see if we can extract a number */
	    l = strtol(p, &q, 10);
	    if ((q != NULL) && (q > p)) {
		/* got a valid number; search for a matchin entry */
		for (i = base; padata[i] != NULL; i++) {
		    /* bubble the matching entry to the front of the list */
		    if (padata[i]->pa_type == l) {
			tmp = padata[i];
			for (j = i; j > base; j--)
			    padata[j] = padata[j - 1];
			padata[base] = tmp;
			base++;
			break;
		    }
		}
		p = q;
	    } else {
		break;
	    }
	}
    }
    if (need_free_string)
	free(preauth_types);

#ifdef DEBUG
    fprintf (stderr, "preauth data types after sorting:");
    for (i = 0; padata[i]; i++)
	fprintf (stderr, " %d", padata[i]->pa_type);
    fprintf (stderr, "\n");
#endif

    return 0;
}

static krb5_error_code
build_in_tkt_name(krb5_context context,
		  char *in_tkt_service,
		  krb5_const_principal client,
		  krb5_principal *server)
{
    krb5_error_code ret;

    *server = NULL;

    if (in_tkt_service) {
	/* this is ugly, because so are the data structures involved.  I'm
	   in the library, so I'm going to manipulate the data structures
	   directly, otherwise, it will be worse. */

        if ((ret = krb5_parse_name(context, in_tkt_service, server)))
	    return ret;

	/* stuff the client realm into the server principal.
	   realloc if necessary */
	if ((*server)->realm.length < client->realm.length) {
	    char *p = realloc((*server)->realm.data,
			      client->realm.length);
	    if (p == NULL) {
		krb5_free_principal(context, *server);
		*server = NULL;
		return ENOMEM;
	    }
	    (*server)->realm.data = p;
	}

	(*server)->realm.length = client->realm.length;
	memcpy((*server)->realm.data, client->realm.data, client->realm.length);
    } else {
	ret = krb5_build_principal_ext(context, server,
				       client->realm.length,
				       client->realm.data,
				       KRB5_TGS_NAME_SIZE,
				       KRB5_TGS_NAME,
				       client->realm.length,
				       client->realm.data,
				       0);
    }
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds(krb5_context context,
		    krb5_creds *creds,
		    krb5_principal client,
		    krb5_prompter_fct prompter,
		    void *prompter_data,
		    krb5_deltat start_time,
		    char *in_tkt_service,
		    krb5_gic_opt_ext *options,
		    krb5_gic_get_as_key_fct gak_fct,
		    void *gak_data,
		    int  *use_master,
		    krb5_kdc_rep **as_reply)
{
    krb5_error_code ret;
    krb5_kdc_req request;
    krb5_data *encoded_request_body, *encoded_previous_request;
    krb5_pa_data **preauth_to_use, **kdc_padata;
    int tempint;
    char *tempstr;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    int loopcount;
    krb5_data salt;
    krb5_data s2kparams;
    krb5_keyblock as_key, encrypting_key;
    krb5_keyblock *strengthen_key = NULL;
    krb5_error *err_reply;
    krb5_kdc_rep *local_as_reply;
    krb5_timestamp time_now;
    krb5_enctype etype = 0;
    krb5_preauth_client_rock get_data_rock;
    int canon_flag = 0;
    krb5_principal_data referred_client;
    krb5_boolean retry = 0;
    struct krb5int_fast_request_state *fast_state = NULL;
    krb5_pa_data **out_padata = NULL;
    

    /* initialize everything which will be freed at cleanup */

    s2kparams.data = NULL;
    s2kparams.length = 0;
    request.server = NULL;
    request.ktype = NULL;
    request.addresses = NULL;
    request.padata = NULL;
    encoded_request_body = NULL;
    encoded_previous_request = NULL;
    preauth_to_use = NULL;
    kdc_padata = NULL;
    as_key.length = 0;
    encrypting_key.length = 0;
    encrypting_key.contents = NULL;
        salt.length = 0;
    salt.data = NULL;

	local_as_reply = 0;
#if APPLE_PKINIT
    inTktDebug("krb5_get_init_creds top\n");
#endif /* APPLE_PKINIT */
    
    err_reply = NULL;

    /* referred_client is used to rewrite the client realm for referrals */
    referred_client = *client;
    referred_client.realm.data = NULL;
    referred_client.realm.length = 0;
    ret = krb5int_fast_make_state(context, &fast_state);
    if (ret)
	    goto cleanup;

    /*
     * Set up the basic request structure
     */
    request.magic = KV5M_KDC_REQ;
    request.msg_type = KRB5_AS_REQ;

    /* request.nonce is filled in when we send a request to the kdc */
    request.nonce = 0;

    /* request.padata is filled in later */

    request.kdc_options = context->kdc_default_options;

    /* forwardable */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_FORWARDABLE))
	tempint = options->forwardable;
    else if ((ret = krb5_libdefault_boolean(context, &client->realm,
					    KRB5_CONF_FORWARDABLE, &tempint)) == 0)
	    ;
    else
	tempint = 0;
    if (tempint)
	request.kdc_options |= KDC_OPT_FORWARDABLE;

    /* proxiable */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_PROXIABLE))
	tempint = options->proxiable;
    else if ((ret = krb5_libdefault_boolean(context, &client->realm,
					    KRB5_CONF_PROXIABLE, &tempint)) == 0)
	    ;
    else
	tempint = 0;
    if (tempint)
	request.kdc_options |= KDC_OPT_PROXIABLE;

    /* canonicalize */
    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_CANONICALIZE))
	tempint = 1;
    else if ((ret = krb5_libdefault_boolean(context, &client->realm,
					    KRB5_CONF_CANONICALIZE, &tempint)) == 0)
	;
    else
	tempint = 0;
    if (tempint)
	request.kdc_options |= KDC_OPT_CANONICALIZE;

    /* allow_postdate */
    
    if (start_time > 0)
	request.kdc_options |= (KDC_OPT_ALLOW_POSTDATE|KDC_OPT_POSTDATED);
    
    /* ticket lifetime */
    
    if ((ret = krb5_timeofday(context, &request.from)))
	goto cleanup;
    request.from = krb5int_addint32(request.from, start_time);
    
    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_TKT_LIFE)) {
        tkt_life = options->tkt_life;
    } else if ((ret = krb5_libdefault_string(context, &client->realm,
					     KRB5_CONF_TICKET_LIFETIME, &tempstr))
	       == 0) {
	ret = krb5_string_to_deltat(tempstr, &tkt_life);
	free(tempstr);
	if (ret) {
	    goto cleanup;
	}
    } else {
	/* this used to be hardcoded in kinit.c */
	tkt_life = 24*60*60;
    }
    request.till = krb5int_addint32(request.from, tkt_life);
    
    /* renewable lifetime */
    
    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE)) {
	renew_life = options->renew_life;
    } else if ((ret = krb5_libdefault_string(context, &client->realm,
					     KRB5_CONF_RENEW_LIFETIME, &tempstr))
	       == 0) {
	ret = krb5_string_to_deltat(tempstr, &renew_life);
	free(tempstr);
	if (ret) {
	    goto cleanup;
	}
    } else {
	renew_life = 0;
    }
    if (renew_life > 0)
	request.kdc_options |= KDC_OPT_RENEWABLE;
    
    if (renew_life > 0) {
	request.rtime = krb5int_addint32(request.from, renew_life);
        if (request.rtime < request.till) {
            /* don't ask for a smaller renewable time than the lifetime */
            request.rtime = request.till;
        }
        /* we are already asking for renewable tickets so strip this option */
	request.kdc_options &= ~(KDC_OPT_RENEWABLE_OK);
    } else {
	request.rtime = 0;
    }
    
    /* client */

    request.client = client;

    /* per referrals draft, enterprise principals imply canonicalization */
    canon_flag = ((request.kdc_options & KDC_OPT_CANONICALIZE) != 0) ||
	client->type == KRB5_NT_ENTERPRISE_PRINCIPAL;

    /* service */
    if ((ret = build_in_tkt_name(context, in_tkt_service,
				 request.client, &request.server)))
	goto cleanup;

    krb5_preauth_request_context_init(context);


    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST)) {
	request.ktype = options->etype_list;
	request.nktypes = options->etype_list_length;
    } else if ((ret = krb5_get_default_in_tkt_ktypes(context,
						     &request.ktype)) == 0) {
	for (request.nktypes = 0;
	     request.ktype[request.nktypes];
	     request.nktypes++)
	    ;
    } else {
	/* there isn't any useful default here.  ret is set from above */
	goto cleanup;
    }

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST)) {
	request.addresses = options->address_list;
    }
    /* it would be nice if this parsed out an address list, but
       that would be work. */
    else if (((ret = krb5_libdefault_boolean(context, &client->realm,
					    KRB5_CONF_NOADDRESSES, &tempint)) != 0)
	     || (tempint == 1)) {
	    ;
    } else {
	if ((ret = krb5_os_localaddr(context, &request.addresses)))
	    goto cleanup;
    }

    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /* set up the other state.  */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST)) {
	if ((ret = make_preauth_list(context, options->preauth_list,
				     options->preauth_list_length,
				     &preauth_to_use)))
	    goto cleanup;
    }

    /* the salt is allocated from somewhere, unless it is from the caller,
       then it is a reference */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_SALT)) {
	salt = *options->salt;
    } else {
	salt.length = SALT_TYPE_AFS_LENGTH;
	salt.data = NULL;
    }


    /* set the request nonce */
    if ((ret = krb5_timeofday(context, &time_now)))
	goto cleanup;
    /*
     * XXX we know they are the same size... and we should do
     * something better than just the current time
     */
    {
	unsigned char random_buf[4];
	krb5_data random_data;

	random_data.length = 4;
	random_data.data = (char *)random_buf;
	if (krb5_c_random_make_octets(context, &random_data) == 0)
	    /* See RT ticket 3196 at MIT.  If we set the high bit, we
	       may have compatibility problems with Heimdal, because
	       we (incorrectly) encode this value as signed.  */
	    request.nonce = 0x7fffffff & load_32_n(random_buf);
	else
	    /* XXX  Yuck.  Old version.  */
	    request.nonce = (krb5_int32) time_now;
    }
    ret = krb5int_fast_as_armor(context, fast_state, options, &request);
    if (ret != 0)
	goto cleanup;
    /* give the preauth plugins a chance to prep the request body */
    krb5_preauth_prepare_request(context, options, &request);
    ret = krb5int_fast_prep_req_body(context, fast_state,
				     &request, &encoded_request_body);
    if (ret)
        goto cleanup;

    get_data_rock.magic = CLIENT_ROCK_MAGIC;
    get_data_rock.etype = &etype;
    get_data_rock.fast_state = fast_state;
    
    /* now, loop processing preauth data and talking to the kdc */
    for (loopcount = 0; loopcount < MAX_IN_TKT_LOOPS; loopcount++) {
	if (request.padata) {
	    krb5_free_pa_data(context, request.padata);
	    request.padata = NULL;
	}
	if (!err_reply) {
            /* either our first attempt, or retrying after PREAUTH_NEEDED */
	    if ((ret = krb5_do_preauth(context,
				       &request,
				       encoded_request_body,
				       encoded_previous_request,
				       preauth_to_use, &request.padata,
				       &salt, &s2kparams, &etype, &as_key,
				       prompter, prompter_data,
				       gak_fct, gak_data,
				       &get_data_rock, options)))
	        goto cleanup;
	    if (out_padata) {
	      krb5_free_pa_data(context, out_padata);
	      out_padata = NULL;
	    }
	} else {
	    if (preauth_to_use != NULL) {
		/*
		 * Retry after an error other than PREAUTH_NEEDED,
		 * using e-data to figure out what to change.
		 */
		ret = krb5_do_preauth_tryagain(context,
					       &request,
					       encoded_request_body,
					       encoded_previous_request,
					       preauth_to_use, &request.padata,
					       err_reply,
					       &salt, &s2kparams, &etype,
					       &as_key,
					       prompter, prompter_data,
					       gak_fct, gak_data,
					       &get_data_rock, options);
	    } else {
		/* No preauth supplied, so can't query the plug-ins. */
		ret = KRB5KRB_ERR_GENERIC;
	    }
	    if (ret) {
		/* couldn't come up with anything better */
		ret = err_reply->error + ERROR_TABLE_BASE_krb5;
	    }
	    krb5_free_error(context, err_reply);
	    err_reply = NULL;
	    if (ret)
		goto cleanup;
	}

        if (encoded_previous_request != NULL) {
	    krb5_free_data(context, encoded_previous_request);
	    encoded_previous_request = NULL;
        }
	ret = krb5int_fast_prep_req(context, fast_state,
				    &request, encoded_request_body,
				    encode_krb5_as_req, &encoded_previous_request);
	if (ret)
	    goto cleanup;

	err_reply = 0;
	local_as_reply = 0;
	if ((ret = send_as_request(context, encoded_previous_request,
				   krb5_princ_realm(context, request.client), &err_reply,
				   &local_as_reply, use_master)))
	    goto cleanup;

	if (err_reply) {
	  ret = krb5int_fast_process_error(context, fast_state, &err_reply,
					   &out_padata, &retry);
	  if (ret !=0)
	    goto cleanup;
	  if ((err_reply->error == KDC_ERR_PREAUTH_REQUIRED ||err_reply->error == KDC_ERR_PREAUTH_FAILED)
&& retry) {
		/* reset the list of preauth types to try */
		if (preauth_to_use) {
		    krb5_free_pa_data(context, preauth_to_use);
		    preauth_to_use = NULL;
		}
		preauth_to_use = out_padata;
		out_padata = NULL;
		krb5_free_error(context, err_reply);
		err_reply = NULL;
		ret = sort_krb5_padata_sequence(context,
						&request.server->realm,
						preauth_to_use);
		if (ret)
		    goto cleanup;
		/* continue to next iteration */
	    } else if (canon_flag && err_reply->error == KDC_ERR_WRONG_REALM) {
		if (err_reply->client == NULL ||
		    err_reply->client->realm.length == 0) {
		    ret = KRB5KDC_ERR_WRONG_REALM;
		    krb5_free_error(context, err_reply);
		    goto cleanup;
		}
		/* Rewrite request.client with realm from error reply */
		if (referred_client.realm.data) {
		    krb5_free_data_contents(context, &referred_client.realm);
		    referred_client.realm.data = NULL;
		}
		ret = krb5int_copy_data_contents(context,
						 &err_reply->client->realm,
						 &referred_client.realm);
		krb5_free_error(context, err_reply);
		err_reply = NULL;
		if (ret)
		    goto cleanup;
		request.client = &referred_client;

		krb5_free_principal(context, request.server);
		request.server = NULL;

		ret = build_in_tkt_name(context, in_tkt_service,
					request.client, &request.server);
		if (ret)
		    goto cleanup;
	    } else {
		if (retry)  {
		    /* continue to next iteration */
		} else {
		    /* error + no hints = give up */
		    ret = (krb5_error_code) err_reply->error
		          + ERROR_TABLE_BASE_krb5;
		    krb5_free_error(context, err_reply);
		    goto cleanup;
		}
	    }
	} else if (local_as_reply) {
	    break;
	} else {
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto cleanup;
	}
    }

#if APPLE_PKINIT
    inTktDebug("krb5_get_init_creds done with send_as_request loop lc %d\n",
	(int)loopcount);
#endif /* APPLE_PKINIT */
    if (loopcount == MAX_IN_TKT_LOOPS) {
	ret = KRB5_GET_IN_TKT_LOOP;
	goto cleanup;
    }

    /* process any preauth data in the as_reply */
    krb5_clear_preauth_context_use_counts(context);
    ret = krb5int_fast_process_response(context, fast_state,
				       local_as_reply, &strengthen_key);
    if (ret)
	goto cleanup;
    if ((ret = sort_krb5_padata_sequence(context, &request.server->realm,
					 local_as_reply->padata)))
	goto cleanup;
    etype = local_as_reply->enc_part.enctype;
    if ((ret = krb5_do_preauth(context,
			       &request,
			       encoded_request_body, encoded_previous_request,
			       local_as_reply->padata, &kdc_padata,
			       &salt, &s2kparams, &etype, &as_key, prompter,
			       prompter_data, gak_fct, gak_data,
			       &get_data_rock, options))) {
#if APPLE_PKINIT
        inTktDebug("krb5_get_init_creds krb5_do_preauth returned %d\n", (int)ret);
#endif /* APPLE_PKINIT */
	goto cleanup;
	}

    /*
     * If we haven't gotten a salt from another source yet, set up one
     * corresponding to the client principal returned by the KDC.  We
     * could get the same effect by passing local_as_reply->client to
     * gak_fct below, but that would put the canonicalized client name
     * in the prompt, which raises issues of needing to sanitize
     * unprintable characters.  So for now we just let it affect the
     * salt.  local_as_reply->client will be checked later on in
     * verify_as_reply.
     */
    if (salt.length == SALT_TYPE_AFS_LENGTH && salt.data == NULL) {
	ret = krb5_principal2salt(context, local_as_reply->client, &salt);
	if (ret)
	    goto cleanup;
    }

    /* XXX For 1.1.1 and prior KDC's, when SAM is used w/ USE_SAD_AS_KEY,
       the AS_REP comes back encrypted in the user's longterm key
       instead of in the SAD. If there was a SAM preauth, there
       will be an as_key here which will be the SAD. If that fails,
       use the gak_fct to get the password, and try again. */
      
    /* XXX because etypes are handled poorly (particularly wrt SAM,
       where the etype is fixed by the kdc), we may want to try
       decrypt_as_reply twice.  If there's an as_key available, try
       it.  If decrypting the as_rep fails, or if there isn't an
       as_key at all yet, then use the gak_fct to get one, and try
       again.  */
    if (as_key.length) {
      ret = krb5int_fast_reply_key(context, strengthen_key, &as_key,
				   &encrypting_key);
      if (ret)
	goto cleanup;
      	ret = decrypt_as_reply(context, NULL, local_as_reply, NULL,
			       NULL, &encrypting_key, krb5_kdc_rep_decrypt_proc,
			       NULL);
    } else
	ret = -1;
	   
    if (ret) {
	/* if we haven't get gotten a key, get it now */

	if ((ret = ((*gak_fct)(context, request.client,
			       local_as_reply->enc_part.enctype,
			       prompter, prompter_data, &salt, &s2kparams,
			       &as_key, gak_data))))
	    goto cleanup;

	ret = krb5int_fast_reply_key(context, strengthen_key, &as_key,
				     &encrypting_key);
	if (ret)
	  goto cleanup;
	if ((ret = decrypt_as_reply(context, NULL, local_as_reply, NULL,
				    NULL, &encrypting_key, krb5_kdc_rep_decrypt_proc,
				    NULL)))
	    goto cleanup;
    }

    if ((ret = verify_as_reply(context, time_now, &request, local_as_reply)))
	goto cleanup;

    /* XXX this should be inside stash_as_reply, but as long as
       get_in_tkt is still around using that arg as an in/out, I can't
       do that */
    memset(creds, 0, sizeof(*creds));

    if ((ret = stash_as_reply(context, time_now, &request, local_as_reply,
			      creds, NULL)))
	goto cleanup;

    /* success */

    ret = 0;

cleanup:
    if (ret != 0) {
	char *client_name;
	/* See if we can produce a more detailed error message.  */
	switch (ret) {
	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	    client_name = NULL;
	    if (krb5_unparse_name(context, client, &client_name) == 0) {
		krb5_set_error_message(context, ret,
				       "Client '%s' not found in Kerberos database",
				       client_name);
		free(client_name);
	    }
	    break;
	default:
	    break;
	}
    }
    krb5_preauth_request_context_fini(context);
	krb5_free_keyblock(context, strengthen_key);
	if (encrypting_key.contents)
	  krb5_free_keyblock_contents(context, &encrypting_key);
	    if (fast_state)
	krb5int_fast_free_state(context, fast_state);
    if (out_padata)
	krb5_free_pa_data(context, out_padata);
    if (encoded_previous_request != NULL) {
	krb5_free_data(context, encoded_previous_request);
	encoded_previous_request = NULL;
    }
    if (encoded_request_body != NULL) {
	krb5_free_data(context, encoded_request_body);
	encoded_request_body = NULL;
    }
    if (request.server)
	krb5_free_principal(context, request.server);
    if (request.ktype &&
	(!(options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST))))
	free(request.ktype);
    if (request.addresses &&
	(!(options &&
	   (options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST))))
	krb5_free_addresses(context, request.addresses);
    if (preauth_to_use)
	krb5_free_pa_data(context, preauth_to_use);
    if (kdc_padata)
	krb5_free_pa_data(context, kdc_padata);
    if (request.padata)
	krb5_free_pa_data(context, request.padata);
    if (as_key.length)
	krb5_free_keyblock_contents(context, &as_key);
    if (salt.data &&
	(!(options && (options->flags & KRB5_GET_INIT_CREDS_OPT_SALT))))
	free(salt.data);
    krb5_free_data_contents(context, &s2kparams);
    if (as_reply)
	*as_reply = local_as_reply;
    else if (local_as_reply)
	krb5_free_kdc_rep(context, local_as_reply);
    if (referred_client.realm.data)
	krb5_free_data_contents(context, &referred_client.realm);

    return(ret);
}
