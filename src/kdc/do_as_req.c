/*
 * kdc/do_as_req.c
 *
 * Portions Copyright (C) 2007 Apple Inc.
 * Copyright 1990,1991,2007,2008,2009 by the Massachusetts Institute of Technology.
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
 * KDC Routines to deal with AS_REQ's
 */
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "com_err.h"

#include <syslog.h>
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif	/* hpux */
#endif /* HAVE_NETINET_IN_H */

#include "kdc_util.h"
#include "policy.h"
#include "adm.h"
#include "adm_proto.h"
#include "extern.h"

#if APPLE_PKINIT
#define     AS_REQ_DEBUG    0
#if	    AS_REQ_DEBUG
#define     asReqDebug(args...)       printf(args)
#else
#define     asReqDebug(args...)
#endif
#endif /* APPLE_PKINIT */

static krb5_error_code prepare_error_as (struct kdc_request_state *, krb5_kdc_req *, int, krb5_data *, 
					 krb5_principal, krb5_data **,
					 const char *);

/*ARGSUSED*/
krb5_error_code
process_as_req(krb5_kdc_req *request, krb5_data *req_pkt,
	       const krb5_fulladdr *from, krb5_data **response)
{
    krb5_db_entry client, server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_error_code errcode;
    int c_nprincs = 0, s_nprincs = 0;
    krb5_boolean more;
    krb5_timestamp kdc_time, authtime = 0;
    krb5_keyblock session_key;
    const char *status;
    krb5_key_data *server_key, *client_key;
    krb5_keyblock server_keyblock, client_keyblock;
    krb5_keyblock *mkey_ptr;
    krb5_enctype useenctype;
    krb5_boolean update_client = 0;
    krb5_data e_data;
    register int i;
    krb5_timestamp until, rtime;
    char *cname = 0, *sname = 0;
    unsigned int c_flags = 0, s_flags = 0;
    krb5_principal_data client_princ;
    void *pa_context = NULL;
    int did_log = 0;
    const char *emsg = 0;
    krb5_keylist_node *tmp_mkey_list;
    struct kdc_request_state *state = NULL;
    krb5_data encoded_req_body;
    krb5_keyblock *as_encrypting_key = NULL;
    

#if APPLE_PKINIT
    asReqDebug("process_as_req top realm %s name %s\n", 
	request->client->realm.data, request->client->data->data);
#endif /* APPLE_PKINIT */

    ticket_reply.enc_part.ciphertext.data = 0;
    e_data.data = 0;
    server_keyblock.contents = NULL;
    client_keyblock.contents = NULL;
    reply.padata = 0;
    memset(&reply, 0, sizeof(reply));

    session_key.contents = 0;
    enc_tkt_reply.authorization_data = NULL;

    if (request->msg_type != KRB5_AS_REQ) {
        status = "msg_type mismatch";
        errcode = KRB5_BADMSGTYPE;
        goto errout;
    }
    errcode = kdc_make_rstate(&state);
    if (errcode != 0) {
	status = "constructing state";
	goto errout;
    }
    if (fetch_asn1_field((unsigned char *) req_pkt->data,
			 1, 4, &encoded_req_body) != 0) {
        errcode = ASN1_BAD_ID;
        status = "Finding req_body";
	goto errout;
    }
    errcode = kdc_find_fast(&request, &encoded_req_body, NULL /*TGS key*/, NULL, state);
    if (errcode) {
	status = "error decoding FAST";
	goto errout;
    }
    request->kdc_state = state;
    if (!request->client) {
	status = "NULL_CLIENT";
	errcode = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	goto errout;
    }
    if ((errcode = krb5_unparse_name(kdc_context, request->client, &cname))) {
	status = "UNPARSING_CLIENT";
	goto errout;
    }
    limit_string(cname);
    if (!request->server) {
	status = "NULL_SERVER";
	errcode = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto errout;
    }
    if ((errcode = krb5_unparse_name(kdc_context, request->server, &sname))) {
	status = "UNPARSING_SERVER";
	goto errout;
    }
    limit_string(sname);
    
    /*
     * We set KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY as a hint
     * to the backend to return naming information in lieu
     * of cross realm TGS entries.
     */
    setflag(c_flags, KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY);
    /*
     * Note that according to the referrals draft we should
     * always canonicalize enterprise principal names.
     */
    if (isflagset(request->kdc_options, KDC_OPT_CANONICALIZE) ||
	krb5_princ_type(kdc_context,
			request->client) == KRB5_NT_ENTERPRISE_PRINCIPAL) {
	setflag(c_flags, KRB5_KDB_FLAG_CANONICALIZE); 
    }
    if (include_pac_p(kdc_context, request)) {
	setflag(c_flags, KRB5_KDB_FLAG_INCLUDE_PAC); 
    }
    c_nprincs = 1;
    if ((errcode = krb5_db_get_principal_ext(kdc_context, request->client,
					     c_flags, &client, &c_nprincs,
					     &more))) {
	status = "LOOKING_UP_CLIENT";
	c_nprincs = 0;
	goto errout;
    }

    if (more) {
	status = "NON-UNIQUE_CLIENT";
	errcode = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
	goto errout;
    } else if (c_nprincs != 1) {
	status = "CLIENT_NOT_FOUND";
#ifdef KRBCONF_VAGUE_ERRORS
	errcode = KRB5KRB_ERR_GENERIC;
#else
	errcode = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
#endif
	goto errout;
    }
   
    /*
     * If the backend returned a principal that is not in the local
     * realm, then we need to refer the client to that realm.
     */
    if (!is_local_principal(client.princ)) {
 	/* Entry is a referral to another realm */
 	status = "REFERRAL";
 	errcode = KRB5KDC_ERR_WRONG_REALM;
 	goto errout;
    }

#if 0 
    /*
     * Turn off canonicalization if client is marked DES only
     * (unless enterprise principal name was requested)
     */
    if (isflagset(client.attributes, KRB5_KDB_NON_MS_PRINCIPAL) &&
 	krb5_princ_type(kdc_context,
 			request->client) != KRB5_NT_ENTERPRISE_PRINCIPAL) {
 	clear(c_flags, KRB5_KDB_FLAG_CANONICALIZE);
    }
#endif
 
    s_flags = 0;
    if (isflagset(request->kdc_options, KDC_OPT_CANONICALIZE)) {
 	setflag(s_flags, KRB5_KDB_FLAG_CANONICALIZE); 
    }
    s_nprincs = 1;
    if ((errcode = krb5_db_get_principal_ext(kdc_context, request->server,
 					     s_flags, &server,
 					     &s_nprincs, &more))) {
 	status = "LOOKING_UP_SERVER";
 	goto errout;
    }
    if (more) {
	status = "NON-UNIQUE_SERVER";
	errcode = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
	goto errout;
    } else if (s_nprincs != 1) {
	status = "SERVER_NOT_FOUND";
	errcode = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto errout;
    }

    if ((errcode = krb5_timeofday(kdc_context, &kdc_time))) {
	status = "TIMEOFDAY";
	goto errout;
    }
    authtime = kdc_time; /* for audit_as_request() */

    if ((errcode = validate_as_request(request, client, server,
				       kdc_time, &status))) {
	if (!status) 
	    status = "UNKNOWN_REASON";
	errcode += ERROR_TABLE_BASE_krb5;
	goto errout;
    }
      
    /*
     * Select the keytype for the ticket session key.
     */
    if ((useenctype = select_session_keytype(kdc_context, &server,
					     request->nktypes,
					     request->ktype)) == 0) {
	/* unsupported ktype */
	status = "BAD_ENCRYPTION_TYPE";
	errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
	goto errout;
    }

    if ((errcode = krb5_c_make_random_key(kdc_context, useenctype,
					  &session_key))) {
	status = "RANDOM_KEY_FAILED";
	goto errout;
    }

    /*
     * Canonicalization is only effective if we are issuing a TGT
     * (the intention is to allow support for Windows "short" realm
     * aliases, nothing more).
     */
    if (isflagset(s_flags, KRB5_KDB_FLAG_CANONICALIZE) &&
	krb5_is_tgs_principal(request->server) &&
	krb5_is_tgs_principal(server.princ)) {
	ticket_reply.server = server.princ;
    } else {
	ticket_reply.server = request->server;
    }

    enc_tkt_reply.flags = 0;
    enc_tkt_reply.times.authtime = authtime;

    setflag(enc_tkt_reply.flags, TKT_FLG_INITIAL);

    	/* It should be noted that local policy may affect the  */
        /* processing of any of these flags.  For example, some */
        /* realms may refuse to issue renewable tickets         */

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE))
	    setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	    setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    enc_tkt_reply.session = &session_key;
    if (isflagset(c_flags, KRB5_KDB_FLAG_CANONICALIZE)) {
	client_princ = *(client.princ);
    } else {
	client_princ = *(request->client);
	/* The realm is always canonicalized */
	client_princ.realm = *(krb5_princ_realm(context, client.princ));
    }
    enc_tkt_reply.client = &client_princ;
    enc_tkt_reply.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply.transited.tr_contents = empty_string; /* equivalent of "" */

    if (isflagset(request->kdc_options, KDC_OPT_POSTDATED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_POSTDATED);
	setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;
    
    until = (request->till == 0) ? kdc_infinity : request->till;

    enc_tkt_reply.times.endtime =
	min(until,
	    min(enc_tkt_reply.times.starttime + client.max_life,
		min(enc_tkt_reply.times.starttime + server.max_life,
		    enc_tkt_reply.times.starttime + max_life_for_realm)));

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE_OK) &&
	!isflagset(client.attributes, KRB5_KDB_DISALLOW_RENEWABLE) &&
	(enc_tkt_reply.times.endtime < request->till)) {

	/* we set the RENEWABLE option for later processing */

	setflag(request->kdc_options, KDC_OPT_RENEWABLE);
	request->rtime = request->till;
    }
    rtime = (request->rtime == 0) ? kdc_infinity : request->rtime;

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	/*
	 * XXX Should we squelch the output renew_till to be no
	 * earlier than the endtime of the ticket? 
	 */
	setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	enc_tkt_reply.times.renew_till =
	    min(rtime, enc_tkt_reply.times.starttime +
		       min(client.max_renewable_life,
			   min(server.max_renewable_life,
			       max_renewable_life_for_realm)));
    } else
	enc_tkt_reply.times.renew_till = 0; /* XXX */

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    enc_tkt_reply.caddrs = request->addresses;
    enc_tkt_reply.authorization_data = 0;

    /* 
     * Check the preauthentication if it is there.
     */
    if (request->padata) {
	errcode = check_padata(kdc_context, &client, req_pkt, request,
			       &enc_tkt_reply, &pa_context, &e_data);
	if (errcode) {
	    if (errcode == KRB5KDC_ERR_PREAUTH_FAILED)
		get_preauth_hint_list(request, &client, &server, &e_data);
	    
	    if (kdc_modifies_kdb) {
		/*
		 * Note: this doesn't work if you're using slave servers!!!
		 * It also causes the database to be modified (and thus
		 * need to be locked) frequently.
		 */
		if (client.fail_auth_count < KRB5_MAX_FAIL_COUNT) {
		    client.fail_auth_count = client.fail_auth_count + 1;
		    if (client.fail_auth_count == KRB5_MAX_FAIL_COUNT) {
			client.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
		    }
		}
		client.last_failed = kdc_time;
	    }
	    update_client = 1;
	    status = "PREAUTH_FAILED";
#ifdef KRBCONF_VAGUE_ERRORS
	    errcode = KRB5KRB_ERR_GENERIC;
#endif
	    goto errout;
	} 
    }

    /*
     * Final check before handing out ticket: If the client requires
     * preauthentication, verify that the proper kind of
     * preauthentication was carried out.
     */
    status = missing_required_preauth(&client, &server, &enc_tkt_reply);
    if (status) {
	errcode = KRB5KDC_ERR_PREAUTH_REQUIRED;
	get_preauth_hint_list(request, &client, &server, &e_data);
	goto errout;
    }

    if ((errcode = validate_forwardable(request, client, server,
					kdc_time, &status))) {
	errcode += ERROR_TABLE_BASE_krb5;
	goto errout;
    }

    ticket_reply.enc_part2 = &enc_tkt_reply;

    /*
     * Find the server key
     */
    if ((errcode = krb5_dbe_find_enctype(kdc_context, &server,
					 -1, /* ignore keytype */
					 -1,		/* Ignore salttype */
					 0,		/* Get highest kvno */
					 &server_key))) {
	status = "FINDING_SERVER_KEY";
	goto errout;
    }

    if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist, &server,
                                      &mkey_ptr))) {
        /* try refreshing master key list */
        /* XXX it would nice if we had the mkvno here for optimization */
        if (krb5_db_fetch_mkey_list(kdc_context, master_princ,
                                    &master_keyblock, 0, &tmp_mkey_list) == 0) {
            krb5_dbe_free_key_list(kdc_context, master_keylist);
            master_keylist = tmp_mkey_list;
            if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist,
                                              &server, &mkey_ptr))) {
                status = "FINDING_MASTER_KEY";
                goto errout;
            }
        } else {
            status = "FINDING_MASTER_KEY";
            goto errout;
        }
    }

    /* convert server.key into a real key (it may be encrypted
       in the database) */
    if ((errcode = krb5_dbekd_decrypt_key_data(kdc_context, mkey_ptr, 
    /* server_keyblock is later used to generate auth data signatures */
					       server_key, &server_keyblock,
					       NULL))) {
	status = "DECRYPT_SERVER_KEY";
	goto errout;
    }
	
    /*
     * Find the appropriate client key.  We search in the order specified
     * by request keytype list.
     */
    client_key = (krb5_key_data *) NULL;
    for (i = 0; i < request->nktypes; i++) {
	useenctype = request->ktype[i];
	if (!krb5_c_valid_enctype(useenctype))
	    continue;

	if (!krb5_dbe_find_enctype(kdc_context, &client, useenctype, -1,
				   0, &client_key))
	    break;
    }
    if (!(client_key)) {
	/* Cannot find an appropriate key */
	status = "CANT_FIND_CLIENT_KEY";
	errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
	goto errout;
    }

    if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist, &client,
                                      &mkey_ptr))) {
        /* try refreshing master key list */
        /* XXX it would nice if we had the mkvno here for optimization */
        if (krb5_db_fetch_mkey_list(kdc_context, master_princ,
                                    &master_keyblock, 0, &tmp_mkey_list) == 0) {
            krb5_dbe_free_key_list(kdc_context, master_keylist);
            master_keylist = tmp_mkey_list;
            if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist,
                                              &client, &mkey_ptr))) {
                status = "FINDING_MASTER_KEY";
                goto errout;
            }
        } else {
            status = "FINDING_MASTER_KEY";
            goto errout;
        }
    }

    /* convert client.key_data into a real key */
    if ((errcode = krb5_dbekd_decrypt_key_data(kdc_context, mkey_ptr, 
					       client_key, &client_keyblock,
					       NULL))) {
	status = "DECRYPT_CLIENT_KEY";
	goto errout;
    }
    client_keyblock.enctype = useenctype;

    /* Start assembling the response */
    reply.msg_type = KRB5_AS_REP;
    reply.client = enc_tkt_reply.client; /* post canonicalization */
    reply.ticket = &ticket_reply;
    reply_encpart.session = &session_key;
    if ((errcode = fetch_last_req_info(&client, &reply_encpart.last_req))) {
	status = "FETCH_LAST_REQ";
	goto errout;
    }
    reply_encpart.nonce = request->nonce;
    reply_encpart.key_exp = client.expiration;
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* copy the time fields EXCEPT for authtime; it's location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = authtime = kdc_time;

    reply_encpart.caddrs = enc_tkt_reply.caddrs;
    reply_encpart.enc_padata = NULL;

    /* Fetch the padata info to be returned (do this before
       authdata to handle possible replacement of reply key */
    errcode = return_padata(kdc_context, &client, req_pkt, request,
			    &reply, client_key, &client_keyblock, &pa_context);
    if (errcode) {
	status = "KDC_RETURN_PADATA";
	goto errout;
    }

#if APPLE_PKINIT
    asReqDebug("process_as_req reply realm %s name %s\n", 
	reply.client->realm.data, reply.client->data->data);
#endif /* APPLE_PKINIT */

    errcode = return_svr_referral_data(kdc_context,
				       &server, &reply_encpart);
    if (errcode) {
	status = "KDC_RETURN_ENC_PADATA";
	goto errout;
    }

    
    errcode = handle_authdata(kdc_context,
			      c_flags,
			      &client,
			      &server,
			      &server,
			      &client_keyblock,
			      &server_keyblock,
			      req_pkt,
			      request,
			      NULL, /* for_user_princ */
			      NULL, /* enc_tkt_request */
			      &enc_tkt_reply);
    if (errcode) {
	krb5_klog_syslog(LOG_INFO, "AS_REQ : handle_authdata (%d)", errcode);
	status = "HANDLE_AUTHDATA";
	goto errout;
    }

    errcode = krb5_encrypt_tkt_part(kdc_context, &server_keyblock, &ticket_reply);
    if (errcode) {
	status = "ENCRYPTING_TICKET";
	goto errout;
    }
    ticket_reply.enc_part.kvno = server_key->key_data_kvno;
    errcode = kdc_fast_response_handle_padata(state, request, &reply, client_keyblock.enctype);
    if (errcode) {
	status = "fast response handling";
	goto errout;
    }

    /* now encode/encrypt the response */

    reply.enc_part.enctype = client_keyblock.enctype;

    errcode = kdc_fast_handle_reply_key(state, &client_keyblock, &as_encrypting_key);
    if (errcode) {
	status = "generating reply key";
	goto errout;
    }
        errcode = krb5_encode_kdc_rep(kdc_context, KRB5_AS_REP, &reply_encpart, 
				  0, as_encrypting_key,  &reply, response);
    reply.enc_part.kvno = client_key->key_data_kvno;
    if (errcode) {
	status = "ENCODE_KDC_REP";
	goto errout;
    }
    
    /* these parts are left on as a courtesy from krb5_encode_kdc_rep so we
       can use them in raw form if needed.  But, we don't... */
    memset(reply.enc_part.ciphertext.data, 0, reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data);

    if (kdc_modifies_kdb) {
	/*
	 * If we get this far, we successfully did the AS_REQ.
	 */
	client.last_success = kdc_time;
	client.fail_auth_count = 0;
    }
    update_client = 1;

    log_as_req(from, request, &reply, &client, cname, &server, sname,
	       authtime, 0, 0, 0);
    did_log = 1;

    goto egress;

errout:
    assert (status != 0);
    /* fall through */

egress:
    if (pa_context)
	free_padata_context(kdc_context, &pa_context);
    if (as_encrypting_key)
	krb5_free_keyblock(kdc_context, as_encrypting_key);
    if (errcode)
	emsg = krb5_get_error_message(kdc_context, errcode);

    if (status) {
	log_as_req(from, request, &reply, &client, cname, &server, sname, 0,
		   status, errcode, emsg);
	did_log = 1;
    }
    if (errcode) {
	if (status == 0) {
	    status = emsg;
	}
	errcode -= ERROR_TABLE_BASE_krb5;
	if (errcode < 0 || errcode > 128)
	    errcode = KRB_ERR_GENERIC;
	    
	errcode = prepare_error_as(state, request, errcode, &e_data,
 				   c_nprincs ? client.princ : NULL,
				   response, status);
	status = 0;
    }
    if (emsg)
	krb5_free_error_message(kdc_context, emsg);

    if (enc_tkt_reply.authorization_data != NULL)
	krb5_free_authdata(kdc_context, enc_tkt_reply.authorization_data);
    if (server_keyblock.contents != NULL)
 	krb5_free_keyblock_contents(kdc_context, &server_keyblock);
    if (client_keyblock.contents != NULL)
	krb5_free_keyblock_contents(kdc_context, &client_keyblock);
    if (reply.padata != NULL)
	krb5_free_pa_data(kdc_context, reply.padata);

    if (cname != NULL)
	    free(cname);
    if (sname != NULL)
	    free(sname);
    if (c_nprincs) {
	if (kdc_modifies_kdb) {
	    if (update_client) {
		krb5_error_code errcode2;

		krb5_db_put_principal(kdc_context, &client, &c_nprincs);
		/*
		 * ptooey.  We want krb5_db_sync() or something like that.
		 */
		errcode2 = krb5_db_fini(kdc_context);
		if (errcode2 == 0)
		    errcode2 = krb5_db_open(kdc_context, db_args,
					    KRB5_KDB_OPEN_RW|KRB5_KDB_SRV_TYPE_KDC);
		/* Reset master key */
		krb5_db_set_mkey(kdc_context, &kdc_active_realm->realm_mkey);
	    }
	}
	krb5_db_free_principal(kdc_context, &client, c_nprincs);
    }
    if (s_nprincs)
	krb5_db_free_principal(kdc_context, &server, s_nprincs);
    if (session_key.contents != NULL)
	krb5_free_keyblock_contents(kdc_context, &session_key);
    if (ticket_reply.enc_part.ciphertext.data != NULL) {
	memset(ticket_reply.enc_part.ciphertext.data , 0,
	       ticket_reply.enc_part.ciphertext.length);
	free(ticket_reply.enc_part.ciphertext.data);
    }

    krb5_free_data_contents(kdc_context, &e_data);
    kdc_free_rstate(state);
    request->kdc_state = NULL;
    krb5_free_kdc_req(kdc_context, request);
    assert(did_log != 0);
    return errcode;
}

static krb5_error_code
prepare_error_as (struct kdc_request_state *rstate, krb5_kdc_req *request, int error, krb5_data *e_data,
		  krb5_principal canon_client, krb5_data **response,
		  const char *status)
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;
    krb5_pa_data **pa = NULL;
    krb5_typed_data **td = NULL;
    size_t size;
    
    errpkt.ctime = request->nonce;
    errpkt.cusec = 0;

    if ((retval = krb5_us_timeofday(kdc_context, &errpkt.stime,
				    &errpkt.susec)))
	return(retval);
    errpkt.error = error;
    errpkt.server = request->server;

    if (error == KRB5KDC_ERR_WRONG_REALM)
	errpkt.client = canon_client;
    else
	errpkt.client = request->client;
    errpkt.text.length = strlen(status) + 1;
    if (!(errpkt.text.data = strdup(status)))
	return ENOMEM;

    if (!(scratch = (krb5_data *)malloc(sizeof(*scratch)))) {
	free(errpkt.text.data);
	return ENOMEM;
    }
    if (e_data  != NULL&& e_data->data != NULL) {
	errpkt.e_data = *e_data;
    } else {
	errpkt.e_data.length = 0;
	errpkt.e_data.data = NULL;
    }
    /*We need to try and produce a padata sequence for FAST*/
    retval = decode_krb5_padata_sequence(e_data, &pa);
    if (retval != 0) {
	retval = decode_krb5_typed_data(e_data, &td);
	if (retval == 0) {
	    for (size =0; td[size]; size++);
	    pa = calloc(size+1, sizeof(*pa));
	    if (pa == NULL)
		retval = ENOMEM;
	    else 		for (size = 0; td[size]; size++) {
		krb5_pa_data *pad = malloc(sizeof(krb5_pa_data ));
		if (pad == NULL) {
		    retval = ENOMEM;
		    break;
		}
		pad->pa_type = td[size]->type;
		pad->contents = td[size]->data;
		pad->length = td[size]->length;
		pa[size] = pad;
                    td[size]->data = NULL;
                    td[size]->length = 0;
	    }
	    krb5_free_typed_data(kdc_context, td);
	}
    }
    retval = kdc_fast_handle_error(kdc_context, rstate,
				   request, pa, &errpkt);
    if (retval == 0)
    retval = krb5_mk_error(kdc_context, &errpkt, scratch);
    free(errpkt.text.data);
    if (retval)
	free(scratch);
    else 
	*response = scratch;
    krb5_free_pa_data(kdc_context, pa);
    return retval;
}
