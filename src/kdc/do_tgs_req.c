/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * KDC Routines to deal with TGS_REQ's
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_do_tgs_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>
#include <krb5/ext-proto.h>
#include <com_err.h>

#include <syslog.h>
#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
#endif

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"


static void find_alternate_tgs PROTOTYPE((krb5_kdc_req *,
					  krb5_db_entry *,
					  krb5_boolean *,
					  int *));

static krb5_error_code prepare_error_tgs PROTOTYPE((krb5_kdc_req *,
						    krb5_ticket *,
						    int,
						    const char *,
						    krb5_data **));
/*ARGSUSED*/
krb5_error_code
process_tgs_req(request, pkt, from, is_secondary, response)
krb5_kdc_req *request;
krb5_data *pkt;
const krb5_fulladdr *from;		/* who sent it ? */
int	is_secondary;
krb5_data **response;			/* filled in with a response packet */
{

    krb5_db_entry server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply, *header_ticket;
    krb5_tkt_authent *req_authdat;
    int st_idx = 0;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_transited enc_tkt_transited;
    int newtransited = 0;
    krb5_error_code retval;
    int nprincs;
    krb5_boolean more;
    krb5_timestamp kdc_time, authtime;
    krb5_keyblock *session_key;
    krb5_timestamp until, rtime;
    krb5_keyblock encrypting_key;
    char *cname = 0, *sname = 0, *fromstring = 0;
    krb5_last_req_entry *nolrarray[2], nolrentry;
/*    krb5_address *noaddrarray[1]; */
    krb5_enctype useetype;
    int	errcode;
    register int i;
    int firstpass = 1;
    char	*status;

#ifdef KRB5_USE_INET
    if (from->address->addrtype == ADDRTYPE_INET)
	fromstring =
	    (char *) inet_ntoa(*(struct in_addr *)from->address->contents);
#endif
    if (!fromstring)
	fromstring = "<unknown>";

    header_ticket = 0;
    req_authdat = 0;
    retval = kdc_process_tgs_req(request, from, pkt, &req_authdat);
    if (req_authdat)
	header_ticket = req_authdat->ticket;
    if (retval) {
	if (header_ticket && !header_ticket->enc_part2) {
	    krb5_free_tkt_authent(req_authdat);
	    header_ticket = 0;
	}
	errcode = retval - ERROR_TABLE_BASE_krb5;
	if (errcode < 0 || errcode > 128) {
	    errcode = KRB_ERR_GENERIC;
	    prepare_error_tgs(request, header_ticket, errcode,
				     fromstring, response);
	    return retval;
	} else {
	    /* protocol error */
	    return(prepare_error_tgs(request, header_ticket, errcode,
				     fromstring, response));
	}
    }
	
    /* we've already dealt with the AP_REQ authentication, so
       we can use header_ticket freely.
       The encrypted part (if any) has been decrypted with the session key.
       */

    if (retval = krb5_unparse_name(header_ticket->enc_part2->client, &cname)) {
	krb5_free_tkt_authent(req_authdat);
	return(retval);
    }
    if (retval = krb5_unparse_name(request->server, &sname)) {
	free(cname);
	krb5_free_tkt_authent(req_authdat);
	return(retval);
    }
    authtime = header_ticket->enc_part2->times.authtime;

    /* XXX make sure server here has the proper realm...taken from AP_REQ
       header? */

    nprincs = 1;
    if (retval = krb5_db_get_principal(request->server, &server, &nprincs,
				       &more)) {
        syslog(LOG_INFO,
	       "TGS_REQ: GET_PRINCIPAL: authtime %d, host %s, %s for %s (%s)",
	       authtime, fromstring, cname, sname, error_message(retval));
	free(cname);
	free(sname);
	krb5_free_tkt_authent(req_authdat);
	return(retval);
    }
tgt_again:
    if (more) {
        syslog(LOG_INFO,
	       "TGS_REQ: NON_UNIQUE_PRINCIPAL: authtime %d, host %s, %s for %s",
	       authtime, fromstring, cname, sname);
	krb5_db_free_principal(&server, nprincs);
	free(cname);
	free(sname);
	return(prepare_error_tgs(request,
				 header_ticket,
				 KDC_ERR_PRINCIPAL_NOT_UNIQUE,
				 fromstring,
				 response));
    } else if (nprincs != 1) {
	/* XXX Is it possible for a principal to have length 1 so that
	   the following statement is undefined?  Only length 3 is valid
	   here, but can a length 1 ticket pass through all prior tests?  */

	krb5_data *server_1 = krb5_princ_component(request->server, 1);
	krb5_data *tgs_1 = krb5_princ_component(tgs_server, 1);

	/* might be a request for a TGT for some other realm; we should
	   do our best to find such a TGS in this db */
	if (firstpass && krb5_princ_size(request->server) == 3 &&
	    server_1->length == tgs_1->length &&
	    !memcmp(server_1->data, tgs_1->data, tgs_1->length)) {
	    krb5_db_free_principal(&server, nprincs);
	    find_alternate_tgs(request, &server, &more, &nprincs);
	    firstpass = 0;
	    goto tgt_again;
	}
	krb5_db_free_principal(&server, nprincs);
        syslog(LOG_INFO,
	       "TGS_REQ: UNKNOWN PRINCIPAL: authtime %d, host %s, %s for %s",
	       authtime, fromstring, cname, sname);
	return(prepare_error_tgs(request,
				 header_ticket,
				 KDC_ERR_S_PRINCIPAL_UNKNOWN,
				 fromstring,
				 response));
    }

#define tkt_cleanup() {krb5_free_tkt_authent(req_authdat); }
#define cleanup() { krb5_db_free_principal(&server, 1); free(cname); free(sname); }

    status = "UNKNOWN_REASON";
    if (retval = validate_tgs_request(request, server, header_ticket,
				      kdc_time, &status)) {
	syslog(LOG_INFO, "TGS_REQ: %s: authtime %d, host %s, %s for %s",
	       status, authtime, fromstring, cname, sname);
	cleanup();
	return(prepare_error_tgs(request,
				 header_ticket,
				 retval,
				 fromstring,
				 response));
    }

    if (retval = krb5_timeofday(&kdc_time)) {
	syslog(LOG_INFO, "TGS_REQ: TIME_OF_DAY: authtime %d, host %s, %s for %s", 
                  authtime, fromstring, cname, sname);
	tkt_cleanup();
	cleanup();
	return(retval);
    }
    
    for (i = 0; i < request->netypes; i++)
	if (valid_etype(request->etype[i]))
	    break;
    if (i == request->netypes) {
	/* unsupported etype */

	syslog(LOG_INFO, "TGS_REQ: BAD ENCRYPTION TYPE: authtime %d, host %s, %s for %s",
                  authtime, cname, sname);
	cleanup();
	return(prepare_error_tgs(request,
				 header_ticket,
				 KDC_ERR_ETYPE_NOSUPP,
				 fromstring, response));
    }
    useetype = request->etype[i];

    if (retval = (*(krb5_csarray[useetype]->system->random_key))(krb5_csarray[useetype]->random_sequence, &session_key)) {
	/* random key failed */
	syslog(LOG_INFO, "TGS_REQ: RANDOM KEY FAILED: authtime %d, host %s, %s for %s",
                  authtime, fromstring, cname, sname);
	tkt_cleanup();
	cleanup();
	return(retval);
    }

#undef cleanup
#define cleanup() { krb5_db_free_principal(&server, 1); \
		    krb5_free_keyblock(session_key); \
		    free(cname); free(sname); }
    
    ticket_reply.server = request->server; /* XXX careful for realm... */
    ticket_reply.enc_part.etype = useetype;
    ticket_reply.enc_part.kvno = server.kvno;

    enc_tkt_reply.flags = 0;
    enc_tkt_reply.times.starttime = 0;

    /*
     * Fix header_ticket's starttime; if it's zero, fill in the
     * authtime's value.
     */
    if (!(header_ticket->enc_part2->times.starttime))
	header_ticket->enc_part2->times.starttime =
	    header_ticket->enc_part2->times.authtime;

    /* don't use new addresses unless forwarded, see below */

    enc_tkt_reply.caddrs = header_ticket->enc_part2->caddrs;
    /* noaddrarray[0] = 0; */
    reply_encpart.caddrs = 0;		/* optional...don't put it in */

    /* It should be noted that local policy may affect the  */
    /* processing of any of these flags.  For example, some */
    /* realms may refuse to issue renewable tickets         */

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = request->addresses;
	reply_encpart.caddrs = request->addresses;
    }	
    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_FORWARDED))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(request->kdc_options, KDC_OPT_PROXY)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXY);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = request->addresses;
	reply_encpart.caddrs = request->addresses;
    }

    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isflagset(request->kdc_options, KDC_OPT_POSTDATED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_POSTDATED);
	setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;

    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
	/* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
	   to the caller */
	ticket_reply = *(header_ticket);
	enc_tkt_reply = *(header_ticket->enc_part2);
	clear(enc_tkt_reply.flags, TKT_FLG_INVALID);
    }

    if (isflagset(request->kdc_options, KDC_OPT_RENEW)) {
	krb5_deltat old_life;

	/* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
	   to the caller */
	ticket_reply = *(header_ticket);
	enc_tkt_reply = *(header_ticket->enc_part2);

	old_life = enc_tkt_reply.times.endtime - enc_tkt_reply.times.starttime;

	enc_tkt_reply.times.starttime = kdc_time;
	enc_tkt_reply.times.endtime =
	    min(header_ticket->enc_part2->times.renew_till,
		kdc_time + old_life);
    } else {
	/* not a renew request */
	enc_tkt_reply.times.starttime = kdc_time;
	until = (request->till == 0) ? kdc_infinity : request->till;
	enc_tkt_reply.times.endtime =
	    min(until, min(enc_tkt_reply.times.starttime + server.max_life,
			   min(enc_tkt_reply.times.starttime + max_life_for_realm,
			       header_ticket->enc_part2->times.endtime)));
	if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE_OK) &&
	    (enc_tkt_reply.times.endtime < request->till) &&
	    isflagset(header_ticket->enc_part2->flags,
		  TKT_FLG_RENEWABLE)) {
	    setflag(request->kdc_options, KDC_OPT_RENEWABLE);
	    request->rtime =
		min(request->till,
		    header_ticket->enc_part2->times.renew_till);
	}
    }
    rtime = (request->rtime == 0) ? kdc_infinity : request->rtime;

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	/* already checked above in policy check to reject request for a
	   renewable ticket using a non-renewable ticket */
	setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	enc_tkt_reply.times.renew_till =
	    min(rtime,
		min(header_ticket->enc_part2->times.renew_till,
		    enc_tkt_reply.times.starttime +
		    min(server.max_renewable_life,
			max_renewable_life_for_realm)));
    } else {
	enc_tkt_reply.times.renew_till = 0;
    }
    
    /*
     * Set authtime to be the same as header_ticket's
     */
    enc_tkt_reply.times.authtime = header_ticket->enc_part2->times.authtime;
    
    /*
     * Propagate the preauthentication flags through to the returned ticket.
     */
    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_PRE_AUTH))
	setflag(enc_tkt_reply.flags, TKT_FLG_PRE_AUTH);

    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_HW_AUTH))
	setflag(enc_tkt_reply.flags, TKT_FLG_HW_AUTH);
    
    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    /* assemble any authorization data */
    if (request->authorization_data.ciphertext.data) {
	krb5_encrypt_block eblock;
	krb5_data scratch;

	/* decrypt the authdata in the request */
	if (!valid_etype(request->authorization_data.etype)) {
	    syslog(LOG_INFO, "TGS_REQ: BAD_AUTH_ETYPE: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    cleanup();
	    return prepare_error_tgs(request, header_ticket,
				     KDC_ERR_ETYPE_NOSUPP,
				     fromstring, response);
	}
	/* put together an eblock for this encryption */

	krb5_use_cstype(&eblock, request->authorization_data.etype);

	scratch.length = request->authorization_data.ciphertext.length;
	if (!(scratch.data =
	      malloc(request->authorization_data.ciphertext.length))) {
	    syslog(LOG_INFO, "TGS_REQ: AUTH_NOMEM: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return(ENOMEM);
	}
	/* do any necessary key pre-processing */
	if (retval = krb5_process_key(&eblock,
				      header_ticket->enc_part2->session)) {
	    syslog(LOG_INFO, "TGS_REQ: AUTH_PROCESS_KEY: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    free(scratch.data);
	    tkt_cleanup();
	    cleanup();
	    return(retval);
	}

	/* call the encryption routine */
	if (retval = krb5_decrypt((krb5_pointer) request->authorization_data.ciphertext.data,
				  (krb5_pointer) scratch.data,
				  scratch.length, &eblock, 0)) {
	    syslog(LOG_INFO, "TGS_REQ: AUTH_ENCRYPT_FAIL: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    (void) krb5_finish_key(&eblock);
	    free(scratch.data);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
	if (retval = krb5_finish_key(&eblock)) {
	    syslog(LOG_INFO, "TGS_REQ: FINISH_KEY: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    free(scratch.data);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
	/* scratch now has the authorization data, so we decode it */
	retval = decode_krb5_authdata(&scratch, request->unenc_authdata);
	free(scratch.data);
	if (retval) {
	    syslog(LOG_INFO, "TGS_REQ: DECODE_AUTH: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}

	if (retval =
	    concat_authorization_data(request->unenc_authdata,
				      header_ticket->enc_part2->authorization_data, 
				      &enc_tkt_reply.authorization_data)) {
	    syslog(LOG_INFO, "TGS_REQ: CONCAT_AUTH: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
    } else
	enc_tkt_reply.authorization_data =
	    header_ticket->enc_part2->authorization_data;

    enc_tkt_reply.session = session_key;
    enc_tkt_reply.client = header_ticket->enc_part2->client;
    enc_tkt_reply.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply.transited.tr_contents = empty_string; /* equivalent of "" */

    /* realm compare is like strcmp, but knows how to deal with these args */
    if (realm_compare(realm_of_tgt(header_ticket),
		       header_ticket->server)) {
	/* tgt issued by local realm */
	enc_tkt_reply.transited = header_ticket->enc_part2->transited;
    } else {
	/* assemble new transited field into allocated storage */
	if (header_ticket->enc_part2->transited.tr_type !=
	    KRB5_DOMAIN_X500_COMPRESS) {
	    syslog(LOG_INFO, "TGS_REQ: BAD_TRTYPE: authtime %d, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return KRB5KDC_ERR_TRTYPE_NOSUPP;
	}
	enc_tkt_transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
	enc_tkt_transited.tr_contents.data = 0;
	enc_tkt_transited.tr_contents.length = 0;
	enc_tkt_reply.transited = enc_tkt_transited;
	if (retval =
	    add_to_transited(&header_ticket->enc_part2->transited.tr_contents,
			       &enc_tkt_reply.transited.tr_contents,
			       header_ticket->server,
			       enc_tkt_reply.client,
			       request->server)) {
	    syslog(LOG_INFO, "TGS_REQ: ADD_TR_FAIL: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
	newtransited = 1;
    }
#undef cleanup
#define cleanup() { krb5_db_free_principal(&server, 1); \
		   krb5_free_keyblock(session_key); \
		   free(cname); free(sname); \
	   if (newtransited) free(enc_tkt_reply.transited.tr_contents.data); }

    ticket_reply.enc_part2 = &enc_tkt_reply;

    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	krb5_keyblock *st_sealing_key;
	krb5_kvno st_srv_kvno;

	if (retval = kdc_get_server_key(request->second_ticket[st_idx],
					&st_sealing_key,
					&st_srv_kvno)) {
	    syslog(LOG_INFO, "TGS_REQ: 2ND_TKT_SERVER: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}

	/* decrypt the ticket */
	retval = krb5_decrypt_tkt_part(st_sealing_key,
				       request->second_ticket[st_idx]);
	krb5_free_keyblock(st_sealing_key);
	if (retval) {
	    syslog(LOG_INFO, "TGS_REQ: 2ND_TKT_DECRYPT: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
					
	if (retval = krb5_encrypt_tkt_part(request->second_ticket[st_idx]->enc_part2->session,
					   &ticket_reply)) {
	    syslog(LOG_INFO, "TGS_REQ: 2ND_TKT_ENCRYPT: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
	st_idx++;
    } else {
	/* convert server.key into a real key (it may be encrypted
	   in the database) */
	if (retval = KDB_CONVERT_KEY_OUTOF_DB(&server.key, &encrypting_key)) {
	    syslog(LOG_INFO, "TGS_REQ: CONV_KEY: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}

	retval = krb5_encrypt_tkt_part(&encrypting_key, &ticket_reply);

	memset((char *)encrypting_key.contents, 0, encrypting_key.length);
	xfree(encrypting_key.contents);

	if (retval) {
	    syslog(LOG_INFO, "TGS_REQ: TKT_ENCRYPT: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	    tkt_cleanup();
	    cleanup();
	    return retval;
	}
    }

    if (newtransited)
	free(enc_tkt_reply.transited.tr_contents.data);
    krb5_db_free_principal(&server, 1);

#undef cleanup

    /* Start assembling the response */
    reply.msg_type = KRB5_TGS_REP;
    reply.padata = 0;		/* always */
    reply.client = header_ticket->enc_part2->client;
    reply.enc_part.etype = useetype;
    reply.enc_part.kvno = 0;		/* We are using the session key */
    reply.ticket = &ticket_reply;

    reply_encpart.session = session_key;
    reply_encpart.nonce = request->nonce;

    /* copy the time fields EXCEPT for authtime; its location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = header_ticket->enc_part2->times.authtime;

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    nolrentry.lr_type = KRB5_LRQ_NONE;
    nolrentry.value = 0;
    nolrarray[0] = &nolrentry;
    nolrarray[1] = 0;
    reply_encpart.last_req = nolrarray;	/* not available for TGS reqs */
    reply_encpart.key_exp = 0;		/* ditto */
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;
    
    /* use the session key in the ticket, unless there's a subsession key
       in the AP_REQ */

    retval = krb5_encode_kdc_rep(KRB5_TGS_REP, &reply_encpart,
				 req_authdat->authenticator->subkey ?
				 req_authdat->authenticator->subkey :
				 header_ticket->enc_part2->session,
				 &reply, response);
    if (retval) {
	syslog(LOG_INFO, "TGS_REQ; ENCODE_KDC_REP: authtime %d, host %s, %s for %s",
	       authtime, fromstring, cname, sname);
    } else {
	if (is_secondary)
	    syslog(LOG_INFO, "TGS_REQ; ISSUE: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
	else
	    syslog(LOG_INFO, "TGS_REQ: ISSUE: authtime %d, host %s, %s for %s",
		   authtime, fromstring, cname, sname);
    }
    free(cname);
    free(sname);

    krb5_free_keyblock(session_key);
    tkt_cleanup();
    memset(ticket_reply.enc_part.ciphertext.data, 0,
	   ticket_reply.enc_part.ciphertext.length);
    free(ticket_reply.enc_part.ciphertext.data);
    /* these parts are left on as a courtesy from krb5_encode_kdc_rep so we
       can use them in raw form if needed.  But, we don't... */
    memset(reply.enc_part.ciphertext.data, 0,
	   reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data);
    return retval;
}

static krb5_error_code
prepare_error_tgs (request, ticket, error, ident, response)
register krb5_kdc_req *request;
krb5_ticket *ticket;
int error;
const char *ident;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;


    syslog(LOG_INFO, "TGS_REQ: host %s: %s while processing request",
	   ident,
	   error_message(error+KRB5KDC_ERR_NONE));

    errpkt.ctime = request->nonce;
    errpkt.cusec = 0;

    if (retval = krb5_us_timeofday(&errpkt.stime, &errpkt.susec)) {
	if (ticket)
	    krb5_free_ticket(ticket);
	return(retval);
    }
    errpkt.error = error;
    errpkt.server = request->server;
    errpkt.client = ticket ? ticket->enc_part2->client : 0; /* may not know
							       the name */
    errpkt.text.length = strlen(error_message(error+KRB5KDC_ERR_NONE))+1;
    if (!(errpkt.text.data = malloc(errpkt.text.length))) {
	if (ticket)
	    krb5_free_ticket(ticket);
	return ENOMEM;
    }
    (void) strcpy(errpkt.text.data, error_message(error+KRB5KDC_ERR_NONE));

    if (!(scratch = (krb5_data *)malloc(sizeof(*scratch)))) {
	free(errpkt.text.data);
	if (ticket)
	    krb5_free_ticket(ticket);
	return ENOMEM;
    }
    errpkt.e_data.length = 0;
    errpkt.e_data.data = 0;

    retval = krb5_mk_error(&errpkt, scratch);
    free(errpkt.text.data);
    *response = scratch;
    if (ticket)
	krb5_free_ticket(ticket);
    return retval;
}

/*
 * The request seems to be for a ticket-granting service somewhere else,
 * but we don't have a ticket for the final TGS.  Try to give the requestor
 * some intermediate realm.
 */
static void
find_alternate_tgs(request, server, more, nprincs)
krb5_kdc_req *request;
krb5_db_entry *server;
krb5_boolean *more;
int *nprincs;
{
    krb5_error_code retval;
    krb5_principal *plist, *pl2;
    krb5_data *tmp;

    *nprincs = 0;
    *more = FALSE;

    if (retval = krb5_walk_realm_tree(krb5_princ_component(request->server, 0),
				      krb5_princ_component(request->server, 2),
				      &plist, KRB5_REALM_BRANCH_CHAR))
	return;

    /* move to the end */
    for (pl2 = plist; *pl2; pl2++);

    /* the first entry in this array is for krbtgt/local@local, so we
       ignore it */
    while (--pl2 > plist) {
	*nprincs = 1;
	tmp = krb5_princ_realm(*pl2);
	krb5_princ_set_realm(*pl2, krb5_princ_realm(tgs_server));
	retval = krb5_db_get_principal(*pl2, server, nprincs, more);
	krb5_princ_set_realm(*pl2, tmp);
	if (retval) {
	    *nprincs = 0;
	    *more = FALSE;
	    krb5_free_realm_tree(plist);
	    return;
	}
	if (*more) {
	    krb5_db_free_principal(server, *nprincs);
	    continue;
	} else if (*nprincs == 1) {
	    /* Found it! */
	    krb5_principal tmpprinc;
	    char *sname;

	    tmp = krb5_princ_realm(*pl2);
	    krb5_princ_set_realm(*pl2, krb5_princ_realm(tgs_server));
	    if (retval = krb5_copy_principal(*pl2, &tmpprinc)) {
		krb5_db_free_principal(server, *nprincs);
		krb5_princ_set_realm(*pl2, tmp);
		continue;
	    }
	    krb5_princ_set_realm(*pl2, tmp);

	    krb5_free_principal(request->server);
	    request->server = tmpprinc;
	    if (krb5_unparse_name(request->server, &sname)) {
		syslog(LOG_INFO,
		       "TGS_REQ: issuing alternate <un-unparseable> TGT");
	    } else {
		syslog(LOG_INFO,
		       "TGS_REQ: issuing TGT %s", sname);
		free(sname);
	    }
	    return;
	}
	krb5_db_free_principal(server, *nprincs);
	continue;
    }

    *nprincs = 0;
    *more = FALSE;
    krb5_free_realm_tree(plist);
    return;
}

