/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * KDC Routines to deal with TGS_REQ's
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_do_tgs_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>
#include <krb5/ext-proto.h>
#include <com_err.h>

#include <syslog.h>
#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"


static krb5_error_code prepare_error_tgs PROTOTYPE((krb5_tgs_req *,
						int,
						krb5_data **));
static krb5_error_code decrypt_second_ticket PROTOTYPE((krb5_ticket *));

/*ARGSUSED*/
krb5_error_code
process_tgs_req(request, from, response)
krb5_tgs_req *request;
const krb5_fulladdr *from;		/* who sent it ? */
krb5_data **response;			/* filled in with a response packet */
{

    krb5_db_entry server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply, *second_ticket, *header_ticket;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_error_code retval;
    int nprincs;
    krb5_boolean more;
    krb5_timestamp kdc_time;
    krb5_keyblock *session_key;
    int newtransited = 0;
    krb5_timestamp until, rtime;
    krb5_keyblock encrypting_key;
    register krb5_real_tgs_req *realreq;
    char *cname = 0, *sname = 0, *fromstring = 0;
    krb5_last_req_entry *nolrarray[1];
    krb5_address *noaddrarray[1];

    if ((retval = decrypt_tgs_req(request, from))) {
	if (!request->tgs_request2)
	    return retval;
	if (retval > ERROR_TABLE_BASE_krb5 &&
	    retval < ERROR_TABLE_BASE_krb5 + 128) {
	    /* protocol error */
	    return(prepare_error_tgs(request,
				     retval - ERROR_TABLE_BASE_krb5,
				     response));
	} else
	    return retval;
    }
	
    /* get ptr to real stuff */
    realreq = request->tgs_request2;

    /* we've already dealt with the AP_REQ header, so
       we can use request->header2 freely.
       The encrypted part (if any) has been decrypted with the session key.
       */

    /* short-hand name to avoid lots of dereferencing */
    header_ticket = request->header2->ticket;

    if (retval = krb5_unparse_name(header_ticket->enc_part2->client, &cname))
	return(retval);
    if (retval = krb5_unparse_name(realreq->server, &sname)) {
	free(cname);
	return(retval);
    }
#ifdef KRB5_USE_INET
    if (from->address->addrtype == ADDRTYPE_INET)
	fromstring = inet_ntoa(*(struct in_addr *)from->address->contents);
#endif
    if (!fromstring)
	fromstring = "<unknown>";

    syslog(LOG_INFO, "TGS_REQ: host %s, %s for %s", fromstring, cname, sname);
    free(cname);
    free(sname);

    second_ticket = 0;

    /* XXX make sure server here has the proper realm...taken from AP_REQ
       header? */

    nprincs = 1;
    if (retval = krb5_db_get_principal(realreq->server, &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error_tgs(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE,
				 response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error_tgs(request, KDC_ERR_S_PRINCIPAL_UNKNOWN,
				 response));
    }

#define cleanup() {krb5_db_free_principal(&server, 1);}

    if (retval = krb5_timeofday(&kdc_time)) {
	cleanup();
	return(retval);
    }
    
    if (!valid_etype(realreq->etype)) {
	/* unsupported etype */

	cleanup();
	return(prepare_error_tgs(request, KDC_ERR_ETYPE_NOSUPP, response));
    }

    if (isflagset(realreq->kdc_options, KDC_OPT_REUSE_SKEY)) {
	/* decrypt second ticket, and examine */
	if (!realreq->enc_part2) {
	    cleanup();
	    return(prepare_error_tgs(request, KDC_ERR_BADOPTION, response));
	}
	second_ticket = realreq->enc_part2->second_ticket;
	if (retval = decrypt_second_ticket(second_ticket)) {
	    cleanup();
	    return(retval);
	}
	if (!isflagset(second_ticket->enc_part2->flags,
		   TKT_FLG_DUPLICATE_SKEY)) {
	    krb5_free_enc_tkt_part(second_ticket->enc_part2);
	    second_ticket->enc_part2 = 0;
	    cleanup();
	    return(prepare_error_tgs(request, KDC_ERR_BADOPTION, response));
	}
	session_key = second_ticket->enc_part2->session;
    } else {
	if (retval = (*(krb5_csarray[realreq->etype]->system->random_key))(krb5_csarray[realreq->etype]->random_sequence, &session_key)) {
	    /* random key failed */
	    cleanup();
	    return(retval);
	}
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&server, 1); \
		   bzero((char *)session_key->contents, session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; \
		   if (second_ticket) { \
		       krb5_free_enc_tkt_part(second_ticket->enc_part2); \
		       second_ticket->enc_part2 = 0;}}

    ticket_reply.server = realreq->server; /* XXX careful for realm... */
    ticket_reply.etype = realreq->etype;
    ticket_reply.skvno = server.kvno;

    enc_tkt_reply.flags = 0;
    enc_tkt_reply.times.starttime = 0;


    /* don't use new addresses unless forwarded, see below */

    enc_tkt_reply.caddrs = header_ticket->enc_part2->caddrs;
    noaddrarray[0] = 0;
    reply_encpart.caddrs = noaddrarray;

        /* It should be noted that local policy may affect the  */
        /* processing of any of these flags.  For example, some */
        /* realms may refuse to issue renewable tickets         */

    /* the policy check MUST make sure there are no invalid option/flag
       combinations */

    if (against_flag_policy_tgs(request)) {
	cleanup();
	return(prepare_error_tgs(request, KDC_ERR_BADOPTION, response));
    }

    if (isflagset(realreq->kdc_options, KDC_OPT_FORWARDABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isflagset(realreq->kdc_options, KDC_OPT_FORWARDED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = realreq->addresses;
	reply_encpart.caddrs = realreq->addresses;
    }	

    if (isflagset(realreq->kdc_options, KDC_OPT_PROXIABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(realreq->kdc_options, KDC_OPT_PROXY)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXY);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = realreq->addresses;
	reply_encpart.caddrs = realreq->addresses;
    }

    if (isflagset(realreq->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isflagset(realreq->kdc_options, KDC_OPT_POSTDATED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_POSTDATED);
	setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
	if (against_postdate_policy(realreq->from)) {
	    cleanup();
	    return(prepare_error_tgs(request, KDC_ERR_BADOPTION, response));
	}	    
	enc_tkt_reply.times.starttime = realreq->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;

    if (isflagset(realreq->kdc_options, KDC_OPT_DUPLICATE_SKEY) ||
	isflagset(realreq->kdc_options, KDC_OPT_REUSE_SKEY))
	setflag(enc_tkt_reply.flags, TKT_FLG_DUPLICATE_SKEY);
    if (isflagset(realreq->kdc_options, KDC_OPT_VALIDATE)) {
	if (header_ticket->enc_part2->times.starttime > kdc_time) {
	    cleanup();
	    return(prepare_error_tgs(request, KRB_AP_ERR_TKT_NYV, response));
	}
	/* XXX move this check out elsewhere? */
	if (check_hot_list(header_ticket)) {
	    cleanup();
	    return(prepare_error_tgs(request, KRB_AP_ERR_REPEAT, response));
	}
	/* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
	   to the caller */
	ticket_reply = *(header_ticket);
	enc_tkt_reply = *(header_ticket->enc_part2);
	clear(enc_tkt_reply.flags, TKT_FLG_INVALID);
    }
    /* 
        if (req.kdc_options.(any flag except ENC-TKT-IN-SKEY, RENEW,
                             and those already processed) then
                return KRB_ERROR, code KDC_ERR_BADOPTION;
        endif
	*/

    enc_tkt_reply.times.authtime = header_ticket->enc_part2->times.authtime;
    if (isflagset(realreq->kdc_options, KDC_OPT_RENEW)) {
	krb5_deltat old_life;

          /* Note that if the endtime has already passed, the ticket would  */
          /* have been rejected in the initial authentication stage, so     */
          /* there is no need to check again here                           */

	/* has it completely run out? */
	if (header_ticket->enc_part2->times.renew_till < kdc_time) {
	    cleanup();
	    return(prepare_error_tgs(request, KRB_AP_ERR_TKT_EXPIRED, response));
	}    

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
	until = (realreq->till == 0) ? infinity : realreq->till;
	enc_tkt_reply.times.endtime =
	    min(until, min(enc_tkt_reply.times.starttime + server.max_life,
			   min(enc_tkt_reply.times.starttime + max_life_for_realm,
			       header_ticket->enc_part2->times.endtime)));
	if (isflagset(realreq->kdc_options, KDC_OPT_RENEWABLE_OK) &&
	    (enc_tkt_reply.times.endtime < realreq->till) &&
	    isflagset(header_ticket->enc_part2->flags,
		  TKT_FLG_RENEWABLE)) {
	    setflag(realreq->kdc_options, KDC_OPT_RENEWABLE);
	    realreq->rtime =
		min(realreq->till,
		    header_ticket->enc_part2->times.renew_till);
	}
    }
    rtime = (realreq->rtime == 0) ? infinity : realreq->rtime;

    if (isflagset(realreq->kdc_options, KDC_OPT_RENEWABLE)) {
	/* already checked above in policy check to reject request for a
	   renewable ticket using a non-renewable ticket */
	setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	enc_tkt_reply.times.renew_till =
	    min(rtime,
		min(enc_tkt_reply.times.starttime + server.max_renewable_life,
		    min(enc_tkt_reply.times.starttime + max_renewable_life_for_realm,
			header_ticket->enc_part2->times.renew_till)));
    } else {
	enc_tkt_reply.times.renew_till = 0; /* XXX */
    }

    /* assemble any authorization data */
    if (realreq->enc_part2 && realreq->enc_part2->authorization_data) {
	if (retval =
	    concat_authorization_data(realreq->enc_part2->authorization_data,
				      header_ticket->enc_part2->authorization_data, 
				      &enc_tkt_reply.authorization_data)) {
	    cleanup();
	    return retval;
	}
    } else
	enc_tkt_reply.authorization_data =
	    header_ticket->enc_part2->authorization_data;
    enc_tkt_reply.session = session_key;
    enc_tkt_reply.client = header_ticket->enc_part2->client;
    enc_tkt_reply.transited = empty_string; /* equivalent of "" */

    /* realm compare is like strcmp, but knows how to deal with these args */
    if (realm_compare(realm_of_tgt(header_ticket),
		       header_ticket->server)) {
	/* tgt issued by local realm */
	enc_tkt_reply.transited = header_ticket->enc_part2->transited;
    } else {
	/* assemble new transited field into allocated storage */
	if (retval =
	    compress_transited(&header_ticket->enc_part2->transited,
			       header_ticket->server,
			       &enc_tkt_reply.transited)) {
	    cleanup();
	    return retval;
	}
	newtransited = 1;
    }
#undef cleanup
#define cleanup() {krb5_db_free_principal(&server, 1); \
		   bzero((char *)session_key->contents, session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; \
		   if (second_ticket) { \
		       krb5_free_enc_tkt_part(second_ticket->enc_part2); \
		       second_ticket->enc_part2 = 0;} \
		   if (newtransited) free(enc_tkt_reply.transited.data);}

    ticket_reply.enc_part2 = &enc_tkt_reply;
    enc_tkt_reply.confounder = krb5_random_confounder();

    if (isflagset(realreq->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	if (!second_ticket) {
	    if (!realreq->enc_part2) {
		cleanup();
		return(prepare_error_tgs(request, KDC_ERR_BADOPTION,
					 response));
	    }
	    if 	(retval = decrypt_second_ticket(realreq->enc_part2->second_ticket)) {
		cleanup();
		return(retval);
	    }
	    second_ticket = realreq->enc_part2->second_ticket;
	}
	if (retval = krb5_encrypt_tkt_part(second_ticket->enc_part2->session,
					   &ticket_reply)) {
	    cleanup();
	    return retval;
	}
    } else {
	/* convert server.key into a real key (it may be encrypted
	   in the database) */
	if (retval = kdc_convert_key(&server.key, &encrypting_key,
				     CONVERT_OUTOF_DB)) {
	    cleanup();
	    return retval;
	}

	retval = krb5_encrypt_tkt_part(&encrypting_key, &ticket_reply);

	bzero((char *)encrypting_key.contents, encrypting_key.length);
	free((char *)encrypting_key.contents);

	if (retval) {
	    cleanup();
	    return retval;
	}
    }

    if (newtransited)
	free(enc_tkt_reply.transited.data);
    if (second_ticket) {
	krb5_free_enc_tkt_part(second_ticket->enc_part2);
	second_ticket->enc_part2 = 0;
    }
    krb5_db_free_principal(&server, 1);

#undef cleanup

    /* Start assembling the response */
    reply.client = header_ticket->enc_part2->client;
    reply.etype = realreq->etype;
    reply.ckvno = 0;			/* We are using the session key */
    reply.ticket = &ticket_reply;

    reply_encpart.session = session_key;
    reply_encpart.ctime = realreq->ctime;

    /* copy the time fields EXCEPT for authtime; it's location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = kdc_time;


    nolrarray[0] = 0;
    reply_encpart.last_req = nolrarray;	/* not available for TGS reqs */
    reply_encpart.key_exp = 0;		/* ditto */
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;
    reply_encpart.confounder = krb5_random_confounder();

    retval = krb5_encode_kdc_rep(KRB5_TGS_REP, &reply_encpart,
				 header_ticket->enc_part2->session,
				 &reply, response);
    bzero((char *)session_key->contents, session_key->length);
    free((char *)session_key->contents);
    session_key->contents = 0;
    return retval;
}

static krb5_error_code
prepare_error_tgs (request, error, response)
register krb5_tgs_req *request;
int error;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;
    krb5_real_tgs_req *realreq = request->tgs_request2;

    errpkt.ctime = realreq->ctime;
    errpkt.cmsec = 0;

    if (retval = krb5_ms_timeofday(&errpkt.stime, &errpkt.smsec))
	return(retval);
    errpkt.error = error;
    errpkt.server = realreq->server;
    errpkt.client = request->header2->ticket->enc_part2->client;
    errpkt.text.length = strlen(error_message(error+KRB5KDC_ERR_NONE))+1;
    if (!(errpkt.text.data = malloc(errpkt.text.length)))
	return ENOMEM;
    (void) strcpy(errpkt.text.data, error_message(error+KRB5KDC_ERR_NONE));

    if (!(scratch = (krb5_data *)malloc(sizeof(*scratch)))) {
	free(errpkt.text.data);
	return ENOMEM;
    }
    retval = krb5_mk_error(&errpkt, scratch);
    free(errpkt.text.data);
    *response = scratch;
    return retval;
}

static krb5_error_code
decrypt_second_ticket(ticket)
register krb5_ticket *ticket;
{
    int nprincs;
    krb5_error_code retval;
    krb5_db_entry server;
    krb5_boolean more;

    nprincs = 1;
    if (retval = krb5_db_get_principal(ticket->server, &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&server, nprincs);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (nprincs != 1) {
	krb5_db_free_principal(&server, nprincs);
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
    retval = krb5_decrypt_tkt_part(&server.key, ticket);
    krb5_db_free_principal(&server, nprincs);
    return(retval);
}
