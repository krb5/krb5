/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * KDC Routines to deal with AS_REQ's
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_do_as_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/kdb.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <errno.h>
#include <com_err.h>

#include <sys/types.h>
#include <krb5/ext-proto.h>

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"

static krb5_error_code prepare_error_as PROTOTYPE((krb5_as_req *,
						int,
						krb5_data **));

/*
 * Do all the processing required for a AS_REQ
 */

/* XXX needs lots of cleanup and modularizing */

/*ARGSUSED*/
krb5_error_code
process_as_req(request, from, response)
register krb5_as_req *request;
krb5_fulladdr *from;			/* who sent it ? */
krb5_data **response;			/* filled in with a response packet */
{

    krb5_db_entry client, server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_error_code retval;
    int nprincs;
    krb5_boolean more;
    krb5_timestamp kdc_time;
    krb5_keyblock *session_key;
    krb5_keyblock encrypting_key;

    krb5_timestamp until, rtime;

    nprincs = 1;
    if (retval = krb5_db_get_principal(request->client, &client, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error_as(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error_as(request, KDC_ERR_C_PRINCIPAL_UNKNOWN, response));
    }	
	
    nprincs = 1;
    if (retval = krb5_db_get_principal(request->server, &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error_as(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error_as(request, KDC_ERR_S_PRINCIPAL_UNKNOWN, response));
    }

#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); }

    if (retval = krb5_timeofday(&kdc_time)) {
	cleanup();
	return(retval);
    }

    if (!valid_etype(request->etype)) {
	/* unsupported etype */

	cleanup();
	return(prepare_error_as(request, KDC_ERR_ETYPE_NOSUPP, response));
    }

    if (retval = (*(krb5_csarray[request->etype]->system->random_key))(krb5_csarray[request->etype]->random_sequence, &session_key)) {
	/* random key failed */
	cleanup();
	return(retval);
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); \
		   krb5_db_free_principal(&server, 1); \
		   bzero((char *)session_key->contents, session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; }


    ticket_reply.server = request->server;
    ticket_reply.etype = request->etype;
    ticket_reply.skvno = server.kvno;

    enc_tkt_reply.flags = 0;

        /* It should be noted that local policy may affect the  */
        /* processing of any of these flags.  For example, some */
        /* realms may refuse to issue renewable tickets         */

    if (against_flag_policy_as(request)) {
	cleanup();
	return(prepare_error_as(request, KDC_ERR_BADOPTION, response));
    }

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isflagset(request->kdc_options, KDC_OPT_DUPLICATE_SKEY))
	setflag(enc_tkt_reply.flags, TKT_FLG_DUPLICATE_SKEY);


    enc_tkt_reply.session = session_key;
    enc_tkt_reply.client = request->client;
    enc_tkt_reply.transited = empty_string; /* equivalent of "" */
    enc_tkt_reply.times.authtime = kdc_time;

    if (isflagset(request->kdc_options, KDC_OPT_POSTDATED)) {
	if (against_postdate_policy(request->from)) {
	    cleanup();
	    return(prepare_error_as(request, KDC_ERR_POLICY, response));
	}
	setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;
    

    until = (request->till == 0) ? infinity : request->till;

    enc_tkt_reply.times.endtime =
	min(until,
	    min(enc_tkt_reply.times.starttime + client.max_life,
		min(enc_tkt_reply.times.starttime + server.max_life,
		    enc_tkt_reply.times.starttime + max_life_for_realm)));

    /* XXX why && request->till ? */
    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE_OK) && 
	request->till && (enc_tkt_reply.times.endtime < request->till)) {

	/* we set the RENEWABLE option for later processing */

	setflag(request->kdc_options, KDC_OPT_RENEWABLE);
	request->rtime = request->till;
    }
    rtime = (request->rtime == 0) ? infinity : request->rtime;

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	enc_tkt_reply.times.renew_till =
	    min(rtime, min(enc_tkt_reply.times.starttime +
			   client.max_renewable_life,
			   min(enc_tkt_reply.times.starttime +
			       server.max_renewable_life,
			       enc_tkt_reply.times.starttime +
			       max_renewable_life_for_realm)));
    } else
	enc_tkt_reply.times.renew_till = 0; /* XXX */

    enc_tkt_reply.caddrs = request->addresses;
    enc_tkt_reply.authorization_data = 0; /* XXX? */

    /* XXX need separate etypes for ticket encryption and kdc_rep encryption */

    ticket_reply.enc_part2 = &enc_tkt_reply;

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

    krb5_db_free_principal(&server, 1);

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); \
		   bzero((char *)session_key->contents, session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; \
		   bzero(ticket_reply.enc_part.data, \
			 ticket_reply.enc_part.length); \
		   free(ticket_reply.enc_part.data);}

    /* Start assembling the response */
    reply.client = request->client;
    reply.etype = request->etype;
    reply.ckvno = client.kvno;
    reply.ticket = &ticket_reply;

    reply_encpart.session = session_key;
    if (retval = fetch_last_req_info(&client, &reply_encpart.last_req)) {
	cleanup();
	return retval;
    }

    reply_encpart.ctime = request->ctime;
    reply_encpart.key_exp = client.expiration;
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* copy the time fields EXCEPT for authtime; it's location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = kdc_time;

    reply_encpart.caddrs = enc_tkt_reply.caddrs;

    /* now encode/encrypt the response */

    /* convert client.key into a real key (it may be encrypted
       in the database) */
    if (retval = kdc_convert_key(&client.key, &encrypting_key,
				 CONVERT_OUTOF_DB)) {
	cleanup();
	return retval;
    }
    retval = krb5_encode_kdc_rep(KRB5_AS_REP, &reply, &reply_encpart,
				 &encrypting_key, response);
    bzero((char *)encrypting_key.contents, encrypting_key.length);
    free((char *)encrypting_key.contents);
    cleanup();
    return retval;
}

static krb5_error_code
prepare_error_as (request, error, response)
register krb5_as_req *request;
int error;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;

    errpkt.ctime = request->ctime;
    errpkt.cmsec = 0;

    if (retval = krb5_ms_timeofday(&errpkt.stime, &errpkt.smsec))
	return(retval);
    errpkt.error = error;
    errpkt.server = request->server;
    errpkt.client = request->client;
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
