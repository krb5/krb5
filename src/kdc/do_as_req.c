/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * KDC Routines to deal with AS_REQ's
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_do_as_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>
#include <com_err.h>

#include <krb5/ext-proto.h>

#include <syslog.h>
#ifdef KRB5_USE_INET
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"

static krb5_error_code prepare_error_as PROTOTYPE((krb5_kdc_req *,
						   int,
						   krb5_data **));

/*
 * Do all the processing required for a AS_REQ
 */

/* XXX needs lots of cleanup and modularizing */

/*ARGSUSED*/
krb5_error_code
process_as_req(request, from, response)
register krb5_kdc_req *request;
const krb5_fulladdr *from;		/* who sent it ? */
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
    krb5_enctype useetype;
    register int i;

    krb5_timestamp until, rtime;
    char *cname = 0, *sname = 0, *fromstring = 0;

    if (!request->client)
	return(prepare_error_as(request, KDC_ERR_C_PRINCIPAL_UNKNOWN,
				response));
    if (retval = krb5_unparse_name(request->client, &cname)) {
	syslog(LOG_INFO, "AS_REQ: %s while unparsing client name",
	       error_message(retval));
	return(prepare_error_as(request, KDC_ERR_C_PRINCIPAL_UNKNOWN,
				response));
    }
    if (retval = krb5_unparse_name(request->server, &sname)) {
	free(cname);
	syslog(LOG_INFO, "AS_REQ: %s while unparsing server name",
	       error_message(retval));
	return(prepare_error_as(request, KDC_ERR_S_PRINCIPAL_UNKNOWN,
				response));
    }
#ifdef KRB5_USE_INET
    if (from->address->addrtype == ADDRTYPE_INET)
	fromstring = inet_ntoa(*(struct in_addr *)from->address->contents);
#endif
    if (!fromstring)
	fromstring = "<unknown>";

    syslog(LOG_INFO, "AS_REQ: host %s, %s for %s", fromstring, cname, sname);
    free(cname);
    free(sname);

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

    for (i = 0; i < request->netypes; i++)
	if (valid_etype(request->etype[i]))
	    break;
    if (i == request->netypes) {
	/* unsupported etype */

	cleanup();
	return(prepare_error_as(request, KDC_ERR_ETYPE_NOSUPP, response));
    }
    useetype = request->etype[i];

    if (retval = (*(krb5_csarray[useetype]->system->random_key))(krb5_csarray[useetype]->random_sequence, &session_key)) {
	/* random key failed */
	cleanup();
	return(retval);
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); \
		   krb5_db_free_principal(&server, 1); \
		   memset((char *)session_key->contents, 0, \
			  session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; }


    ticket_reply.server = request->server;
    ticket_reply.enc_part.etype = useetype;
    ticket_reply.enc_part.kvno = server.kvno;

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
    enc_tkt_reply.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply.transited.tr_contents = empty_string; /* equivalent of "" */

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
    

    until = (request->till == 0) ? kdc_infinity : request->till;

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
    rtime = (request->rtime == 0) ? kdc_infinity : request->rtime;

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

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    enc_tkt_reply.caddrs = request->addresses;
    enc_tkt_reply.authorization_data = 0; /* XXX? */

    ticket_reply.enc_part2 = &enc_tkt_reply;

    /* convert server.key into a real key (it may be encrypted
       in the database) */
    if (retval = KDB_CONVERT_KEY_OUTOF_DB(&server.key, &encrypting_key)) {
	cleanup();
	return retval;
    }
    retval = krb5_encrypt_tkt_part(&encrypting_key, &ticket_reply);
    memset((char *)encrypting_key.contents, 0, encrypting_key.length);
    free((char *)encrypting_key.contents);
    if (retval) {
	cleanup();
	return retval;
    }

    krb5_db_free_principal(&server, 1);

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); \
		   memset((char *)session_key->contents, 0, \
			  session_key->length); \
		   free((char *)session_key->contents); \
		   session_key->contents = 0; \
		   memset(ticket_reply.enc_part.ciphertext.data, 0, \
			 ticket_reply.enc_part.ciphertext.length); \
		   free(ticket_reply.enc_part.ciphertext.data);}

    /* Start assembling the response */
    reply.msg_type = KRB5_AS_REP;

    reply.padata = 0;
    /* XXX put in padata salting stuff here*/

    reply.client = request->client;
    /* XXX need separate etypes for ticket encryption and kdc_rep encryption */
    reply.enc_part.etype = useetype;
    reply.enc_part.kvno = client.kvno;
    reply.ticket = &ticket_reply;

    reply_encpart.session = session_key;
    if (retval = fetch_last_req_info(&client, &reply_encpart.last_req)) {
	cleanup();
	return retval;
    }

    reply_encpart.nonce = request->nonce;
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
    if (retval = KDB_CONVERT_KEY_OUTOF_DB(&client.key, &encrypting_key)) {
	cleanup();
	return retval;
    }
    retval = krb5_encode_kdc_rep(KRB5_AS_REP, &reply_encpart,
				 &encrypting_key,  &reply, response);
    memset((char *)encrypting_key.contents, 0, encrypting_key.length);
    free((char *)encrypting_key.contents);
    cleanup();
    return retval;
}

static krb5_error_code
prepare_error_as (request, error, response)
register krb5_kdc_req *request;
int error;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;

    errpkt.ctime = request->nonce;
    errpkt.cusec = 0;

    if (retval = krb5_us_timeofday(&errpkt.stime, &errpkt.susec))
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
    errpkt.e_data.length = 0;
    errpkt.e_data.data = 0;

    retval = krb5_mk_error(&errpkt, scratch);
    free(errpkt.text.data);
    *response = scratch;
    return retval;
}
