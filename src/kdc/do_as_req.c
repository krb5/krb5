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
static char rcsid_do_as_req_c >>>[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/kdb.h>
#include <krb5/asn.1/KRB5-types.h>
#include <krb5/asn.1/krb5_free.h>
#include <krb5/asn.1/asn1defs.h>
#include <krb5/asn.1/KRB5-types-aux.h>
#include <krb5/asn.1/encode.h>
#include <errno.h>
#include <com_err.h>

extern krb5_cs_table_entry *csarray[];
extern int max_cryptosystem;		/* max entry in array */
extern krb5_data empty_string;		/* initialized to {0, ""} */
extern krb5_timestamp infinity;		/* greater than every valid timestamp */
extern krb5_deltat max_life_for_realm;	/* XXX should be a parameter? */
extern krb5_deltat max_renewable_life_for_realm; /* XXX should be a parameter? */

static krb5_error_code prepare_error PROTOTYPE((int,
						krb5_data *));
/*
 * Do all the processing required for a AS_REQ
 */

/* XXX needs lots of cleanup and modularizing */

#define isset(flagfield, flag) (flagfield & flag)
#define set(flagfield, flag) (flagfield &= flag)

#ifndef	min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

krb5_error_code
process_as_req(request, response)
register krb5_as_req *request;
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
    krb5_encrypt_block eblock;
    krb5_data *scratch;

    krb5_timestamp until, rtime;

    nprincs = 1;
    if (retval = krb5_db_get_principal(request->client, &client, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, nprincs);
	return(prepare_error(request, KDC_ERR_C_PRINCIPAL_UNKNOWN, response));
    }	
	
    nprincs = 1;
    if (retval = krb5_db_get_principal(request->server, &server, &nprincs,
				       &more))
	return(retval);
    if (more) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error(request, KDC_ERR_PRINCIPAL_NOT_UNIQUE, response));
    } else if (nprincs != 1) {
	krb5_db_free_principal(&client, 1);
	krb5_db_free_principal(&server, nprincs);
	return(prepare_error(request, KDC_ERR_S_PRINCIPAL_UNKNOWN, response));
    }

    if (retval = krb5_timeofday(&kdc_time))
	return(retval);

    if (request->etype > max_cryptosystem ||
	!csarray[request->etype]->system) {
	/* unsupported etype */

#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); }

	cleanup();
	return(prepare_error(request, KDC_ERR_ETYPE_NOSUPP, response));
    }

    if (retval = (*(csarray[request->etype]->system->random_key))(csarray[request->etype]->random_sequence, &session_key)) {
	/* random key failed */
	cleanup();
	return(retval);
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); bzero((char *)session_key, sizeof(*session_key)+session_key->length-1); }


    ticket_reply.server = request->server;
    ticket_reply.etype = request->etype;
    ticket_reply.skvno = server.kvno;

    enc_tkt_reply.flags = 0;

        /* It should be noted that local policy may affect the  */
        /* processing of any of these flags.  For example, some */
        /* realms may refuse to issue renewable tickets         */

    if (isset(request->kdc_options, KDC_OPT_FORWARDED) ||
	isset(request->kdc_options, KDC_OPT_PROXY) ||
	isset(request->kdc_options, KDC_OPT_RENEW) ||
	isset(request->kdc_options, KDC_OPT_VALIDATE) ||
	isset(request->kdc_options, KDC_OPT_REUSE_SKEY) ||
	isset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	/* none of these options is valid for an AS request */
	cleanup();
	return(prepare_error(request, KDC_ERR_BADOPTION, response));
    }

    if (isset(request->kdc_options, KDC_OPT_FORWARDABLE))
	set(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isset(request->kdc_options, KDC_OPT_PROXIABLE))
	set(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	set(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isset(request->kdc_options, KDC_OPT_DUPLICATE_SKEY))
	set(enc_tkt_reply.flags, TKT_FLG_DUPLICATE_SKEY);


    enc_tkt_reply.session = session_key;
    enc_tkt_reply.client = request->client;
    enc_tkt_reply.transited = empty_string; /* equivalent of "" */
    enc_tkt_reply.times.authtime = kdc_time;

    if (isset(request->kdc_options, KDC_OPT_POSTDATED)) {
	if (against_postdate_policy(request->from)) {
	    cleanup();
	    return(prepare_error(request, KDC_ERR_POLICY, response));
	}
	set(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;
    

    until = (request->till == 0) ? infinity : request->till;

    enc_tkt_reply.times.endtime =
	min(until,
	    min(enc_tkt_reply.times.starttime + client.max_life,
		min(enc_tkt_reply.times.starttime + server.max_life,
		    enc_tkt_reply.times.starttime + max_life_for_realm)));

    if (isset(request->kdc_options, KDC_OPT_RENEWABLE_OK) && 
	request->till && (enc_tkt_reply.times.endtime < request->till)) {

	/* we set the RENEWABLE option for later processing */

	set(request->kdc_options, KDC_OPT_RENEWABLE);
	request->rtime = request->till;
    }
    rtime = (request->rtime == 0) ? infinity : request->rtime;

    if (isset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	set(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
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

    /* encrypt the encrypted part */
    /*  Encode the to-be-encrypted part. */
    if (retval = encode_krb5_enc_tkt_part(&enc_tkt_reply, &scratch)) {
	cleanup();
	return retval;
    }

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1); krb5_db_free_principal(&server, 1); bzero((char *)session_key, sizeof(*session_key)+session_key->length-1); bzero(scratch->data, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = csarray[request->etype]->system;
    ticket_reply.enc_part.length = krb5_encrypt_size(scratch->length,
						     eblock.crypto_entry);
    if (!(ticket_reply.enc_part.data = malloc(ticket_reply.enc_part.length))) {
	cleanup();
	return ENOMEM;
    }
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, server.key)) {
	free(ticket_reply.enc_part.data);
	cleanup();
	return retval;
    }
    if (retval = (*eblock.crypto_entry->encrypt_func)((krb5_pointer) scratch->data, (krb5_pointer) ticket_reply.enc_part.data, scratch->length, &eblock)) {
	free(ticket_reply.enc_part.data);
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
	cleanup();
	return retval;
    }

    /* ticket is now complete-- do some cleanup */
    bzero(scratch->data, scratch->length);
    krb5_free_data(scratch);
    krb5_db_free_principal(&server, 1);

#undef cleanup
#define cleanup() {krb5_db_free_principal(&client, 1);bzero((char *)session_key, sizeof(*session_key)+session_key->length-1); bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data);}

    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	cleanup();
	return retval;
    }

    /* XXX need separate etypes for ticket encryption and kdc_rep encryption */


    /* Start assembling the response */
    reply.client = request->client;
    reply.etype = request->etype;
    reply.ckvno = client.kvno;
    reply.ticket = &ticket_reply;


    reply_encpart.session = session_key;
    reply_encpart.last_req = 0;		/* XXX */
    reply_encpart.ctime = request->ctime;
    reply_encpart.key_exp = client.expiration;
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* copy the time fields EXCEPT for authtime; it's location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = kdc_time;

    reply_encpart.caddrs = enc_tkt_reply.caddrs;

    /* finished with session key */
    bzero((char *)session_key, sizeof(*session_key)+session_key->length-1);

#undef cleanup
#define cleanup() { krb5_db_free_principal(&client, 1); bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data);}

    /* now encode/encrypt the response */

    if (retval = encode_krb5_enc_kdc_rep_part(&reply_encpart, &scratch)) {
	cleanup();
	return retval;
    }
#undef cleanup
#define cleanup() { krb5_db_free_principal(&client, 1); bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data); bzero(scratch->data, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = csarray[request->etype]->system;
    reply.enc_part.length = krb5_encrypt_size(scratch->length,
					      eblock.crypto_entry);
    if (!(reply.enc_part.data = malloc(reply.enc_part.length))) {
	cleanup();
	return ENOMEM;
    }
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, client.key)) {
	free(reply.enc_part.data);
	cleanup();
	return retval;
    }
    if (retval = (*eblock.crypto_entry->encrypt_func)((krb5_pointer) scratch->data, (krb5_pointer) reply.enc_part.data, scratch->length, &eblock)) {
	free(reply.enc_part.data);
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
	cleanup();
	return retval;
    }

    /* some more cleanup */
    bzero(scratch->data, scratch->length);
    krb5_free_data(scratch);
    krb5_db_free_principal(&client, 1);

#undef cleanup
#define cleanup() { bzero(ticket_reply.enc_part.data, ticket_reply.enc_part.length); free(ticket_reply.enc_part.data); bzero(reply.enc_part.data,reply.enc_part.length); free(reply.enc_part.data); }

    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	cleanup();
	return retval;
    }

    /* now it's ready to be encoded for the wire! */

    retval = encode_krb5_kdc_rep(&reply, response);
    cleanup();
    return retval;

}

static krb5_error_code
prepare_error (request, error, response)
register krb5_as_req *request;
int error;
krb5_data **response;
{
    krb5_error errpkt;
    krb5_error_code retval;


    errpkt.ctime = request->ctime;
    errpkt.cmsec = 0;

    if (retval = krb5_mstimeofday(&errpkt.stime, &errpkt.smsec))
	return(retval);
    errpkt.error = error;
    errpkt.server = request->server;
    errpkt.client = request->client;
    errpkt.text.length = strlen(error_message(error+KRB5KDC_ERR_NONE))+1;
    if (!(errpkt.text.data = malloc(errpkt.text.length)))
	return ENOMEM;
    (void) strcpy(errpkt.text.data, error_message(error+KRB5KDC_ERR_NONE));

    retval = encode_krb5_error(&errpkt, &response);
    free(errpkt.text.data);
    return retval;
}
