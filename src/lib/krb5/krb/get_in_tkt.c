/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_get_in_tkt()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_in_tkt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

/*
 All-purpose initial ticket routine, usually called via
 krb5_get_in_tkt_with_password or krb5_get_in_tkt_with_skey.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, requesting encryption type etype, and using
 creds->times.starttime,  creds->times.endtime,  creds->times.renew_till
 as from, till, and rtime.  creds->times.renew_till is ignored unless
 the RENEWABLE option is requested.

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
#define in_clock_skew(date) (abs((date)-request.ctime) < krb5_clockskew)

/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) PROTOTYPE((const krb5_keytype,
						   krb5_keyblock **,
						   krb5_const_pointer ));
typedef krb5_error_code (*git_decrypt_proc) PROTOTYPE((const krb5_keyblock *,
						       krb5_const_pointer,
						       krb5_kdc_rep * ));
krb5_error_code
krb5_get_in_tkt(DECLARG(const krb5_flags, options),
		DECLARG(krb5_address * const *, addrs),
		DECLARG(const krb5_enctype, etype),
		DECLARG(const krb5_keytype, keytype),
		DECLARG(git_key_proc, key_proc),
		DECLARG(krb5_const_pointer, keyseed),
		DECLARG(git_decrypt_proc, decrypt_proc),
		DECLARG(krb5_const_pointer, decryptarg),
		DECLARG(krb5_creds *, creds),
		DECLARG(krb5_ccache, ccache))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keytype, keytype)
OLDDECLARG(git_key_proc, key_proc)
OLDDECLARG(krb5_const_pointer, keyseed)
OLDDECLARG(git_decrypt_proc, decrypt_proc)
OLDDECLARG(krb5_const_pointer, decryptarg)
OLDDECLARG(krb5_creds *, creds)
OLDDECLARG(krb5_ccache, ccache)
{
    krb5_kdc_req request;
    krb5_kdc_rep *as_reply;
    krb5_error *err_reply;
    krb5_error_code retval;
    krb5_data *packet;
    krb5_data reply;
    krb5_keyblock *decrypt_key;

    request.msg_type = KRB5_AS_REQ;

    /* AS_REQ has no pre-authentication. */
    request.padata_type = 0;
    request.padata.data = 0;
    request.padata.length = 0;

    request.kdc_options = options;
    request.client = creds->client;
    request.server = creds->server;

    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;
    if (retval = krb5_timeofday(&request.ctime))
	return(retval);
    /* XXX we know they are the same size... */
    request.nonce = (krb5_int32) request.ctime;
    request.etype = etype;
    request.addresses = (krb5_address **) addrs;
    request.second_ticket = 0;
    request.authorization_data = 0;

    /* encode & send to KDC */
    if (retval = encode_krb5_as_req(&request, &packet))
	return(retval);
    retval = krb5_sendto_kdc(packet, krb5_princ_realm(creds->client), &reply);
    krb5_free_data(packet);
    if (retval)
	return(retval);

    /* now decode the reply...could be error or as_rep */

    if (!krb5_is_as_rep(&reply) && !krb5_is_krb_error(&reply))
	    return KRB5KRB_AP_ERR_MSG_TYPE;
    if (retval = decode_krb5_as_rep(&reply, &as_reply)) {
	if (decode_krb5_error(&reply, &err_reply))
	    return retval;		/* some other reply--??? */
	/* it was an error */

	if ((err_reply->ctime != request.ctime) ||
	    !krb5_principal_compare(err_reply->server, request.server) ||
	    !krb5_principal_compare(err_reply->client, request.client))
	    retval = KRB5_KDCREP_MODIFIED;
	else
	    retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	/* XXX somehow make error msg text available to application? */

	krb5_free_error(err_reply);
	return retval;
    }

    /* it was a kdc_rep--decrypt & check */

    /* generate the key */
    if (retval = (*key_proc)(keytype, &decrypt_key, keyseed)) {
	krb5_free_kdc_rep(as_reply);
	return retval;
    }
    
    retval = (*decrypt_proc)(decrypt_key, decryptarg, as_reply);
    memset((char *)decrypt_key->contents, 0, decrypt_key->length);
    krb5_free_keyblock(decrypt_key);
    if (retval) {
	krb5_free_kdc_rep(as_reply);
	return retval;
    }

    /* check the contents for sanity: */
    if (!krb5_principal_compare(as_reply->client, request.client)
	|| !krb5_principal_compare(as_reply->enc_part2->server, request.server)
	|| !krb5_principal_compare(as_reply->ticket->server, request.server)
	|| (request.nonce != as_reply->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(addrs, as_reply->enc_part2->caddrs)) */
	|| ((request.from == 0) &&
	    !in_clock_skew(as_reply->enc_part2->times.starttime))
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
	memset((char *)as_reply->enc_part2->session->contents, 0,
	      as_reply->enc_part2->session->length);
	krb5_free_kdc_rep(as_reply);
	return KRB5_KDCREP_MODIFIED;
    }

    /* XXX issue warning if as_reply->enc_part2->key_exp is nearby */
	
    /* fill in the credentials */
    if (retval = krb5_copy_keyblock(as_reply->enc_part2->session,
				    &creds->keyblock)) {
	memset((char *)as_reply->enc_part2->session->contents, 0,
	      as_reply->enc_part2->session->length);
	krb5_free_kdc_rep(as_reply);
	return retval;
    }
#define cleanup_key() {memset((char *)creds->keyblock.contents, 0,\
			     creds->keyblock.length); \
		       free((char *)creds->keyblock.contents); \
		       creds->keyblock.contents = 0; \
		       creds->keyblock.length = 0;}

    creds->times = as_reply->enc_part2->times;
    creds->is_skey = FALSE;		/* this is an AS_REQ, so cannot
					   be encrypted in skey */
    creds->ticket_flags = as_reply->enc_part2->flags;
    if (retval = krb5_copy_addresses(as_reply->enc_part2->caddrs,
				     &creds->addresses)) {
	cleanup_key();
	return retval;
    }
    creds->second_ticket.length = 0;
    creds->second_ticket.data = 0;

    retval = encode_krb5_ticket(as_reply->ticket, &packet);
    krb5_free_kdc_rep(as_reply);
    if (retval) {
	krb5_free_address(creds->addresses);
	cleanup_key();
	return retval;
    }	
    creds->ticket = *packet;
    free((char *) packet);

    /* store it in the ccache! */
    if (retval = krb5_cc_store_cred(ccache, creds)) {
	/* clean up the pieces */
	free((char *)creds->ticket.data);
	krb5_free_address(creds->addresses);
	cleanup_key();
	return retval;
    }
    return 0;
}

