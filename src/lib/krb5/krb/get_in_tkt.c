/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_get_in_tkt()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_in_tkt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/asn1.h>
#include <stdio.h>
#include <krb5/libos-proto.h>

#include <errno.h>
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


/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) PROTOTYPE((krb5_keytype,
						   krb5_keyblock **,
						   krb5_pointer ));
typedef krb5_error_code (*git_decrypt_proc) PROTOTYPE((krb5_keyblock *,
						       krb5_pointer,
						       krb5_kdc_rep * ));
krb5_error_code
krb5_get_in_tkt(DECLARG(const krb5_flags, options),
		DECLARG(const krb5_address **, addrs),
		DECLARG(const krb5_enctype, etype),
		DECLARG(const krb5_keytype, keytype),
		DECLARG(git_key_proc, key_proc),
		DECLARG(const krb5_pointer, keyseed),
		DECLARG(git_decrypt_proc, decrypt_proc),
		DECLARG(const krb5_pointer, decryptarg),
		DECLARG(krb5_creds *, creds),
		DECLARG(krb5_ccache, ccache))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(const krb5_address **, addrs)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keytype, keytype)
OLDDECLARG(git_key_proc, key_proc)
OLDDECLARG(const krb5_pointer, keyseed)
OLDDECLARG(git_decrypt_proc, decrypt_proc)
OLDDECLARG(const krb5_pointer, decryptarg)
OLDDECLARG(krb5_creds *, creds)
OLDDECLARG(krb5_ccache, ccache)
{
    krb5_as_req request;
    krb5_kdc_rep *as_reply;
    krb5_error *err_reply;
    krb5_error_code retval;
    krb5_data *packet;
    krb5_data reply;
    krb5_keyblock *decrypt_key;

    request.kdc_options = options;
    if (retval = krb5_timeofday(&request.ctime))
	return(retval);
    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;
    request.etype = etype;
    request.client = creds->client;
    request.addresses = addrs;
    request.server = creds->server;

    /* encode & send to KDC */
    if (retval = encode_krb5_as_req(&request, &packet))
	return(retval);
    retval = krb5_sendto_kdc(packet, krb5_princ_realm(creds->client), &reply);
    krb5_free_data(packet);
    if (retval)
	return(retval);

    /* now decode the reply...could be error or as_rep */

    if (!krb5_is_kdc_rep(&reply))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    if (retval = decode_krb5_as_rep(&reply, &as_reply)) {
	if (decode_krb5_error(&reply, &err_reply))
	    return retval;		/* some other reply--??? */
	/* it was an error */

	/* XXX check to make sure the timestamps match, etc. */

	retval = err_reply->error + ERROR_TABLE_BASE_krb5;
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
    krb5_free_keyblock(decrypt_key);
    if (retval) {
	krb5_free_kdc_rep(as_reply);
	return retval;
    }

    /* XXX check the contents for sanity... */

    /* fill in the credentials */
    if (retval = krb5_copy_keyblock(as_reply->enc_part2->session,
				    &creds->keyblock)) {
	krb5_free_kdc_rep(as_reply);
	return retval;
    }
#define cleanup_key() {bzero((char *)creds->keyblock.contents, \
			     creds->keyblock.length); \
		       free((char *)creds->keyblock.contents); \
		       creds->keyblock.contents = 0; \
		       creds->keyblock.length = 0;}

    creds->times = as_reply->enc_part2->times;
    creds->is_skey = FALSE;		/* this is an AS_REQ, so cannot
					   be encrypted in skey */
    creds->ticket_flags = as_reply->enc_part2->flags;
    creds->second_ticket.length = 0;
    creds->second_ticket.data = 0;

    retval = encode_krb5_ticket(as_reply->ticket, &packet);
    krb5_free_kdc_rep(as_reply);
    if (retval) {
	cleanup_key();
	return retval;
    }	
    creds->ticket = *packet;
    free((char *) packet);

    /* store it in the ccache! */
    if (retval = krb5_cc_store_cred(ccache, creds)) {
	/* clean up the pieces */
	free((char *)creds->ticket.data);
	cleanup_key();
	return retval;
    }
    return 0;
}

