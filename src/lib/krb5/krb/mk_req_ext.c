/*
 * lib/krb5/krb/mk_req_ext.c
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
 * krb5_mk_req_extended()
 */


#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/libos.h>
#include <krb5/los-proto.h>

#include <krb5/ext-proto.h>

/*
 Formats a KRB_AP_REQ message into outbuf, with more complete options than
 krb_mk_req.

 outbuf, ap_req_options, checksum, and ccache are used in the
 same fashion as for krb5_mk_req.

 creds is used to supply the credentials (ticket and session key) needed
 to form the request.

 if creds->ticket has no data (length == 0), then a ticket is obtained
 from either the cache or the TGS, passing creds to krb5_get_credentials().
 kdc_options specifies the options requested for the ticket to be used.
 If a ticket with appropriate flags is not found in the cache, then these
 options are passed on in a request to an appropriate KDC.

 ap_req_options specifies the KRB_AP_REQ options desired.

 if ap_req_options specifies AP_OPTS_USE_SESSION_KEY, then creds->ticket
 must contain the appropriate ENC-TKT-IN-SKEY ticket.

 checksum specifies the checksum to be used in the authenticator.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 On an error return, the credentials pointed to by creds might have been
 augmented with additional fields from the obtained credentials; the entire
 credentials should be released by calling krb5_free_creds().

 returns system errors
*/

static krb5_error_code 
krb5_generate_authenticator PROTOTYPE((krb5_context,
				       krb5_authenticator *, krb5_principal,
				       const krb5_checksum *, krb5_keyblock *,
				       krb5_int32, krb5_authdata ** ));

krb5_error_code INTERFACE
krb5_mk_req_extended(context, ap_req_options, checksum, sequence, 
		     newkey, in_creds, authentp, outbuf)
    krb5_context context;
    const krb5_flags ap_req_options;
    const krb5_checksum *checksum;
    krb5_int32 sequence;
    krb5_keyblock **newkey;
    krb5_creds *in_creds;
    krb5_authenticator *authentp;
    krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_ap_req request;
    krb5_authenticator authent;
    krb5_data *scratch;
    krb5_enctype etype;
    krb5_encrypt_block eblock;
    krb5_data *toutbuf;
    int cleanup_key = 0;

    request.ticket = 0;
    request.authenticator.ciphertext.data = 0;
    if (newkey)
	*newkey = 0;
    scratch = 0;
    
    if ((ap_req_options & AP_OPTS_USE_SESSION_KEY) &&
	!in_creds->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    if (!in_creds->ticket.length) 
	return(KRB5_NO_TKT_SUPPLIED);

/*	if (retval = krb5_get_credentials(context, kdc_options,
					  ccache, in_creds, out_creds)) */

    /* we need a native ticket */
    if (retval = decode_krb5_ticket(&(in_creds)->ticket, &request.ticket))
	return(retval);
    
    /* verify a valid etype is available */
    etype = request.ticket->enc_part.etype;

    if (!valid_etype(etype)) {
	retval = KRB5_PROG_ETYPE_NOSUPP;
	goto cleanup;
    }

    request.ap_options = ap_req_options;
    if (newkey) {
	if (retval = krb5_generate_subkey(context, &(in_creds)->keyblock, 
					  newkey))
	    goto cleanup;
    }

    if (retval = krb5_generate_authenticator(context, &authent, 
					     (in_creds)->client, checksum,
					     newkey ? *newkey : 0, sequence, 
					     (in_creds)->authdata))
	goto cleanup;
	
    /* encode the authenticator */
    retval = encode_krb5_authenticator(&authent, &scratch);
    if (retval)
	goto cleanup;
    
    /* Null out these fields, to prevent pointer sharing problems;
     * they were supplied by the caller
     */
    authent.client = NULL;
    authent.checksum = NULL;
    authent.authorization_data = NULL;
    if (authentp)
	    *authentp = authent;
    else
	    krb5_free_authenticator_contents(context, &authent);

    /* put together an eblock for this encryption */

    krb5_use_cstype(context, &eblock, etype);
    request.authenticator.etype = etype;
    request.authenticator.kvno = 0;
    request.authenticator.ciphertext.length =
	krb5_encrypt_size(scratch->length, eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  request.authenticator.ciphertext.length))) {
	/* may destroy scratch->data */
	retval = ENOMEM;
	goto cleanup;
    }
    memset(scratch->data + scratch->length, 0,
	  request.authenticator.ciphertext.length - scratch->length);
    if (!(request.authenticator.ciphertext.data =
	  malloc(request.authenticator.ciphertext.length))) {
	retval = ENOMEM;
	goto cleanup;
    }

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(context, &eblock, &(in_creds)->keyblock))
	goto cleanup;

    cleanup_key++;

    /* call the encryption routine */
    if (retval = krb5_encrypt(context, (krb5_pointer) scratch->data,
			      (krb5_pointer) request.authenticator.ciphertext.data,
			      scratch->length, &eblock, 0))
	goto cleanup;

    if (retval = krb5_finish_key(context, &eblock))
	goto cleanup;
    cleanup_key = 0;
    
    retval = encode_krb5_ap_req(&request, &toutbuf);
    if (retval)
	goto cleanup;
    
    *outbuf = *toutbuf;
    krb5_xfree(toutbuf);

cleanup:
    if (request.ticket)
	krb5_free_ticket(context, request.ticket);
    if (request.authenticator.ciphertext.data) {
    	(void) memset(request.authenticator.ciphertext.data, 0,
		      request.authenticator.ciphertext.length);
	free(request.authenticator.ciphertext.data);
    }
    if (retval && newkey && *newkey)
	krb5_free_keyblock(context, *newkey);
    if (scratch) {
	memset(scratch->data, 0, scratch->length);
        krb5_xfree(scratch->data);
	krb5_xfree(scratch);
    }
    if (cleanup_key)
	krb5_finish_key(context, &eblock);

    return retval;
}

static krb5_error_code
krb5_generate_authenticator(context, authent, client, cksum, key, seq_number, authorization)
    krb5_context context;
    krb5_authenticator *authent;
    krb5_principal client;
    const krb5_checksum *cksum;
    krb5_keyblock *key;
    krb5_int32 seq_number;
    krb5_authdata **authorization;
{
    krb5_error_code retval;
    
    authent->client = client;
    authent->checksum = (krb5_checksum *)cksum;
    if (key) {
	retval = krb5_copy_keyblock(context, key, &authent->subkey);
	if (retval)
	    return retval;
    } else
	authent->subkey = 0;
    authent->subkey = key;
    authent->seq_number = seq_number;
    authent->authorization_data = authorization;

    return(krb5_us_timeofday(context, &authent->ctime, &authent->cusec));
}
