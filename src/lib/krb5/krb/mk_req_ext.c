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


#include "k5-int.h"
#include "auth_con.h"

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
krb5_mk_req_extended(context, auth_context, ap_req_options, in_data, in_creds,
		     outbuf)
    krb5_context 	  context;
    krb5_auth_context	* auth_context;
    const krb5_flags 	  ap_req_options;
    krb5_data		* in_data;
    krb5_creds 		* in_creds;
    krb5_data 		* outbuf;
{
    krb5_error_code 	  retval;
    krb5_checksum	  checksum;
    krb5_checksum	  *checksump = 0;
    krb5_auth_context	  new_auth_context;

    krb5_ap_req request;
    krb5_data *scratch = 0;
    krb5_encrypt_block eblock;
    krb5_data *toutbuf;

    request.ap_options = ap_req_options & AP_OPTS_WIRE_MASK;
    request.authenticator.ciphertext.data = 0;
    request.ticket = 0;
    
    if (!in_creds->ticket.length) 
	return(KRB5_NO_TKT_SUPPLIED);

    /* we need a native ticket */
    if ((retval = decode_krb5_ticket(&(in_creds)->ticket, &request.ticket)))
	return(retval);
    
    /* verify a valid enctype is available */
    if (!valid_enctype(request.ticket->enc_part.enctype)) {
	retval = KRB5_PROG_ETYPE_NOSUPP;
	goto cleanup;
    }

    /* generate auth_context if needed */
    if (*auth_context == NULL) {
	if ((retval = krb5_auth_con_init(context, &new_auth_context)))
	    goto cleanup;
	*auth_context = new_auth_context;
    }

    /* set auth context keyblock */
    if ((retval = krb5_copy_keyblock(context, &in_creds->keyblock, 
				     &((*auth_context)->keyblock))))
	goto cleanup;

    /* generate seq number if needed */
    if ((((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE)
     || ((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE))
      && ((*auth_context)->local_seq_number == 0)) 
	if ((retval = krb5_generate_seq_number(context, &in_creds->keyblock,
				     &(*auth_context)->local_seq_number)))
	    goto cleanup;
	

    /* generate subkey if needed */
    if ((ap_req_options & AP_OPTS_USE_SUBKEY)&&(!(*auth_context)->local_subkey))
	if ((retval = krb5_generate_subkey(context, &(in_creds)->keyblock, 
					   &(*auth_context)->local_subkey)))
	    goto cleanup;


    if (in_data) {
      if ((*auth_context)->cksumtype == 0x8003) {
	/* XXX Special hack for GSSAPI */
	checksum.checksum_type = 0x8003;
	checksum.length = in_data->length;
	checksum.contents = (krb5_octet *) in_data->data;
      } else  {
	/* Generate checksum, XXX What should the seed be? */
	if ((checksum.contents = (krb5_octet *)malloc(krb5_checksum_size(context,
				 (*auth_context)->cksumtype))) == NULL) {
	  retval = ENOMEM;
	  goto cleanup;
	}
	if ((retval = krb5_calculate_checksum(context, 
					      (*auth_context)->cksumtype, 
					      in_data->data, in_data->length,
					      (*auth_context)->keyblock->contents,
					      (*auth_context)->keyblock->length,
					      &checksum)))
	  goto cleanup_cksum;
      }
      checksump = &checksum;
    }

    /* Generate authenticator */
    if (((*auth_context)->authentp = (krb5_authenticator *)malloc(sizeof(
					krb5_authenticator))) == NULL) {
	retval = ENOMEM;
	goto cleanup_cksum;
    }

    if ((retval = krb5_generate_authenticator(context,
					      (*auth_context)->authentp,
					      (in_creds)->client, checksump,
					      (*auth_context)->local_subkey,
					      (*auth_context)->local_seq_number,
					      (in_creds)->authdata)))
	goto cleanup_cksum;
	
    /* encode the authenticator */
    if ((retval = encode_krb5_authenticator((*auth_context)->authentp,
					    &scratch)))
	goto cleanup_cksum;
    
    /* Null out these fields, to prevent pointer sharing problems;
     * they were supplied by the caller
     */
    (*auth_context)->authentp->client = NULL;
    (*auth_context)->authentp->checksum = NULL;
    (*auth_context)->authentp->authorization_data = NULL;

    /* put together an eblock for this encryption */

    krb5_use_enctype(context, &eblock, request.ticket->enc_part.enctype);
    request.authenticator.enctype = request.ticket->enc_part.enctype;
    request.authenticator.kvno = 0;
    request.authenticator.ciphertext.length =
	krb5_encrypt_size(scratch->length, eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  request.authenticator.ciphertext.length))) {
	/* may destroy scratch->data */
	retval = ENOMEM;
	goto cleanup_cksum;
    }
    memset(scratch->data + scratch->length, 0,
	  request.authenticator.ciphertext.length - scratch->length);
    if (!(request.authenticator.ciphertext.data =
	  malloc(request.authenticator.ciphertext.length))) {
	retval = ENOMEM;
	goto cleanup_cksum;
    }

    /* do any necessary key pre-processing */
    if ((retval = krb5_process_key(context, &eblock, &(in_creds)->keyblock)))
	goto cleanup;

    /* call the encryption routine */
    if ((retval = krb5_encrypt(context, (krb5_pointer) scratch->data,
			       (krb5_pointer) request.authenticator.ciphertext.data,
			       scratch->length, &eblock, 0))) {
        krb5_finish_key(context, &eblock);
	goto cleanup_cksum;
    }

    if ((retval = krb5_finish_key(context, &eblock)))
	goto cleanup_cksum;
    
    if ((retval = encode_krb5_ap_req(&request, &toutbuf)))
	goto cleanup_cksum;
#ifdef HAVE_C_STRUCTURE_ASSIGNMENT
    *outbuf = *toutbuf;
#else
    memcpy(outbuf, toutbuf, sizeof(krb5_data));
#endif

    krb5_xfree(toutbuf);

cleanup_cksum:
    if (checksump && checksump->checksum_type != 0x8003)
      free(checksump->contents);

cleanup:
    if (request.ticket)
	krb5_free_ticket(context, request.ticket);
    if (request.authenticator.ciphertext.data) {
    	(void) memset(request.authenticator.ciphertext.data, 0,
		      request.authenticator.ciphertext.length);
	free(request.authenticator.ciphertext.data);
    }
    if (scratch) {
	memset(scratch->data, 0, scratch->length);
        krb5_xfree(scratch->data);
	krb5_xfree(scratch);
    }
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
