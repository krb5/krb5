/*
 * lib/krb5/krb/mk_rep.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_mk_rep()
 */

#include "k5-int.h"
#include "auth_con.h"

/*
 Formats a KRB_AP_REP message into outbuf.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/

krb5_error_code
krb5_mk_rep(context, auth_context, outbuf)
    krb5_context 	  context;
    krb5_auth_context	  auth_context;
    krb5_data 		* outbuf;
{
    krb5_error_code 	  retval;
    krb5_keytype 	  keytype;
    krb5_enctype 	  etype;
    krb5_ap_rep_enc_part  repl;
    krb5_encrypt_block 	  eblock;
    krb5_ap_rep 	  reply;
    krb5_data 		* scratch;
    krb5_data 		* toutbuf;

    /* verify a valid etype is available */
    if (!valid_keytype(keytype = auth_context->keyblock->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;

    etype = krb5_keytype_array[keytype]->system->proto_enctype;

    if (!valid_etype(etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* Make the reply */
    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) ||
	(auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
	(auth_context->local_seq_number == 0)) {
	if ((retval = krb5_generate_seq_number(context, auth_context->keyblock,
					       &auth_context->local_seq_number)))
            return(retval);
    }

    repl.ctime = auth_context->authentp->ctime;    
    repl.cusec = auth_context->authentp->cusec;    
    repl.subkey = auth_context->authentp->subkey;    
    repl.seq_number = auth_context->local_seq_number;

    /* encode it before encrypting */
    if ((retval = encode_krb5_ap_rep_enc_part(&repl, &scratch)))
	return retval;

    /* put together an eblock for this encryption */
    krb5_use_cstype(context, &eblock, etype);
    reply.enc_part.etype = etype;
    reply.enc_part.kvno = 0;		/* XXX user set? */

    reply.enc_part.ciphertext.length = krb5_encrypt_size(scratch->length,
							 eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  reply.enc_part.ciphertext.length))) {
	/* may destroy scratch->data */
	krb5_xfree(scratch);
	return ENOMEM;
    }
    memset(scratch->data + scratch->length, 0,
	  reply.enc_part.ciphertext.length - scratch->length);
    if (!(reply.enc_part.ciphertext.data =
	  malloc(reply.enc_part.ciphertext.length))) {
	retval = ENOMEM;
	goto cleanup_scratch;
    }

    /* do any necessary key pre-processing */
    if ((retval = krb5_process_key(context, &eblock, auth_context->keyblock)))
	goto cleanup_encpart;

    /* call the encryption routine */
    if ((retval = krb5_encrypt(context, (krb5_pointer) scratch->data,
			       (krb5_pointer) reply.enc_part.ciphertext.data,
			       scratch->length, &eblock, 0))) {
	krb5_finish_key(context, &eblock);
	goto cleanup_encpart;
    }

    if ((retval = krb5_finish_key(context, &eblock)))
	goto cleanup_encpart;

    if (!(retval = encode_krb5_ap_rep(&reply, &toutbuf))) {
	*outbuf = *toutbuf;
	krb5_xfree(toutbuf);
    }

cleanup_encpart:
    memset(reply.enc_part.ciphertext.data, 0, reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data); 
    reply.enc_part.ciphertext.length = 0; 
    reply.enc_part.ciphertext.data = 0;

cleanup_scratch:
    memset(scratch->data, 0, scratch->length); 
    krb5_free_data(context, scratch);

    return retval;
}
