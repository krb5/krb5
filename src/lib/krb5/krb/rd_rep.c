/*
 * lib/krb5/krb/rd_rep.c
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
 * krb5_rd_rep()
 */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>

/*
 *  Parses a KRB_AP_REP message, returning its contents.
 * 
 *  repl is filled in with with a pointer to allocated memory containing
 * the fields from the encrypted response. 
 * 
 *  the key in kblock is used to decrypt the message.
 * 
 *  returns system errors, encryption errors, replay errors
 */

krb5_error_code
krb5_rd_rep(inbuf, kblock, repl)
const krb5_data *inbuf;
const krb5_keyblock *kblock;
krb5_ap_rep_enc_part **repl;
{
    krb5_error_code retval;
    krb5_ap_rep *reply;
    krb5_encrypt_block eblock;
    krb5_data scratch;

    if (!krb5_is_ap_rep(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;

    if (!valid_keytype(kblock->keytype))
	return KRB5_PROG_KEYTYPE_NOSUPP;
    
    /* decode it */

    if (retval = decode_krb5_ap_rep(inbuf, &reply))
	return retval;

    /* put together an eblock for this encryption */

    if (!valid_etype(reply->enc_part.etype)) {
	krb5_free_ap_rep(reply);
	return KRB5_PROG_ETYPE_NOSUPP;
    }
    krb5_use_cstype(&eblock, reply->enc_part.etype);

    scratch.length = reply->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length))) {
	krb5_free_ap_rep(reply);
	return(ENOMEM);
    }

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, kblock)) {
    errout:
	free(scratch.data);
	krb5_free_ap_rep(reply);
	return(retval);
    }

    /* call the encryption routine */
    if (retval = krb5_decrypt((krb5_pointer) reply->enc_part.ciphertext.data,
			      (krb5_pointer) scratch.data,
			      scratch.length, &eblock, 0)) {
	(void) krb5_finish_key(&eblock);
	goto errout;
    }
#define clean_scratch() {memset(scratch.data, 0, scratch.length); \
free(scratch.data);}
    /* finished with the top-level encoding of the ap_rep */
    krb5_free_ap_rep(reply);
    if (retval = krb5_finish_key(&eblock)) {

	clean_scratch();
	return retval;
    }
    /*  now decode the decrypted stuff */
    retval = decode_krb5_ap_rep_enc_part(&scratch, repl);
    clean_scratch();
    (*repl)->subkey->etype = reply->enc_part.etype;
    return retval;
}
