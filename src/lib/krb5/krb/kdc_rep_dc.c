/*
 * lib/krb5/krb/kdc_rep_dc.c
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
 * krb5_kdc_rep_decrypt_proc()
 */

#include "k5-int.h"

/*
 * Decrypt the encrypted portion of the KDC_REP message, using the key
 * passed.
 *
 */

/*ARGSUSED*/
krb5_error_code
krb5_kdc_rep_decrypt_proc(context, key, decryptarg, dec_rep)
    krb5_context context;
    const krb5_keyblock * key;
    krb5_const_pointer decryptarg;
    krb5_kdc_rep * dec_rep;
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_enc_kdc_rep_part *local_encpart;

    if (!valid_keytype(dec_rep->enc_part.keytype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* set up scratch decrypt/decode area */

    scratch.length = dec_rep->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(dec_rep->enc_part.ciphertext.length))) {
	return(ENOMEM);
    }

    /* put together an eblock for this encryption */

    krb5_use_keytype(context, &eblock, dec_rep->enc_part.keytype);

    /* do any necessary key pre-processing */
    if ((retval = krb5_process_key(context, &eblock, key))) {
	free(scratch.data);
	return(retval);
    }

    /* call the decryption routine */
    if ((retval = krb5_decrypt(context, (krb5_pointer) dec_rep->enc_part.ciphertext.data,
			       (krb5_pointer) scratch.data,
			       scratch.length, &eblock, 0))) {
	(void) krb5_finish_key(context, &eblock);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {memset(scratch.data, 0, scratch.length); \
free(scratch.data);}
    if ((retval = krb5_finish_key(context, &eblock))) {
	clean_scratch();
	return retval;
    }

    /* and do the decode */
    retval = decode_krb5_enc_kdc_rep_part(&scratch, &local_encpart);
    clean_scratch();
    if (retval)
	return retval;

    dec_rep->enc_part2 = local_encpart;

    return 0;
}
