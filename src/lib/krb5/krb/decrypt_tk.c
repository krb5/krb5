/*
 * lib/krb5/krb/decrypt_tk.c
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
 * krb5_decrypt_tkt_part() function.
 */

#include "k5-int.h"

/*
 Decrypts dec_ticket->enc_part
 using *srv_key, and places result in dec_ticket->enc_part2.
 The storage of dec_ticket->enc_part2 will be allocated before return.

 returns errors from encryption routines, system errors

*/

krb5_error_code
krb5_decrypt_tkt_part(context, srv_key, ticket)
    krb5_context context;
    const krb5_keyblock *srv_key;
    register krb5_ticket *ticket;
{
    krb5_enc_tkt_part *dec_tkt_part;
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_error_code retval;

    if (!valid_enctype(ticket->enc_part.enctype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* put together an eblock for this encryption */
    krb5_use_enctype(context, &eblock, ticket->enc_part.enctype);

    scratch.length = ticket->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(ticket->enc_part.ciphertext.length)))
	return(ENOMEM);

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(context, &eblock, srv_key)) {
	free(scratch.data);
	return(retval);
    }

    /* call the encryption routine */
    if (retval = krb5_decrypt(context, 
			      (krb5_pointer) ticket->enc_part.ciphertext.data,
			      (krb5_pointer) scratch.data, scratch.length, 
			      &eblock, 0)) {
	(void) krb5_finish_key(context, &eblock);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {memset(scratch.data, 0, scratch.length); \
free(scratch.data);}
    retval = krb5_finish_key(context, &eblock);
    if (retval) {

	clean_scratch();
	return retval;
    }
    /*  now decode the decrypted stuff */
    retval = decode_krb5_enc_tkt_part(&scratch, &dec_tkt_part);
    if (!retval) {
	ticket->enc_part2 = dec_tkt_part;
    }
    clean_scratch();
    return retval;
}
