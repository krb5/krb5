/*
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"

/*
 * This routine takes a key and a krb5_data structure as input, and
 * outputs the encrypted data in a krb5_enc_data structure.  Note that
 * the krb5_enc_data structure is not allocated, and the kvno field is
 * not filled in.
 */
krb5_error_code
krb5_encrypt_data(context, key, ivec, data, enc_data)
    krb5_context	context;
    krb5_keyblock *	key;
    krb5_pointer	ivec;
    krb5_data *		data;
    krb5_enc_data *	enc_data;
{
    krb5_error_code	retval;
    krb5_encrypt_block	eblock;

    krb5_use_enctype(context, &eblock, key->enctype);

    enc_data->magic = KV5M_ENC_DATA;
    enc_data->kvno = 0;
    enc_data->enctype = key->enctype;
    enc_data->ciphertext.length = krb5_encrypt_size(data->length,
						    eblock.crypto_entry);
    enc_data->ciphertext.data = malloc(enc_data->ciphertext.length);
    if (enc_data->ciphertext.data == 0)
	return ENOMEM;

    if ((retval = krb5_process_key(context, &eblock, key)) != 0)
	goto cleanup;

    if ((retval = krb5_encrypt(context, (krb5_pointer) data->data,
			       (krb5_pointer) enc_data->ciphertext.data,
			       data->length, &eblock, ivec))) {
    	krb5_finish_key(context, &eblock);
        goto cleanup;
    }
    (void) krb5_finish_key(context, &eblock);

    return 0;

cleanup:
    free(enc_data->ciphertext.data);
    return retval;
}
    
