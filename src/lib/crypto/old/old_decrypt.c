/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "old.h"

krb5_error_code
krb5_old_decrypt(enc, hash, key, usage, ivec, input, arg_output)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_data *input;
     krb5_data *arg_output;
{
    krb5_error_code ret;
    size_t blocksize, hashsize, plainsize;
    unsigned char *plaintext, *cksumdata;
    krb5_data output, cksum;
    int alloced;

    (*(enc->block_size))(&blocksize);
    (*(hash->hash_size))(&hashsize);

    plainsize = input->length - blocksize - hashsize;

    if (arg_output->length < plainsize)
	return(KRB5_BAD_MSIZE);

    /* if there's enough space to work in the app buffer, use it,
       otherwise allocate our own */

    if ((cksumdata = (unsigned char *) malloc(hashsize)) == NULL)
	return(ENOMEM);

    if (arg_output->length < input->length) {
	output.length = input->length;

	if ((output.data = (krb5_octet *) malloc(output.length)) == NULL) {
	    free(cksumdata);
	    return(ENOMEM);
	}

	alloced = 1;
    } else {
	output.length = input->length;

	output.data = arg_output->data;

	alloced = 0;
    }

    /* decrypt it */

    if (ret = ((*(enc->decrypt))(key, ivec, input, &output)))
	goto cleanup;

    /* verify the checksum */

    memcpy(cksumdata, output.data+blocksize, hashsize);
    memset(output.data+blocksize, 0, hashsize);

    cksum.length = hashsize;
    cksum.data = output.data+blocksize;

    if (ret = ((*(hash->hash))(1, &output, &cksum)))
	goto cleanup;

    if (memcmp(cksum.data, cksumdata, cksum.length) != 0) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	goto cleanup;
    }

    /* copy the plaintext around */

    if (alloced) {
	memcpy(arg_output->data, output.data+blocksize+hashsize,
	       plainsize);
    } else {
	memmove(arg_output->data, arg_output->data+blocksize+hashsize,
		plainsize);
    }
    arg_output->length = plainsize;

    ret = 0;

cleanup:
    if (alloced) {
	memset(output.data, 0, output.length);
	free(output.data);
    }

    memset(cksumdata, 0, hashsize);
    free(cksumdata);
    return(ret);
}

