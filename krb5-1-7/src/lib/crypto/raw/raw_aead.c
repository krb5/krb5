/*
 * lib/crypto/raw/raw_aead.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


#include "k5-int.h"
#include "raw.h"
#include "aead.h"

/* AEAD */

static krb5_error_code
krb5int_raw_crypto_length(const struct krb5_aead_provider *aead,
			  const struct krb5_enc_provider *enc,
			  const struct krb5_hash_provider *hash,
			  krb5_cryptotype type,
			  unsigned int *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = enc->block_size;
	break;
    default:
	*length = 0;
	break;
    }

    return 0;
}

static krb5_error_code
krb5int_raw_encrypt_iov(const struct krb5_aead_provider *aead,
			const struct krb5_enc_provider *enc,
			const struct krb5_hash_provider *hash,
			const krb5_keyblock *key,
			krb5_keyusage usage,
			const krb5_data *ivec,
			krb5_crypto_iov *data,
			size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *padding;
    size_t i;
    unsigned int blocksize = 0;
    unsigned int plainlen = 0;
    unsigned int padsize = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &blocksize);
    if (ret != 0)
	return ret;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA)
	    plainlen += iov->data.length;
    }

    if (blocksize != 0) {
	/* Check that the input data is correctly padded */
	if (plainlen % blocksize)
	    padsize = blocksize - (plainlen % blocksize);
    }

    padding = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_PADDING);
    if (padsize && (padding == NULL || padding->data.length < padsize))
	return KRB5_BAD_MSIZE;

    if (padding != NULL) {
	memset(padding->data.data, 0, padsize);
	padding->data.length = padsize;
    }

    assert(enc->encrypt_iov != NULL);

    ret = enc->encrypt_iov(key, ivec, data, num_data); /* will update ivec */

    return ret;
}

static krb5_error_code
krb5int_raw_decrypt_iov(const struct krb5_aead_provider *aead,
			const struct krb5_enc_provider *enc,
			const struct krb5_hash_provider *hash,
			const krb5_keyblock *key,
			krb5_keyusage usage,
			const krb5_data *ivec,
			krb5_crypto_iov *data,
			size_t num_data)
{
    krb5_error_code ret;
    size_t i;
    unsigned int blocksize = 0; /* careful, this is enc block size not confounder len */
    unsigned int cipherlen = 0;

    if (krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM) != NULL) {
	return krb5int_c_iov_decrypt_stream(aead, enc, hash, key,
					    usage, ivec, data, num_data);
    }


    /* E(Confounder | Plaintext | Pad) | Checksum */

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &blocksize);
    if (ret != 0)
	return ret;

    for (i = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (ENCRYPT_DATA_IOV(iov))
	    cipherlen += iov->data.length;
    }

    if (blocksize == 0) {
	/* Check for correct input length in CTS mode */
	if (enc->block_size != 0 && cipherlen < enc->block_size)
	    return KRB5_BAD_MSIZE;
    } else {
	/* Check that the input data is correctly padded */
	if ((cipherlen % blocksize) != 0)
	    return KRB5_BAD_MSIZE;
    }

    /* Validate header and trailer lengths */

    /* derive the keys */

    /* decrypt the plaintext (header | data | padding) */
    assert(enc->decrypt_iov != NULL);

    ret = enc->decrypt_iov(key, ivec, data, num_data); /* will update ivec */

    return ret;
}

const struct krb5_aead_provider krb5int_aead_raw = {
    krb5int_raw_crypto_length,
    krb5int_raw_encrypt_iov,
    krb5int_raw_decrypt_iov
};
