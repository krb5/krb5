/*
 * lib/crypto/dk/dk_aead.c
 *
 * Copyright 2008, 2009 by the Massachusetts Institute of Technology.
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
#include "dk.h"
#include "aead.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

/* AEAD */

static krb5_error_code
krb5int_dk_crypto_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 krb5_cryptotype type,
			 unsigned int *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = enc->block_size;
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = hash->hashsize;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_dk_crypto_length");
	break;
    }

    return 0;
}

static krb5_error_code
krb5int_dk_encrypt_iov(const struct krb5_aead_provider *aead,
		       const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       const krb5_keyblock *key,
		       krb5_keyusage usage,
		       const krb5_data *ivec,
		       krb5_crypto_iov *data,
		       size_t num_data)
{
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1, d2;
    krb5_crypto_iov *header, *trailer, *padding;
    krb5_keyblock ke, ki;
    size_t i;
    unsigned int blocksize = 0;
    unsigned int plainlen = 0;
    unsigned int hmacsize = 0;
    unsigned int padsize = 0;
    unsigned char *cksum = NULL;

    ke.contents = ki.contents = NULL;
    ke.length = ki.length = 0;

    /* E(Confounder | Plaintext | Pad) | Checksum */

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &blocksize);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &hmacsize);
    if (ret != 0)
	return ret;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA)
	    plainlen += iov->data.length;
    }

    /* Validate header and trailer lengths. */

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length < enc->block_size)
	return KRB5_BAD_MSIZE;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length < hmacsize)
	return KRB5_BAD_MSIZE;

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

    ke.length = enc->keylength;
    ke.contents = malloc(ke.length);
    if (ke.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ki.length = enc->keylength;
    ki.contents = malloc(ki.length);
    if (ki.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum = (unsigned char *)malloc(hash->hashsize);
    if (cksum == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    /* derive the keys */

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    store_32_be(usage, constantdata);

    d1.data[4] = 0xAA;

    ret = krb5_derive_key(enc, key, &ke, &d1);
    if (ret != 0)
	goto cleanup;

    d1.data[4] = 0x55;

    ret = krb5_derive_key(enc, key, &ki, &d1);
    if (ret != 0)
	goto cleanup;

    /* generate confounder */

    header->data.length = enc->block_size;

    ret = krb5_c_random_make_octets(/* XXX */ NULL, &header->data);
    if (ret != 0)
	goto cleanup;

    /* hash the plaintext */
    d2.length = hash->hashsize;
    d2.data = (char *)cksum;

    ret = krb5int_hmac_iov(hash, &ki, data, num_data, &d2);
    if (ret != 0)
	goto cleanup;

    /* encrypt the plaintext (header | data | padding) */
    assert(enc->encrypt_iov != NULL);

    ret = enc->encrypt_iov(&ke, ivec, data, num_data); /* will update ivec */
    if (ret != 0)
	goto cleanup;

    /* possibly truncate the hash */
    assert(hmacsize <= d2.length);

    memcpy(trailer->data.data, cksum, hmacsize);
    trailer->data.length = hmacsize;

cleanup:
    if (ke.contents != NULL) {
	memset(ke.contents, 0, ke.length);
	free(ke.contents);
    }
    if (ki.contents != NULL) {
	memset(ki.contents, 0, ki.length);
	free(ki.contents);
    }
    if (cksum != NULL) {
	free(cksum);
    }

    return ret;
}

static krb5_error_code
krb5int_dk_decrypt_iov(const struct krb5_aead_provider *aead,
		       const struct krb5_enc_provider *enc,
		       const struct krb5_hash_provider *hash,
		       const krb5_keyblock *key,
		       krb5_keyusage usage,
		       const krb5_data *ivec,
		       krb5_crypto_iov *data,
		       size_t num_data)
{
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1;
    krb5_crypto_iov *header, *trailer;
    krb5_keyblock ke, ki;
    size_t i;
    unsigned int blocksize = 0; /* careful, this is enc block size not confounder len */
    unsigned int cipherlen = 0;
    unsigned int hmacsize = 0;
    unsigned char *cksum = NULL;

    if (krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM) != NULL) {
	return krb5int_c_iov_decrypt_stream(aead, enc, hash, key,
					    usage, ivec, data, num_data);
    }

    ke.contents = ki.contents = NULL;
    ke.length = ki.length = 0;

    /* E(Confounder | Plaintext | Pad) | Checksum */

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &blocksize);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &hmacsize);
    if (ret != 0)
	return ret;

    if (blocksize != 0) {
	/* Check that the input data is correctly padded. */
    for (i = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (ENCRYPT_IOV(iov))
	    cipherlen += iov->data.length;
    }
        if (cipherlen % blocksize != 0)
	    return KRB5_BAD_MSIZE;
    }

    /* Validate header and trailer lengths */

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length != enc->block_size)
	return KRB5_BAD_MSIZE;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length != hmacsize)
	return KRB5_BAD_MSIZE;

    ke.length = enc->keylength;
    ke.contents = malloc(ke.length);
    if (ke.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ki.length = enc->keylength;
    ki.contents = malloc(ki.length);
    if (ki.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum = (unsigned char *)malloc(hash->hashsize);
    if (cksum == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    /* derive the keys */

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    store_32_be(usage, constantdata);

    d1.data[4] = 0xAA;

    ret = krb5_derive_key(enc, key, &ke, &d1);
    if (ret != 0)
	goto cleanup;

    d1.data[4] = 0x55;

    ret = krb5_derive_key(enc, key, &ki, &d1);
    if (ret != 0)
	goto cleanup;

    /* decrypt the plaintext (header | data | padding) */
    assert(enc->decrypt_iov != NULL);

    ret = enc->decrypt_iov(&ke, ivec, data, num_data); /* will update ivec */
    if (ret != 0)
	goto cleanup;

    /* verify the hash */
    d1.length = hash->hashsize; /* non-truncated length */
    d1.data = (char *)cksum;

    ret = krb5int_hmac_iov(hash, &ki, data, num_data, &d1);
    if (ret != 0)
	goto cleanup;

    /* compare only the possibly truncated length */
    if (memcmp(cksum, trailer->data.data, hmacsize) != 0) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	goto cleanup;
    }

cleanup:
    if (ke.contents != NULL) {
	memset(ke.contents, 0, ke.length);
	free(ke.contents);
    }
    if (ki.contents != NULL) {
	memset(ki.contents, 0, ki.length);
	free(ki.contents);
    }
    if (cksum != NULL) {
	free(cksum);
    }

    return ret;
}

const struct krb5_aead_provider krb5int_aead_dk = {
    krb5int_dk_crypto_length,
    krb5int_dk_encrypt_iov,
    krb5int_dk_decrypt_iov
};

static krb5_error_code
krb5int_aes_crypto_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 krb5_cryptotype type,
			 unsigned int *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = enc->block_size;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = 0;
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = 96 / 8;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_aes_crypto_length");
	break;
    }

    return 0;
}

const struct krb5_aead_provider krb5int_aead_aes = {
    krb5int_aes_crypto_length,
    krb5int_dk_encrypt_iov,
    krb5int_dk_decrypt_iov
};

