/*
 * lib/crypto/arcfour/arcfour_aead.c
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
#include "arcfour.h"
#include "arcfour-int.h"
#include "aead.h"

/* AEAD */

static krb5_error_code
krb5int_arcfour_crypto_length(const struct krb5_aead_provider *aead,
			      const struct krb5_enc_provider *enc,
			      const struct krb5_hash_provider *hash,
			      krb5_cryptotype type,
			      size_t *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = CONFOUNDERLENGTH;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = enc->block_size;
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = hash->hashsize;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_arcfour_crypto_length");
	break;
    }

    return 0;
}

static krb5_error_code
alloc_derived_key(const struct krb5_enc_provider *enc,
		  krb5_keyblock *dst,
		  krb5_data *data,
		  const krb5_keyblock *src)
{
    data->length = enc->keybytes;
    data->data = malloc(data->length);
    if (data->data == NULL)
	return ENOMEM;

    *dst = *src;
    dst->length = data->length;
    dst->contents = (void *)data->data;

    return 0;
}

static krb5_error_code
krb5int_arcfour_encrypt_iov(const struct krb5_aead_provider *aead,
			    const struct krb5_enc_provider *enc,
			    const struct krb5_hash_provider *hash,
			    const krb5_keyblock *key,
			    krb5_keyusage usage,
			    const krb5_data *ivec,
			    krb5_crypto_iov *data,
			    size_t num_data)
{
    krb5_error_code ret;
    krb5_crypto_iov *header, *trailer, *padding;
    size_t i, j, num_sign_data;
    krb5_keyblock k1, k2, k3;
    krb5_data d1, d2, d3;
    krb5_keyusage ms_usage;
    char salt_data[14];
    krb5_data salt;
    krb5_data *sign_data = NULL;

    d1.length = d2.length = d3.length = 0;
    d1.data = d2.data = d3.data = NULL;

    /*
     * Caller must have provided space for the header, padding
     * and trailer; per RFC 4757 we will arrange it as:
     *
     *	    Checksum | E(Confounder | Plaintext) 
     *
     * There is no pad required, but if one is provided we will
     * set it to the pad value as would be done in GSS.
     */

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length != CONFOUNDERLENGTH)
	return KRB5_BAD_MSIZE;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || header->data.length != hash->hashsize)
	return KRB5_BAD_MSIZE;

    padding = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_PADDING);
    if (padding != NULL)
	memset(padding->data.data, padding->data.length & 0xFF, padding->data.length);

    ret = alloc_derived_key(enc, &k1, &d1, key);
    if (ret != 0)
	goto cleanup;

    ret = alloc_derived_key(enc, &k2, &d2, key);
    if (ret != 0)
	goto cleanup;

    ret = alloc_derived_key(enc, &k3, &d3, key);
    if (ret != 0)
	goto cleanup;

    /* Begin the encryption, compute K1 */
    salt.data = salt_data;
    salt.length = sizeof(salt_data);

    ms_usage = krb5int_arcfour_translate_usage(usage);

    if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
	strncpy(salt.data, krb5int_arcfour_l40, salt.length);
	store_32_le(ms_usage, salt.data + 10);
    } else {
	salt.length = 4;
	store_32_le(ms_usage, salt.data);
    }
    krb5_hmac(hash, key, 1, &salt, &d1);
    memcpy(k2.contents, k1.contents, k2.length);

    if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP)
	memset(k1.contents + 7, 0xAB, 9);

    ret = krb5_c_random_make_octets(0, &header->data);
    if (ret != 0)
	goto cleanup;

    /* Create a checksum over all the data to be signed */
    for (i = 0, num_sign_data = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA ||
	    iov->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    num_sign_data++;
    }
    sign_data = (krb5_data *)calloc(num_sign_data, sizeof(krb5_data));
    if (sign_data == NULL)
	goto cleanup;

    for (i = 0, j = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA ||
	    iov->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY) {
	    sign_data[j++] = iov[i].data;
	}
    }

    krb5_hmac(hash, &k2, 1, sign_data, &trailer->data);

    krb5_hmac(hash, &k1, 1, &trailer->data, &d3);

    ret = enc->encrypt_iov(&k3, ivec, data);

cleanup:
    if (d1.data != NULL) {
	memset(d1.data, 0, d1.length);
	free(d1.data);
    }
    if (d2.data != NULL) {
	memset(d2.data, 0, d2.length);
	free(d2.data);
    }
    if (d3.data != NULL) {
	memset(d3.data, 0, d3.length);
	free(d3.data);
    }
    if (sign_data != NULL) {
	free(sign_data);
    }

    return ret;
}

static krb5_error_code
krb5int_arcfour_decrypt_iov(const struct krb5_aead_provider *aead,
			    const struct krb5_enc_provider *enc,
			    const struct krb5_hash_provider *hash,
			    const krb5_keyblock *key,
			    krb5_keyusage keyusage,
			    const krb5_data *ivec,
			    krb5_crypto_iov *data,
			    size_t num_data)
{
}

const struct krb5_aead_provider krb5int_aead_arcfour = {
    krb5int_arcfour_crypto_length,
    krb5int_arcfour_encrypt_iov,
    krb5int_arcfour_decrypt_iov
};

