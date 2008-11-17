/*
 * lib/crypto/dk/dk_ccm.c
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
#include "dk.h"
#include "aead.h"

/*
 * Implement AEAD_AES_{128,256}_CCM as described in section 5.3 of RFC 5116.
 *
 * This is the CCM mode as described in NIST 800-38C, with a 12 byte nonce
 * and 16 byte checksum. Multiple buffers of the same type are logically
 * concatenated.
 *
 * The IOV should be laid out as follows:
 *
 *    HEADER | SIGN_DATA | DATA | PADDING | TRAILER
 *
 * SIGN_DATA and PADDING may be absent.
 *
 * Upon decryption, one can pass in explicit buffers as for encryption, or
 * one can pass in STREAM, being the concatenation of HEADER | DATA | TRAILER.
 *
 *    STREAM | SIGN_DATA | DATA
 *
 * Upon output, DATA will contain a pointer into the STREAM buffer with the
 * decrypted payload. SIGN_DATA should be ordered relative to the output DATA
 * buffer as it was upon encryption.
 *
 * For compatibility with RFC 5116, a single key is used both for encryption
 * and checksumming. The key derivation function is as follows:
 *
 *    Kc = DK(base-key, usage | 0xCC)
 *
 * Because the base keys are compatible with RFC 3962, the two encryption
 * types defined here (ENCTYPE_AES128_CCM_128 and ENCTYPE_AES256_CCM_128)
 * are most useful in conjunction with a cryptosystem negotiation protocol
 * such as RFC 4537.
 */

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

#define CCM_FLAG_MASK_Q		0x07
#define CCM_FLAG_MASK_T		0x38
#define CCM_FLAG_ADATA		0x40
#define CCM_FLAG_RESERVED	0x80

#define CCM_NONCE_LENGTH	12
#define CCM_COUNTER_LENGTH	3

static krb5_error_code
krb5int_ccm_crypto_length(const struct krb5_aead_provider *aead,
			  const struct krb5_enc_provider *enc,
			  const struct krb5_hash_provider *hash,
			  krb5_cryptotype type,
			  unsigned int *length)
{
    assert(enc->block_size >= 16);

    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = 16;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	*length = 0; /* CTR mode requires no padding */
	break;
    case KRB5_CRYPTO_TYPE_TRAILER:
    case KRB5_CRYPTO_TYPE_CHECKSUM:
	*length = enc->block_size;
	break;
    default:
	assert(0 && "invalid cryptotype passed to krb5int_ccm_crypto_length");
	break;
    }

    return 0;
}

static krb5_error_code
encode_a_len(krb5_data *a, unsigned int adata_len)
{
    size_t len;
    unsigned char *p;

    if (adata_len > (1 << 16) - (1 << 8))
	len = 6;
    else if (adata_len > 0)
	len = 2;
    else
	len = 0;

    if (a->length < len)
	return KRB5_BAD_MSIZE;

    p = (unsigned char *)a->data;

    switch (len) {
    case 2:
	p[0] = (adata_len >> 8) & 0xFF;
	p[1] = (adata_len     ) & 0xFF;
	break;
    case 6:
	p[0] = 0xFF;
	p[1] = 0xFE;
	p[2] = (adata_len >> 24) & 0xFF;
	p[3] = (adata_len >> 16) & 0xFF;
	p[4] = (adata_len >> 8 ) & 0xFF;
	p[5] = (adata_len      ) & 0xFF;
	break;
    }

    a->length = len;

    return 0;
}

static krb5_error_code
krb5int_ccm_encrypt_iov(const struct krb5_aead_provider *aead,
			const struct krb5_enc_provider *enc,
			const struct krb5_hash_provider *hash,
			const krb5_keyblock *key,
			krb5_keyusage usage,
			const krb5_data *iv,
			krb5_crypto_iov *data,
			size_t num_data)
{
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    krb5_keyblock kc;
    size_t i;
    unsigned int header_len = 0;
    unsigned int trailer_len = 0;
    unsigned int payload_len = 0;
    unsigned int adata_len = 0;
    unsigned char flags = 0;
    krb5_data nonce, cksum, ivec;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;
    char adata_len_buf[6];

    kc.contents = NULL;
    kc.length = 0;

    ivec.data = NULL;
    ivec.length = 0;

    cksum.data = NULL;
    cksum.length = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    if (ret != 0)
	return ret;

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL)
	return KRB5_BAD_MSIZE;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &trailer_len);
    if (ret != 0)
	return ret;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length < trailer_len)
	return KRB5_BAD_MSIZE;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	switch (iov->flags) {
	case KRB5_CRYPTO_TYPE_DATA:
	    payload_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	    adata_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_PADDING:
	    iov->data.length = 0;
	    break;
	default:
	    break;
	}
    }

    if (header != &data[0] || header->data.length < enc->block_size)
	return KRB5_BAD_MSIZE;
	
    /* RFC 5116 5.3, format flags octet */
    flags = CCM_COUNTER_LENGTH - 1; /* q=3 */
    flags |= (((trailer_len - 2) / 2) << 3);
    if (adata_len != 0)
	flags |= CCM_FLAG_ADATA;

    header->data.data[0] = flags;

    nonce.data = &header->data.data[1];
    nonce.length = CCM_NONCE_LENGTH;

    if (iv != NULL) {
	/* iv should be NONCE | COUNTER */
	if (iv->length != nonce.length) {
	    ret = KRB5_BAD_MSIZE;
	    goto cleanup;
	}
	memcpy(nonce.data, iv->data, iv->length);
    } else {
	ret = krb5_c_random_make_octets(/* XXX */ NULL, &nonce);
	if (ret != 0)
	    goto cleanup;
    }

    if (payload_len > 0xFFFFFF) {
	ret = KRB5_BAD_MSIZE;
	goto cleanup;
    }

    header->data.data[13] = (payload_len >> 16) & 0xFF;
    header->data.data[14] = (payload_len >> 8 ) & 0xFF;
    header->data.data[15] = (payload_len      ) & 0xFF;

    sign_data = (krb5_crypto_iov *)calloc(num_data + 1, sizeof(krb5_crypto_iov));
    if (sign_data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    sign_data[0] = *header;

    /* Include length of associated data in CBC-MAC */
    sign_data[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[1].data.data = adata_len_buf;
    sign_data[1].data.length = sizeof(adata_len_buf);
    ret = encode_a_len(&sign_data[1].data, adata_len);
    if (ret != 0)
	goto cleanup;

    memcpy(&sign_data[2], &data[1], (num_data - 1) * sizeof(krb5_crypto_iov));

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage >> 24) & 0xFF;
    d1.data[1] = (usage >> 16) & 0xFF;
    d1.data[2] = (usage >> 8 ) & 0xFF;
    d1.data[3] = (usage      ) & 0xFF;

    d1.data[4] = 0xCC;

    kc.length = enc->keylength;
    kc.contents = malloc(kc.length);
    if (kc.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    ret = krb5_derive_key(enc, key, &kc, &d1);
    if (ret != 0)
	goto cleanup;

    assert(enc->encrypt_iov != NULL);

    cksum.data = malloc(trailer_len);
    if (cksum.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum.length = trailer_len;

    ret = krb5int_c_mandatory_cksumtype(NULL, key->enctype, &cksumtype);
    if (ret != 0)
	goto cleanup;

    keyhash = krb5int_c_find_checksum_type(cksumtype);
    if (keyhash == NULL) {
	ret = KRB5_BAD_ENCTYPE;
	goto cleanup;
    }

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, sign_data, num_data + 1, &cksum);
    if (ret != 0)
	goto cleanup;

    /* Setup counter */
    ivec.data = malloc(enc->block_size);
    if (ivec.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ivec.length = enc->block_size;

    ivec.data[0] = flags;
    memcpy(&ivec.data[1], nonce.data, nonce.length); /* Copy in nonce */
    memset(&ivec.data[1 + nonce.length], 0, CCM_COUNTER_LENGTH); /* Set counter to zero */

    trailer->data.length = trailer_len;

    /* Encrypt checksum and place in trailer */
    ret = enc->encrypt(&kc, &ivec, &cksum, &trailer->data);
    if (ret != 0)
	goto cleanup;

    /* Don't encrypt B0 (header), but encrypt everything else */
    ret = enc->encrypt_iov(&kc, &ivec, data, num_data);
    if (ret != 0)
	goto cleanup;

cleanup:
    if (kc.contents != NULL) {
	zap(kc.contents, kc.length);
	free(kc.contents);
    }
    if (cksum.data != NULL) {
	free(cksum.data);
    }
    if (ivec.data != NULL) {
	zap(ivec.data, ivec.length);
	free(ivec.data);
    }
    if (sign_data != NULL) {
	free(sign_data);
    }

    return ret;
}

static krb5_error_code
krb5int_ccm_decrypt_iov(const struct krb5_aead_provider *aead,
			const struct krb5_enc_provider *enc,
			const struct krb5_hash_provider *hash,
			const krb5_keyblock *key,
			krb5_keyusage usage,
			const krb5_data *iv,
			krb5_crypto_iov *data,
			size_t num_data)
{
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    krb5_keyblock kc;
    size_t i;
    unsigned int header_len = 0;
    unsigned int trailer_len = 0;
    unsigned int actual_adata_len = 0, actual_payload_len = 0;
    unsigned int payload_len = 0;
    unsigned char flags = 0;
    krb5_data cksum, ivec;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;
    char adata_len_buf[6];

    kc.contents = NULL;
    kc.length = 0;

    ivec.data = NULL;
    ivec.length = 0;

    cksum.data = NULL;
    cksum.length = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    if (ret != 0)
	return ret;

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header != &data[0])
	return KRB5_BAD_MSIZE;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &trailer_len);
    if (ret != 0)
	return ret;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length != trailer_len)
	return KRB5_BAD_MSIZE;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	switch (iov->flags) {
	case KRB5_CRYPTO_TYPE_DATA:
	    actual_payload_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	    actual_adata_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_PADDING:
	    if (iov->data.length != 0)
		return KRB5_BAD_MSIZE;
	    break;
	default:
	    break;
	}
    }

    if (actual_payload_len > 0xFFFFFF)
	return KRB5_BAD_MSIZE;

    if (header->data.length < enc->block_size)
	return KRB5_BAD_MSIZE;

    flags = header->data.data[0];

    if ((flags & CCM_FLAG_RESERVED) != 0) {
	return KRB5_BAD_MSIZE;
    }
    if ((flags & CCM_FLAG_MASK_Q) != CCM_COUNTER_LENGTH - 1) {
	/* Check q=3 */
	return KRB5_BAD_MSIZE;
    }
    if ((unsigned int)(flags & CCM_FLAG_MASK_T) >> 3 != (trailer->data.length - 2) / 2) {
	/* Check bits 3-5 contain (trailer_len-2)/2 */
	return KRB5_BAD_MSIZE;
    }
    if ((flags & CCM_FLAG_ADATA) != (actual_adata_len ? CCM_FLAG_ADATA : 0)) {
	/* Check that AData flag matches presence of associated data */
	return KRB5_BAD_MSIZE;
    }

    payload_len  = (header->data.data[13] << 16);
    payload_len |= (header->data.data[14] << 8 );
    payload_len |= (header->data.data[15]      );

    if (payload_len > actual_payload_len)
	return KRB5_BAD_MSIZE;

    sign_data = (krb5_crypto_iov *)calloc(num_data + 1, sizeof(krb5_crypto_iov));
    if (sign_data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    sign_data[0] = *header;

    /* Include length of associated data in CBC-MAC */
    sign_data[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[1].data.data = adata_len_buf;
    sign_data[1].data.length = sizeof(adata_len_buf);
    ret = encode_a_len(&sign_data[1].data, actual_adata_len);
    if (ret != 0)
	goto cleanup;

    d1.data = (char *)constantdata;
    d1.length = K5CLENGTH;

    d1.data[0] = (usage >> 24) & 0xFF;
    d1.data[1] = (usage >> 16) & 0xFF;
    d1.data[2] = (usage >> 8 ) & 0xFF;
    d1.data[3] = (usage      ) & 0xFF;

    d1.data[4] = 0xCC;

    kc.length = enc->keylength;
    kc.contents = malloc(kc.length);
    if (kc.contents == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    ret = krb5_derive_key(enc, key, &kc, &d1);
    if (ret != 0)
	goto cleanup;

    assert(enc->decrypt_iov != NULL);

    cksum.data = malloc(trailer_len);
    if (cksum.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum.length = trailer_len;

    /* Setup counter */
    ivec.data = malloc(enc->block_size);
    if (ivec.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ivec.length = enc->block_size;

    ivec.data[0] = flags;
    if (iv != NULL) {
	if (iv->length != CCM_NONCE_LENGTH) {
	    ret = KRB5_BAD_MSIZE;
	    goto cleanup;
	}
	memcpy(&ivec.data[1], iv->data, iv->length);
    } else
	memcpy(&ivec.data[1], &header->data.data[1], CCM_NONCE_LENGTH); /* Copy in nonce */
    memset(&ivec.data[1 + CCM_NONCE_LENGTH], 0, CCM_COUNTER_LENGTH); /* Set counter to zero */

    /* Decrypt checksum from trailer */
    ret = enc->decrypt(&kc, &ivec, &trailer->data, &trailer->data);
    if (ret != 0)
	goto cleanup;

    /* Don't decrypt B0 (header), but decrypt everything else */
    ret = enc->decrypt_iov(&kc, &ivec, data, num_data);
    if (ret != 0)
	goto cleanup;

    /* Now, calculate hash for comparison (including B0) */
    ret = krb5int_c_mandatory_cksumtype(NULL, key->enctype, &cksumtype);
    if (ret != 0)
	goto cleanup;

    keyhash = krb5int_c_find_checksum_type(cksumtype);
    if (keyhash == NULL) {
	ret = KRB5_BAD_ENCTYPE;
	goto cleanup;
    }

    memcpy(&sign_data[2], &data[1], (num_data - 1) * sizeof(krb5_crypto_iov));

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, sign_data, num_data + 1, &cksum);
    if (ret != 0)
	goto cleanup;

    if (cksum.length != trailer->data.length ||
	memcmp(cksum.data, trailer->data.data, trailer->data.length) != 0) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	goto cleanup;
    }

cleanup:
    if (kc.contents != NULL) {
	zap(kc.contents, kc.length);
	free(kc.contents);
    }
    if (cksum.data != NULL) {
	free(cksum.data);
    }
    if (ivec.data != NULL) {
	zap(ivec.data, ivec.length);
	free(ivec.data);
    }
    if (sign_data != NULL) {
	free(sign_data);
    }

    return ret;
}

const struct krb5_aead_provider krb5int_aead_ccm = {
    krb5int_ccm_crypto_length,
    krb5int_ccm_encrypt_iov,
    krb5int_ccm_decrypt_iov
};

