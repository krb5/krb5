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
 * Again as required by the CCM specification, SIGN_DATA is processed before
 * DATA for the purpose of checksumming.
 *
 * Because the base keys are compatible with RFC 3962, the two encryption
 * types defined here (ENCTYPE_AES128_CCM_128 and ENCTYPE_AES256_CCM_128)
 * are most useful in conjunction with RFC 4537.
 */

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

#define CCM_FLAG_MASK_Q		0x07
#define CCM_FLAG_MASK_T		0x38
#define CCM_FLAG_ADATA		0x40
#define CCM_FLAG_RESERVED	0x80

static krb5_error_code
krb5int_ccm_crypto_length(const struct krb5_aead_provider *aead,
			  const struct krb5_enc_provider *enc,
			  const struct krb5_hash_provider *hash,
			  krb5_cryptotype type,
			  unsigned int *length)
{
    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = 12; /* RFC 5116 5.3 */
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
encode_a_len(krb5_data *a, krb5_ui_8 adata_len)
{
    size_t len;
    unsigned char *p;

    if (adata_len > (1LL << 32))
	len = 10;
    else if (adata_len > (1LL << 16) - (1LL << 8))
	len = 6;
    else if (adata_len)
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
    case 10:
	p[0] = 0xFF;
	p[1] = 0xFF;
	p[2] = (adata_len >> 56) & 0xFF;
	p[3] = (adata_len >> 48) & 0xFF;
	p[4] = (adata_len >> 40) & 0xFF;
	p[5] = (adata_len >> 32) & 0xFF;
	p[6] = (adata_len >> 24) & 0xFF;
	p[7] = (adata_len >> 16) & 0xFF;
	p[8] = (adata_len >> 8 ) & 0xFF;
	p[9] = (adata_len      ) & 0xFF;
	break;
    }

    a->length = len;

    return 0;
}

/*
 * format_B0() allows the tradeoff between nonce and payload length to
 * be parameterized by replacing the crypto_length() callback
 */
static krb5_error_code
format_B0(krb5_data *B0,	    /* B0 */
	  krb5_data *nonce,	    /* N */
	  size_t trailer_len,	    /* t */
	  krb5_ui_8 adata_len,	    /* a */
	  krb5_ui_8 payload_len)    /* Q */
{
    unsigned char flags;
    unsigned char *p;
    krb5_octet q, i = 0;

    if (B0->length != 16)
	return KRB5_BAD_MSIZE;

    /* SP800-38C A.1: Length Requirements */

    /* t is an elements of {4, 6, 8, 10, 12, 14, 16} */
    if (trailer_len % 2 ||
	(trailer_len < 4 || trailer_len > 16))
	return KRB5_BAD_MSIZE;

    /* n is an element of {7, 8, 9, 10, 11, 12, 13} */
    if (nonce->length < 7 || nonce->length > 13)
	return KRB5_BAD_MSIZE;

    q = 15 - nonce->length;

    /* P consists of fewer than 2^(8q) octets */
    if (payload_len >= (1UL << (8 * q)))
	return KRB5_BAD_MSIZE;

    /* SP800-38C A.1: Formatting of the Control Information and the Nonce */
    flags = q - 1;
    flags |= (((trailer_len - 2) / 2) << 3);
    if (adata_len != 0)
	flags |= CCM_FLAG_ADATA;

    p = (unsigned char *)B0->data;
    p[i++] = flags;

    memcpy(&p[i], nonce->data, nonce->length);
    i += nonce->length;

    for (; i < B0->length; i++) {
	register krb5_octet s;

	s = (q - (i - nonce->length)) * 8;

	p[i] = (payload_len >> s) & 0xFF;
    }

    return 0;
}

/*
 * format_Ctr0 is parameterized by extracting the flags octet from B0
 */
static krb5_error_code
format_Ctr0(krb5_data *Ctr0, krb5_data *B0)
{
    krb5_octet n; /* nonce length */
    krb5_octet q; /* counter length */

    assert(B0->length == 16);

    q = (B0->data[0] & CCM_FLAG_MASK_Q) + 1;

    Ctr0->data[0] = q - 1;

    n = 15 - q;

    assert(n >= 7 && n <= 13);

    memcpy(&Ctr0->data[1], &B0->data[1], n);
    memset(&Ctr0->data[1 + n], 0, q);

    return 0;
}
 
static krb5_error_code
krb5int_ccm_encrypt_iov(const struct krb5_aead_provider *aead,
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
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    krb5_keyblock kc;
    size_t i, num_sign_data = 0;
    unsigned int header_len = 0;
    unsigned int trailer_len = 0;
    size_t payload_len = 0;
    size_t adata_len = 0;
    krb5_data cksum, counter;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;
    char adata_len_buf[6];
    unsigned char B0[16], Ctr[16];

    kc.contents = NULL;
    kc.length = 0;

    cksum.data = NULL;
    cksum.length = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    if (ret != 0)
	return ret;

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length < header_len)
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

    header->data.length = header_len;

    ret = krb5_c_random_make_octets(/* XXX */ NULL, &header->data);
    if (ret != 0)
	goto cleanup;

    sign_data = (krb5_crypto_iov *)calloc(num_data + 1, sizeof(krb5_crypto_iov));
    if (sign_data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data.data = (char *)B0;
    sign_data[num_sign_data].data.length = sizeof(B0);
    ret = format_B0(&sign_data[num_sign_data].data, &header->data, trailer_len,
		    (krb5_ui_8)adata_len, (krb5_ui_8)payload_len);
    if (ret != 0)
	goto cleanup;
    num_sign_data++;

    /* Include length of associated data in CBC-MAC */
    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[num_sign_data].data.data = adata_len_buf;
    sign_data[num_sign_data].data.length = sizeof(adata_len_buf);
    ret = encode_a_len(&sign_data[num_sign_data].data, (krb5_ui_8)adata_len);
    if (ret != 0)
	goto cleanup;
    num_sign_data++;

    /* Reorder input IOV so SIGN_ONLY data is before DATA */
    for (i = 0; i < num_data; i++) {
	if (data[i].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    sign_data[num_sign_data++] = data[i];
    }
    for (i = 0; i < num_data; i++) {
	if (data[i].flags == KRB5_CRYPTO_TYPE_DATA)
	    sign_data[num_sign_data++] = data[i];
    }

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

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, sign_data, num_sign_data, &cksum);
    if (ret != 0)
	goto cleanup;

    /* Initialize first counter block */
    if (ivec == NULL) {
	counter.length = sizeof(Ctr);
	counter.data = (char *)Ctr;

	ret = format_Ctr0(&counter, &sign_data[0].data);
	if (ret != 0)
	    goto cleanup;

	ivec = &counter;
    }

    trailer->data.length = trailer_len;

    /* Encrypt checksum and place in trailer */
    ret = enc->encrypt(&kc, ivec, &cksum, &trailer->data);
    if (ret != 0)
	goto cleanup;

    /* Don't encrypt B0 (header), but encrypt everything else */
    ret = enc->encrypt_iov(&kc, ivec, data, num_data);
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
			const krb5_data *ivec,
			krb5_crypto_iov *data,
			size_t num_data)
{
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data d1;
    krb5_crypto_iov *header, *trailer, *sign_data = NULL;
    krb5_keyblock kc;
    size_t i, num_sign_data = 0;
    unsigned int header_len = 0;
    unsigned int trailer_len = 0;
    size_t adata_len = 0;
    size_t payload_len = 0;
    krb5_data cksum, counter;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;
    char adata_len_buf[6];
    unsigned char B0[16], Ctr[16];

    kc.contents = NULL;
    kc.length = 0;

    cksum.data = NULL;
    cksum.length = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    if (ret != 0)
	return ret;

    header = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_HEADER);
    if (header == NULL || header->data.length != header_len)
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
	    payload_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	    adata_len += iov->data.length;
	    break;
	case KRB5_CRYPTO_TYPE_PADDING:
	    if (iov->data.length != 0)
		return KRB5_BAD_MSIZE;
	    break;
	default:
	    break;
	}
    }

    sign_data = (krb5_crypto_iov *)calloc(num_data + 1, sizeof(krb5_crypto_iov));
    if (sign_data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }

    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_HEADER;
    sign_data[num_sign_data].data.data = (char *)B0;
    sign_data[num_sign_data].data.length = sizeof(B0);
    ret = format_B0(&sign_data[num_sign_data].data, &header->data, trailer_len,
		    (krb5_ui_8)adata_len, (krb5_ui_8)payload_len);
    if (ret != 0)
	goto cleanup;
    num_sign_data++;

    /* Include length of associated data in CBC-MAC */
    sign_data[num_sign_data].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    sign_data[num_sign_data].data.data = adata_len_buf;
    sign_data[num_sign_data].data.length = sizeof(adata_len_buf);
    ret = encode_a_len(&sign_data[num_sign_data].data, (krb5_ui_8)adata_len);
    if (ret != 0)
	goto cleanup;
    num_sign_data++;

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

    /* Initialize first counter block */
    if (ivec == NULL) {
	counter.length = sizeof(Ctr);
	counter.data = (char *)Ctr;

	ret = format_Ctr0(&counter, &sign_data[0].data);
	if (ret != 0)
	    goto cleanup;

	ivec = &counter;
    }

    /* Decrypt checksum from trailer */
    ret = enc->decrypt(&kc, ivec, &trailer->data, &trailer->data);
    if (ret != 0)
	goto cleanup;

    /* Don't decrypt B0 (header), but decrypt everything else */
    ret = enc->decrypt_iov(&kc, ivec, data, num_data);
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

    /* Reorder input IOV so SIGN_ONLY data is before DATA */
    for (i = 0; i < num_data; i++) {
	if (data[i].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    sign_data[num_sign_data++] = data[i];
    }
    for (i = 0; i < num_data; i++) {
	if (data[i].flags == KRB5_CRYPTO_TYPE_DATA)
	    sign_data[num_sign_data++] = data[i];
    }

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, sign_data, num_sign_data, &cksum);
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

