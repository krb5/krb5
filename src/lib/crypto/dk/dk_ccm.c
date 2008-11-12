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

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

#define CCM_FLAG_MASK_Q		0x07
#define CCM_FLAG_MASK_T		0x38
#define CCM_FLAG_ADATA		0x40
#define CCM_FLAG_RESERVED	0x80

/* AEAD */

static krb5_error_code
krb5int_ccm_crypto_length(const struct krb5_aead_provider *aead,
			  const struct krb5_enc_provider *enc,
			  const struct krb5_hash_provider *hash,
			  krb5_cryptotype type,
			  size_t *length)
{
    assert(enc->block_size == 16);

    switch (type) {
    case KRB5_CRYPTO_TYPE_HEADER:
	*length = enc->block_size + 6; /* this is a variable length header */
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
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

static krb5_error_code encode_a_len(krb5_data *header, size_t *a_len, size_t adata_len)
{
    size_t len;
    unsigned char *p;

    if (adata_len > (1 << 16) - (1 << 8))
	len = 6;
    else if (adata_len > 0)
	len = 2;
    else
	len = 0;

    if (header->length < 16 + len)
	return KRB5_BAD_MSIZE;

    p = (unsigned char *)header->data;

    switch (len) {
    case 2:
	p[16] = (adata_len >> 8) & 0xFF;
	p[17] = (adata_len     ) & 0xFF;
	break;
    case 6:
	p[16] = 0xFF;
	p[17] = 0xFE;
	p[18] = (adata_len >> 24) & 0xFF;
	p[19] = (adata_len >> 16) & 0xFF;
	p[20] = (adata_len >> 8 ) & 0xFF;
	p[21] = (adata_len      ) & 0xFF;
	break;
    }

    header->length = 16 + len;

    *a_len = len;

    return 0;
}

static krb5_error_code decode_a_len(krb5_data *header, size_t *a_len, size_t *adata_len)
{
    size_t len, len_len;
    unsigned char *p;

    if (header->length < 18) {
	return KRB5_BAD_MSIZE;
    }

    len = 0;
    len_len = 2;

    p = (unsigned char *)header->data;

    if (p[16] == 0xFF) {
	if (p[17] == 0xFF) {
	    return KRB5_BAD_MSIZE; /* too big */
	} else if (p[17] == 0xFE) {
	    len  = (p[18] << 24);
	    len |= (p[19] << 16);
	    len |= (p[20] << 8 );
	    len |= (p[21]      );

	    len_len += 4;
	} else {
	    len  = (p[16] << 8);
	    len |= (p[17]     );
	}
    } else {
	len  = (p[16] << 8);
	len |= (p[17]     );
    }

    *adata_len = len;

    if (a_len != NULL)
	*a_len = len_len;

    return 0;
}

/* ENCTYPE_AES128_CCM_128 and ENCTYPE_AES256_CCM_128 */

static krb5_error_code
k5_ccm_encrypt_iov(const struct krb5_aead_provider *aead,
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
    krb5_crypto_iov *header, *trailer, *adata = NULL, *adata_pad = NULL;
    krb5_keyblock kc;
    size_t i;
    size_t header_len = 0, blocksize = 0;
    size_t mac_len = 0;
    size_t a_len = 0, adata_len = 0, payload_len = 0;
    unsigned char flags = 0;
    krb5_data nonce, cksum, ivec;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;

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

    /* CCM specifies its own IV (nonce || counter) so not sure how to deal with user IVs */
    if (iv != NULL && iv->length != 0)
	return KRB5_BAD_MSIZE;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &mac_len);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &blocksize);
    if (ret != 0)
	return ret;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length < mac_len)
	return KRB5_BAD_MSIZE;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA)
	    payload_len += iov->data.length;
	else if (iov->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    adata_len += iov->data.length;
	else if (i > 0 &&
	    iov->flags == KRB5_CRYPTO_TYPE_PADDING &&
	    (data[i - 1].flags == KRB5_CRYPTO_TYPE_DATA ||
	     data[i - 1].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY))
	{
	    krb5_crypto_iov *data_to_pad = &data[i - 1];
	    size_t pad_len = 0;

	    /* We may need to adjust the pad once the adata length is known to
	     * account for the adata length encoding
	     */
	    if (data_to_pad->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY &&
		adata_pad == NULL) {
		if (iov->data.length < blocksize - 1)
		    return KRB5_BAD_MSIZE;

		adata = data_to_pad;
		adata_pad = iov;
	    }

	    /* Trim padding length */
	    if (data_to_pad->data.length % blocksize) {
		pad_len = blocksize - (data_to_pad->data.length % blocksize);

		if (iov->data.length < pad_len)
		    return KRB5_BAD_MSIZE;

		memset(iov->data.data, 0, pad_len);
	    }

	    iov->data.length = pad_len;
	}
    }

    if (header->data.length < enc->block_size)
	return KRB5_BAD_MSIZE;
	
    /* RFC 5116 5.3, format flags octet */
    flags = 2; /* q=3 */
    flags |= (((mac_len - 2) / 2) << 3);
    if (adata_len > 0)
	flags |= CCM_FLAG_ADATA;

    header->data.data[0] = flags;

    nonce.data = header->data.data + 1;
    nonce.length = 12;
    ret = krb5_c_random_make_octets(/* XXX */ NULL, &nonce);
    if (ret != 0)
	goto cleanup;

    if (payload_len > 0xFFFFFF)
	return KRB5_BAD_MSIZE;

    header->data.data[13] = (payload_len >> 16) & 0xFF;
    header->data.data[14] = (payload_len >> 8 ) & 0xFF;
    header->data.data[15] = (payload_len      ) & 0xFF;

    ret = encode_a_len(&header->data, &a_len, adata_len);
    if (ret != 0)
	return ret;

    /* Adjust first AData padding if necessary to account for encoding of adata length */
    if (flags & CCM_FLAG_ADATA) {
	size_t pad_len = 0;

	assert(adata != NULL);

	if (adata_pad == NULL)
	    return KRB5_BAD_MSIZE;

	if ((a_len + adata->data.length) % blocksize) {
	    pad_len = blocksize - ((a_len + adata->data.length) % blocksize);
	    memset(adata_pad->data.data, 0, pad_len);
	}
	adata_pad->data.length = pad_len;
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

    cksum.data = malloc(mac_len);
    if (cksum.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum.length = mac_len;

    ret = krb5int_c_mandatory_cksumtype(NULL, key->enctype, &cksumtype);
    if (ret != 0)
	goto cleanup;

    keyhash = krb5int_c_find_checksum_type(cksumtype);
    if (keyhash == NULL) {
	ret = KRB5_BAD_ENCTYPE;
	goto cleanup;
    }

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, data, num_data, &cksum);
    if (ret != 0)
	goto cleanup;

    /* Setup counter */
    ivec.data = malloc(enc->block_size);
    if (ivec.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ivec.length = enc->block_size;

    memcpy(ivec.data, header->data.data, 13); /* Copy in flags and nonce */
    memset(ivec.data + 13, 0, 3); /* Set counter to zero */

    trailer->data.length = mac_len;

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
    return ret;
}

static krb5_error_code
k5_ccm_decrypt_iov(const struct krb5_aead_provider *aead,
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
    krb5_crypto_iov *header, *trailer;
    krb5_keyblock kc;
    size_t i;
    size_t header_len = 0;
    size_t mac_len = 0;
    size_t actual_adata_len = 0, actual_payload_len = 0;
    size_t adata_len = 0, payload_len = 0;
    unsigned char flags = 0;
    krb5_data cksum, ivec;
    krb5_cksumtype cksumtype;
    const struct krb5_cksumtypes *keyhash;

    if (krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM) != NULL)
	return krb5int_c_iov_decrypt_stream(aead, enc, hash, key, usage, iv, data, num_data);

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

    /* CCM specifies its own IV (nonce || counter) so not sure how to deal with user IVs */
    if (iv != NULL && iv->length != 0)
	return KRB5_BAD_MSIZE;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &mac_len);
    if (ret != 0)
	return ret;

    trailer = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (trailer == NULL || trailer->data.length != mac_len)
	return KRB5_BAD_MSIZE;

    for (i = 0; i < num_data; i++) {
	krb5_crypto_iov *iov = &data[i];

	if (iov->flags == KRB5_CRYPTO_TYPE_DATA)
	    actual_payload_len += iov->data.length;
	else if (iov->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
	    actual_adata_len += iov->data.length;
    }

    if (actual_payload_len > 0xFFFFFF)
	return KRB5_BAD_MSIZE;

    if (header->data.length < enc->block_size)
	return KRB5_BAD_MSIZE;

    flags = header->data.data[0];

    if ((flags & CCM_FLAG_MASK_Q) != 2) {
	/* Check q=3 */
	return KRB5_BAD_MSIZE;
    }
    if ((flags & CCM_FLAG_MASK_T) >> 3 != (trailer->data.length - 2) / 2) {
	/* Check bits 3-5 contain (mac_len-2)/2 */
	return KRB5_BAD_MSIZE;
    }

    payload_len  = (header->data.data[13] << 16);
    payload_len |= (header->data.data[14] << 8 );
    payload_len |= (header->data.data[15]      );

    if (payload_len > actual_payload_len)
	return KRB5_BAD_MSIZE;

    if ((flags & CCM_FLAG_ADATA) != 0) {
	/* Adata flag set */
	ret = decode_a_len(&header->data, NULL, &adata_len);
	if (ret != 0)
	    return ret;
    } else
	adata_len = 0;

    if (adata_len > actual_adata_len)
	return KRB5_BAD_MSIZE;

    if ((flags & CCM_FLAG_RESERVED) != 0)
	return KRB5_BAD_MSIZE;

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

    cksum.data = malloc(mac_len);
    if (cksum.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    cksum.length = mac_len;

    /* Setup counter */
    ivec.data = malloc(enc->block_size);
    if (ivec.data == NULL) {
	ret = ENOMEM;
	goto cleanup;
    }
    ivec.length = enc->block_size;

    memcpy(ivec.data, header->data.data, 13); /* Copy in flags and nonce */
    memset(ivec.data + 13, 0, 3); /* Set counter to zero */

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

    ret = krb5int_c_make_checksum_iov(keyhash, &kc, usage, data, num_data, &cksum);
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
    return ret;
}

static krb5_error_code
k5_ccm_decrypt_iov_stream(const struct krb5_aead_provider *aead,
		          const struct krb5_enc_provider *enc,
		          const struct krb5_hash_provider *hash,
		          const krb5_keyblock *key,
		          krb5_keyusage usage,
		          const krb5_data *iv,
		          krb5_crypto_iov *data,
		          size_t num_data)
{
    krb5_crypto_iov iov[6];
    krb5_crypto_iov *stream, *payload, *adata;
    krb5_error_code ret;
    unsigned char flags;
    size_t a_len = 0, adata_len = 0;
    size_t payload_len = 0;
    size_t adata_pad = 0, payload_pad = 0;

    stream = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM);
    assert(stream != NULL);

    payload = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_DATA);
    if (payload == NULL)
	return EINVAL;

    adata = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_SIGN_ONLY);

    if (stream->data.length < enc->block_size /* B0 */ + enc->block_size /* MAC */)
	return KRB5_BAD_MSIZE;

    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data = stream->data;

    flags = iov[0].data.data[0];

    if ((flags & CCM_FLAG_MASK_Q) != 2) {
	/* Check q=3 */
	return KRB5_BAD_MSIZE;
    }
    if ((flags & CCM_FLAG_MASK_T) >> 3 != (enc->block_size - 2) / 2) {
	/* Check bits 3-5 contain (mac_len-2)/2 */
	return KRB5_BAD_MSIZE;
    }

    if (flags & CCM_FLAG_ADATA) {
	ret = decode_a_len(&iov[0].data, &a_len, &adata_len);
	if (ret != 0)
	    return ret;
    }

    assert(a_len < enc->block_size);

    if (adata_len && adata == NULL)
	return KRB5_BAD_MSIZE;

    iov[0].data.length = enc->block_size /* B0 */ + a_len; /* length of adata_len field */

    payload_len  = (iov[0].data.data[13] << 16);
    payload_len |= (iov[0].data.data[14] << 8 );
    payload_len |= (iov[0].data.data[15]      );

    if ((a_len + adata_len) % enc->block_size)
	adata_pad = enc->block_size - ((a_len + adata_len) % enc->block_size);
    if (payload_len % enc->block_size)
	payload_pad = enc->block_size - (payload_len % enc->block_size);

    if (stream->data.length < iov[0].data.length +
	adata_len + adata_pad +
	payload_len + payload_pad + enc->block_size)
	return KRB5_BAD_MSIZE;

    iov[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    iov[1].data.data = iov[0].data.data + iov[0].data.length;
    iov[1].data.length = adata_len;

    iov[2].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[2].data.data = iov[1].data.data + iov[1].data.length;
    iov[2].data.length = adata_pad;

    iov[3].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[3].data.data = iov[2].data.data + iov[2].data.length;
    iov[3].data.length = payload_len;

    iov[4].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[4].data.data = iov[3].data.data + iov[3].data.length;
    iov[4].data.length = payload_pad;

    iov[5].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[5].data.data = iov[4].data.data + iov[4].data.length;
    iov[5].data.length = enc->block_size;

    ret = k5_ccm_decrypt_iov(&krb5int_aead_ccm, enc, hash, key, usage, iv, iov, sizeof(iov)/sizeof(iov[0]));

    if (ret == 0) {
	if (adata != NULL)
	    *adata = iov[1];
	*payload = iov[3];
    }

    return ret;
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
    return k5_ccm_encrypt_iov(aead, enc, hash, key, usage, iv, data, num_data);
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
    if (krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM) != NULL)
	return k5_ccm_decrypt_iov_stream(aead, enc, hash, key, usage, iv, data, num_data);
    else
	return k5_ccm_decrypt_iov(aead, enc, hash, key, usage, iv, data, num_data);
}

const struct krb5_aead_provider krb5int_aead_ccm = {
    krb5int_ccm_crypto_length,
    krb5int_ccm_encrypt_iov,
    krb5int_ccm_decrypt_iov
};

void
krb5int_ccm_encrypt_length(const struct krb5_enc_provider *enc,
			   const struct krb5_hash_provider *hash,
			   size_t inputlen, size_t *length)
{
    /* pad */
    if ((inputlen % enc->block_size) != 0)
	inputlen += enc->block_size - (inputlen % enc->block_size);

    /* header | data | trailer */
    *length = enc->block_size + inputlen + enc->block_size;
}

krb5_error_code
krb5int_ccm_encrypt(const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key, krb5_keyusage usage,
		const krb5_data *ivec, const krb5_data *input,
		krb5_data *output)
{
    krb5_crypto_iov iov[4];
    size_t len = 0;
    krb5_error_code ret;

    krb5int_ccm_encrypt_length(enc, hash, input->length, &len);

    if (output->length < len)
	return KRB5_BAD_MSIZE;

    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data.data = output->data;
    iov[0].data.length = enc->block_size; /* a_len = 0 */

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.data = iov[0].data.data + iov[0].data.length;
    iov[1].data.length = input->length;
    memcpy(iov[1].data.data, input->data, input->length);

    iov[2].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[2].data.data = iov[1].data.data + iov[1].data.length;
    if (iov[1].data.length % enc->block_size)
	iov[2].data.length = enc->block_size - (iov[1].data.length % enc->block_size);
    else
	iov[2].data.length = 0;
    memset(iov[2].data.data, 0, iov[2].data.length);

    iov[3].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[3].data.data = iov[2].data.data + iov[2].data.length;
    iov[3].data.length = enc->block_size;

    ret = krb5int_ccm_encrypt_iov(&krb5int_aead_ccm, enc, hash, key, usage, ivec, iov, sizeof(iov)/sizeof(iov[0]));

    if (ret != 0)
	zap(output->data, output->length);

    return ret;
}

krb5_error_code
krb5int_ccm_decrypt(const struct krb5_enc_provider *enc,
		    const struct krb5_hash_provider *hash,
		    const krb5_keyblock *key, krb5_keyusage usage,
		    const krb5_data *ivec, const krb5_data *input,
		    krb5_data *output)
{
    krb5_crypto_iov iov[2];
    krb5_error_code ret;

    iov[0].flags = KRB5_CRYPTO_TYPE_STREAM;
    iov[0].data = *input;

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data = *output;

    ret = k5_ccm_decrypt_iov_stream(&krb5int_aead_ccm, enc, hash, key, usage, ivec, iov, sizeof(iov)/sizeof(iov[0]));
    if (ret == 0)
	*output = iov[1].data;

    return ret;
}
