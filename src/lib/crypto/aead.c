/*
 * lib/crypto/aead.c
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
#include "etypes.h"
#include "cksumtypes.h"
#include "dk.h"
#include "aead.h"

krb5_crypto_iov * KRB5_CALLCONV
krb5int_c_locate_iov(krb5_crypto_iov *data,
		     size_t num_data,
		     krb5_cryptotype type)
{
    size_t i;
    krb5_crypto_iov *iov = NULL;

    if (data == NULL)
	return NULL;

    for (i = 0; i < num_data; i++) {
	if (data[i].flags == type) {
	    if (iov == NULL)
		iov = &data[i];
	    else
		return NULL; /* can't appear twice */
	}
    }

    return iov;
}

static krb5_error_code
make_unkeyed_checksum_iov(const struct krb5_hash_provider *hash_provider,
			  const krb5_crypto_iov *data,
			  size_t num_data,
			  krb5_data *output)
{
    krb5_data *sign_data;
    size_t num_sign_data;
    krb5_error_code ret;
    size_t i, j;

    /* Create a checksum over all the data to be signed */
    for (i = 0, num_sign_data = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (SIGN_IOV(iov))
	    num_sign_data++;
    }

    /* XXX cleanup to avoid alloc */
    sign_data = (krb5_data *)calloc(num_sign_data, sizeof(krb5_data));
    if (sign_data == NULL)
	return ENOMEM;

    for (i = 0, j = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (SIGN_IOV(iov))
	    sign_data[j++] = iov->data;
    }

    ret = hash_provider->hash(num_sign_data, sign_data, output);

    free(sign_data);

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5int_c_make_checksum_iov(const struct krb5_cksumtypes *cksum_type,
			    const krb5_keyblock *key,
			    krb5_keyusage usage,
			    const krb5_crypto_iov *data,
			    size_t num_data,
			    krb5_data *cksum_data)
{
    int e1, e2;
    krb5_error_code ret;

    if (cksum_type->keyhash != NULL) {
	/* check if key is compatible */

	if (cksum_type->keyed_etype) {
	    for (e1=0; e1<krb5_enctypes_length; e1++) 
		if (krb5_enctypes_list[e1].etype ==
		    cksum_type->keyed_etype)
		    break;

	    for (e2=0; e2<krb5_enctypes_length; e2++) 
		if (krb5_enctypes_list[e2].etype == key->enctype)
		    break;

	    if ((e1 == krb5_enctypes_length) ||
		(e2 == krb5_enctypes_length) ||
		(krb5_enctypes_list[e1].enc != krb5_enctypes_list[e2].enc)) {
		ret = KRB5_BAD_ENCTYPE;
		goto cleanup;
	    }
	}

	if (cksum_type->keyhash->hash_iov == NULL) {
	    return KRB5_BAD_ENCTYPE;
	}

	ret = (*(cksum_type->keyhash->hash_iov))(key, usage, 0,
						 data, num_data, cksum_data);
    } else if (cksum_type->flags & KRB5_CKSUMFLAG_DERIVE) {
	ret = krb5int_dk_make_checksum_iov(cksum_type->hash,
					key, usage, data, num_data,
					cksum_data);
    } else {
	ret = make_unkeyed_checksum_iov(cksum_type->hash, data, num_data,
					cksum_data);
    }

    if (ret == 0) {
	if (cksum_type->trunc_size) {
	    cksum_data->length = cksum_type->trunc_size;
	}
    }

cleanup:
    if (ret != 0) {
	memset(cksum_data->data, 0, cksum_data->length);
    }

    return ret;
}

const struct krb5_cksumtypes * KRB5_CALLCONV
krb5int_c_find_checksum_type(krb5_cksumtype cksumtype)
{
    size_t i;

    for (i = 0; i < krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return NULL;

    return &krb5_cksumtypes_list[i];
}

static int
process_block_p(const krb5_crypto_iov *data,
		size_t num_data,
		struct iov_block_state *iov_state,
		size_t i)
{
    const krb5_crypto_iov *iov = &data[i];
    int process_block;

    switch (iov->flags) {
    case KRB5_CRYPTO_TYPE_SIGN_ONLY:
	process_block = iov_state->include_sign_only;
	break;
    case KRB5_CRYPTO_TYPE_PADDING:
	process_block = (iov_state->pad_to_boundary == 0);
	break;
    case KRB5_CRYPTO_TYPE_HEADER:
	process_block = (iov_state->ignore_header == 0);
	break;
    case KRB5_CRYPTO_TYPE_DATA:
	process_block = 1;
	break;
    default:
	process_block = 0;
	break;
    }

    return process_block;
}

/*
 * Returns TRUE if, having reached the end of the current buffer,
 * we should pad the rest of the block with zeros.
 */
static int
pad_to_boundary_p(const krb5_crypto_iov *data,
		  size_t num_data,
		  struct iov_block_state *iov_state,
		  size_t i,
		  size_t j)
{
    /* If the pad_to_boundary flag is unset, return FALSE */
    if (iov_state->pad_to_boundary == 0)
	return 0;

    /* If we haven't got any data, we need to get some */
    if (j == 0)
	return 0;

    /* Don't consider the header as a boundary */
    if (iov_state->ignore_header == 0)
	return 0;

    /* Don't consider adjacent buffers of the same type as a boundary */
    if (i < num_data - 1 &&
	(data[i].flags == data[i + 1].flags ||
	 data[i].flags == KRB5_CRYPTO_TYPE_HEADER && SIGN_IOV(&data[i])))
	return 0;

    return 1;
}

void KRB5_CALLCONV
krb5int_c_iov_get_block(unsigned char *block,
			size_t block_size,
			const krb5_crypto_iov *data,
			size_t num_data,
			struct iov_block_state *iov_state)
{
    size_t i, j = 0;

    for (i = iov_state->iov_pos; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];
	size_t nbytes;

	if (pad_to_boundary_p(data, num_data, iov_state, i, j))
	    break;

	if (!process_block_p(data, num_data, iov_state, i))
	    continue;

	nbytes = iov->data.length - iov_state->data_pos;
	if (nbytes > block_size - j)
	    nbytes = block_size - j;

	memcpy(block + j, iov->data.data + iov_state->data_pos, nbytes);

	iov_state->data_pos += nbytes;
	j += nbytes;

	assert(j <= block_size);

	if (j == block_size)
	    break;

	assert(iov_state->data_pos == iov->data.length);

	iov_state->data_pos = 0;
    }

    iov_state->iov_pos = i;

    if (j != block_size)
	memset(block + j, 0, block_size - j);
}

void KRB5_CALLCONV
krb5int_c_iov_put_block(const krb5_crypto_iov *data,
			size_t num_data,
			unsigned char *block,
			size_t block_size,
			struct iov_block_state *iov_state)
{
    size_t i, j = 0;

    for (i = iov_state->iov_pos; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];
	size_t nbytes;

	if (pad_to_boundary_p(data, num_data, iov_state, i, j))
	    break;

	if (!process_block_p(data, num_data, iov_state, i))
	    continue;

	nbytes = iov->data.length - iov_state->data_pos;
	if (nbytes > block_size - j)
	    nbytes = block_size - j;

	memcpy(iov->data.data + iov_state->data_pos, block + j, nbytes);

	iov_state->data_pos += nbytes;
	j += nbytes;

	assert(j <= block_size);

	if (j == block_size)
	    break;

	assert(iov_state->data_pos == iov->data.length);

	iov_state->data_pos = 0;
    }

    iov_state->iov_pos = i;
}

krb5_error_code KRB5_CALLCONV
krb5int_c_iov_decrypt_stream(const struct krb5_aead_provider *aead,
			     const struct krb5_enc_provider *enc,
			     const struct krb5_hash_provider *hash,
			     const krb5_keyblock *key,
			     krb5_keyusage keyusage,
			     const krb5_data *ivec,
			     krb5_crypto_iov *data,
			     size_t num_data)
{
    krb5_error_code ret;
    size_t header_len, trailer_len, padding_len;
    krb5_crypto_iov iov[4];
    krb5_crypto_iov *stream, *s_data;

    stream = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM);
    assert(stream != NULL);

    s_data = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_DATA);
    if (s_data == NULL)
	return KRB5_BAD_MSIZE;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &trailer_len);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &padding_len);
    if (ret != 0)
	return ret;

    if (stream->data.length < header_len + trailer_len)
	return KRB5_BAD_MSIZE;

    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data.data = stream->data.data;
    iov[0].data.length = header_len;

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.data = iov[0].data.data + iov[0].data.length;
    iov[1].data.length = stream->data.length - header_len - trailer_len;

    /* XXX not self-describing with respect to length, this is the best we can do */
    iov[2].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[2].data.data = NULL;
    iov[2].data.length = 0;

    iov[3].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[3].data.data = stream->data.data + stream->data.length - trailer_len;
    iov[3].data.length = trailer_len;

    ret = aead->decrypt_iov(aead, enc, hash, key, keyusage, ivec, iov, sizeof(iov)/sizeof(iov[0]));
    if (ret == 0)
	*s_data = iov[1];

    return ret;
}

