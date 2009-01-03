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

krb5_crypto_iov *
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

krb5_error_code 
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

const struct krb5_cksumtypes *
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

#ifdef DEBUG_IOV
static void
dump_block(const char *tag,
	   size_t i,
	   size_t j,
	   unsigned char *block,
	   size_t block_size)
{
    size_t k;

    printf("[%s: %d.%d] ", tag, i, j);

    for (k = 0; k < block_size; k++)
	printf("%02x ", block[k] & 0xFF);

    printf("\n");
}
#endif

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

    /* No boundary between adjacent buffers marked for processing */
    if (data[iov_state->iov_pos].flags == data[i].flags)
	return 0;

    return 1;
}

krb5_boolean
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

	if (!process_block_p(data, num_data, iov_state, i))
	    continue;

	if (pad_to_boundary_p(data, num_data, iov_state, i, j))
	    break;

	iov_state->iov_pos = i;

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

#ifdef DEBUG_IOV
    dump_block("get_block", i, j, block, block_size);
#endif

    return (iov_state->iov_pos < num_data);
}

krb5_boolean
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

	if (!process_block_p(data, num_data, iov_state, i))
	    continue;

	if (pad_to_boundary_p(data, num_data, iov_state, i, j))
	    break;

	iov_state->iov_pos = i;

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

#ifdef DEBUG_IOV
    dump_block("put_block", i, j, block, block_size);
#endif

    return (iov_state->iov_pos < num_data);
}

krb5_error_code
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
    unsigned int header_len, trailer_len, padding_len;
    krb5_crypto_iov *iov;
    krb5_crypto_iov *stream;
    size_t i, j;
    int got_data = 0;

    stream = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM);
    assert(stream != NULL);

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

    iov = (krb5_crypto_iov *)calloc(num_data + 2, sizeof(krb5_crypto_iov));
    if (iov == NULL)
	return ENOMEM;

    i = 0;

    iov[i].flags = KRB5_CRYPTO_TYPE_HEADER; /* takes place of STREAM */
    iov[i].data.data = stream->data.data;
    iov[i].data.length = header_len;
    i++;
 
    for (j = 0; j < num_data; j++) {
	if (data[j].flags == KRB5_CRYPTO_TYPE_DATA) {
	    if (got_data) {
		free(iov);
		return KRB5_BAD_MSIZE;
	    }

	    got_data++;

	    data[j].data.data = stream->data.data + header_len;
	    data[j].data.length = stream->data.length - header_len - trailer_len;
	}
	if (data[j].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY ||
	    data[j].flags == KRB5_CRYPTO_TYPE_DATA)
	    iov[i++] = data[j];
    }

    /* XXX not self-describing with respect to length, this is the best we can do */
    iov[i].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[i].data.data = NULL;
    iov[i].data.length = 0;
    i++;

    iov[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[i].data.data = stream->data.data + stream->data.length - trailer_len;
    iov[i].data.length = trailer_len;
    i++;

    assert(i <= num_data + 2);

    ret = aead->decrypt_iov(aead, enc, hash, key, keyusage, ivec, iov, i);

    free(iov);

    return ret;
}

krb5_error_code
krb5int_c_padding_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 size_t data_length,
			 unsigned int *pad_length)
{
    unsigned int padding;
    krb5_error_code ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_PADDING, &padding);
    if (ret != 0)
	return ret;

    if (padding == 0 || (data_length % padding) == 0)
	*pad_length = 0;
    else
	*pad_length = padding - (data_length % padding);

    return 0;
}

krb5_error_code
krb5int_c_encrypt_aead_compat(const struct krb5_aead_provider *aead,
			      const struct krb5_enc_provider *enc,
			      const struct krb5_hash_provider *hash,
			      const krb5_keyblock *key, krb5_keyusage usage,
			      const krb5_data *ivec, const krb5_data *input,
			      krb5_data *output)
{
    krb5_crypto_iov iov[4];
    krb5_error_code ret;
    unsigned int header_len = 0;
    unsigned int padding_len = 0;
    unsigned int trailer_len = 0;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER,
			      &header_len);
    if (ret != 0)
	return ret;

    ret = krb5int_c_padding_length(aead, enc, hash, input->length, &padding_len);
    if (ret != 0)
	return ret;

    ret = aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER,
			      &trailer_len);
    if (ret != 0)
	return ret;

    if (output->length < header_len + input->length + padding_len + trailer_len)
	return KRB5_BAD_MSIZE;

    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data.data = output->data;
    iov[0].data.length = header_len;

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.data = iov[0].data.data + iov[0].data.length;
    iov[1].data.length = input->length;
    memcpy(iov[1].data.data, input->data, input->length);

    iov[2].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[2].data.data = iov[1].data.data + iov[1].data.length;
    iov[2].data.length = padding_len;

    iov[3].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[3].data.data = iov[2].data.data + iov[2].data.length;
    iov[3].data.length = trailer_len;

    ret = aead->encrypt_iov(aead, enc, hash, key,
			    usage, ivec,
			    iov, sizeof(iov)/sizeof(iov[0]));

    if (ret != 0)
	zap(iov[1].data.data, iov[1].data.length);

    output->length = iov[0].data.length + iov[1].data.length +
		     iov[2].data.length + iov[3].data.length;

    return ret;
}

krb5_error_code
krb5int_c_decrypt_aead_compat(const struct krb5_aead_provider *aead,
			      const struct krb5_enc_provider *enc,
			      const struct krb5_hash_provider *hash,
			      const krb5_keyblock *key, krb5_keyusage usage,
			      const krb5_data *ivec, const krb5_data *input,
			      krb5_data *output)
{
    krb5_crypto_iov iov[2];
    krb5_error_code ret;

    iov[0].flags = KRB5_CRYPTO_TYPE_STREAM;
    iov[0].data.data = malloc(input->length);
    if (iov[0].data.data == NULL)
	return ENOMEM;

    memcpy(iov[0].data.data, input->data, input->length);
    iov[0].data.length = input->length;

    iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[1].data.data = NULL;
    iov[1].data.length = 0;

    ret = krb5int_c_iov_decrypt_stream(aead, enc, hash, key,
				       usage, ivec,
				       iov, sizeof(iov)/sizeof(iov[0]));
    if (ret != 0)
	goto cleanup;

    if (output->length < iov[1].data.length) {
	ret = KRB5_BAD_MSIZE;
	goto cleanup;
    }

    memcpy(output->data, iov[1].data.data, iov[1].data.length);
    output->length = iov[1].data.length;

cleanup:
    zap(iov[0].data.data,  iov[0].data.length);
    free(iov[0].data.data);

    return ret;
}

void
krb5int_c_encrypt_length_aead_compat(const struct krb5_aead_provider *aead,
				     const struct krb5_enc_provider *enc,
				     const struct krb5_hash_provider *hash,
				     size_t inputlen, size_t *length)
{
    unsigned int header_len = 0;
    unsigned int padding_len = 0;
    unsigned int trailer_len = 0;

    aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_HEADER, &header_len);
    krb5int_c_padding_length(aead, enc, hash, inputlen, &padding_len);
    aead->crypto_length(aead, enc, hash, KRB5_CRYPTO_TYPE_TRAILER, &trailer_len);

    *length = header_len + inputlen + padding_len + trailer_len;
}

