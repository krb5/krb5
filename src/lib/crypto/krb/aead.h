/*
 * lib/crypto/aead.h
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
#include "cksumtypes.h"

/* AEAD helpers */

krb5_crypto_iov *
krb5int_c_locate_iov(krb5_crypto_iov *data,
		     size_t num_data,
		     krb5_cryptotype type);

krb5_error_code
krb5int_c_make_checksum_iov(const struct krb5_cksumtypes *cksum,
			    const krb5_keyblock *key,
			    krb5_keyusage usage,
			    const krb5_crypto_iov *data,
			    size_t num_data,
			    krb5_data *cksum_data);

const struct krb5_cksumtypes *
krb5int_c_find_checksum_type(krb5_cksumtype cksumtype);

#define ENCRYPT_CONF_IOV(_iov)	((_iov)->flags == KRB5_CRYPTO_TYPE_HEADER)

#define ENCRYPT_DATA_IOV(_iov)	((_iov)->flags == KRB5_CRYPTO_TYPE_DATA || \
				 (_iov)->flags == KRB5_CRYPTO_TYPE_PADDING)

#define ENCRYPT_IOV(_iov)	(ENCRYPT_CONF_IOV(_iov) || ENCRYPT_DATA_IOV(_iov))

#define SIGN_IOV(_iov)		(ENCRYPT_IOV(_iov) || \
				 (_iov)->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY )

struct iov_block_state {
    size_t iov_pos;			/* index into iov array */
    size_t data_pos;			/* index into iov contents */
    unsigned int ignore_header : 1;	/* have/should we process HEADER */
    unsigned int include_sign_only : 1;	/* should we process SIGN_ONLY blocks */
    unsigned int pad_to_boundary : 1;	/* should we zero fill blocks until next buffer */
};

#define IOV_BLOCK_STATE_INIT(_state)	((_state)->iov_pos = \
					 (_state)->data_pos = \
					 (_state)->ignore_header = \
					 (_state)->include_sign_only = \
					 (_state)->pad_to_boundary = 0)

krb5_boolean
krb5int_c_iov_get_block(unsigned char *block,
			size_t block_size,
			const krb5_crypto_iov *data,
			size_t num_data,
			struct iov_block_state *iov_state);

krb5_boolean
krb5int_c_iov_put_block(const krb5_crypto_iov *data,
			size_t num_data,
			unsigned char *block,
			size_t block_size,
			struct iov_block_state *iov_state);

krb5_error_code
krb5int_c_iov_decrypt_stream(const struct krb5_aead_provider *aead,
			     const struct krb5_enc_provider *enc,
			     const struct krb5_hash_provider *hash,
			     const krb5_keyblock *key,
			     krb5_keyusage keyusage,
			     const krb5_data *ivec,
			     krb5_crypto_iov *data,
			     size_t num_data);

krb5_error_code
krb5int_c_decrypt_aead_compat(const struct krb5_aead_provider *aead,
			      const struct krb5_enc_provider *enc,
			      const struct krb5_hash_provider *hash,
			      const krb5_keyblock *key, krb5_keyusage usage,
			      const krb5_data *ivec, const krb5_data *input,
			      krb5_data *output);

krb5_error_code
krb5int_c_encrypt_aead_compat(const struct krb5_aead_provider *aead,
			      const struct krb5_enc_provider *enc,
			      const struct krb5_hash_provider *hash,
			      const krb5_keyblock *key, krb5_keyusage usage,
			      const krb5_data *ivec, const krb5_data *input,
			      krb5_data *output);

void
krb5int_c_encrypt_length_aead_compat(const struct krb5_aead_provider *aead,
				     const struct krb5_enc_provider *enc,
				     const struct krb5_hash_provider *hash,
				     size_t inputlen, size_t *length);

krb5_error_code
krb5int_c_padding_length(const struct krb5_aead_provider *aead,
			 const struct krb5_enc_provider *enc,
			 const struct krb5_hash_provider *hash,
			 size_t data_length,
			 unsigned int *pad_length);
