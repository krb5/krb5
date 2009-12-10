/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
#include "etypes.h"

/* AEAD helpers */

krb5_crypto_iov *
krb5int_c_locate_iov(krb5_crypto_iov *data,
                     size_t num_data,
                     krb5_cryptotype type);

#define ENCRYPT_CONF_IOV(_iov)  ((_iov)->flags == KRB5_CRYPTO_TYPE_HEADER)

#define ENCRYPT_DATA_IOV(_iov)  ((_iov)->flags == KRB5_CRYPTO_TYPE_DATA || \
                                 (_iov)->flags == KRB5_CRYPTO_TYPE_PADDING)

#define ENCRYPT_IOV(_iov)       (ENCRYPT_CONF_IOV(_iov) || ENCRYPT_DATA_IOV(_iov))

#define SIGN_IOV(_iov)          (ENCRYPT_IOV(_iov) ||                   \
                                 (_iov)->flags == KRB5_CRYPTO_TYPE_SIGN_ONLY )

struct iov_block_state {
    size_t iov_pos;                     /* index into iov array */
    size_t data_pos;                    /* index into iov contents */
    unsigned int ignore_header : 1;     /* have/should we process HEADER */
    unsigned int include_sign_only : 1; /* should we process SIGN_ONLY blocks */
    unsigned int pad_to_boundary : 1;   /* should we zero fill blocks until next buffer */
};

#define IOV_BLOCK_STATE_INIT(_state)    ((_state)->iov_pos =            \
                                         (_state)->data_pos =           \
                                         (_state)->ignore_header =      \
                                         (_state)->include_sign_only =  \
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
krb5int_c_iov_decrypt_stream(const struct krb5_keytypes *ktp, krb5_key key,
                             krb5_keyusage keyusage, const krb5_data *ivec,
                             krb5_crypto_iov *data, size_t num_data);

unsigned int
krb5int_c_padding_length(const struct krb5_keytypes *ktp, size_t data_length);

/*
 * Returns an alias into the current buffer if the next block is fully
 * contained within; otherwise makes a copy of the next block and returns an
 * alias to storage.  After calling this function, encrypt the returned block
 * in place and then call iov_store_block (with a separate output cursor) to
 * store the result back into the iov if necessary.  Returns NULL if there
 * is no next block.
 */
static inline unsigned char *
iov_next_block(unsigned char *storage, size_t len,
               const krb5_crypto_iov *data, size_t num_data,
               struct iov_block_state *pos)
{
    const krb5_crypto_iov *iov = &data[pos->iov_pos];
    unsigned char *block;

    if (pos->iov_pos < num_data && iov->data.length - pos->data_pos >= len) {
        /* Return an alias to memory inside the current iov. */
        block = (unsigned char *) iov->data.data + pos->data_pos;
        pos->data_pos += len;
        return block;
    }
    /* Do it the slow way and return a copy into storage. */
    if (krb5int_c_iov_get_block(storage, len, data, num_data, pos))
        return storage;
    return NULL;
}

/*
 * Store a block retrieved with iov_next_block if necessary, and advance the
 * output cursor.
 */
static inline void
iov_store_block(const krb5_crypto_iov *data, size_t num_data,
                unsigned char *block, unsigned char *storage, size_t len,
                struct iov_block_state *pos)
{
    if (block == storage) {
        /* We got the block the slow way; put it back that way too. */
        krb5int_c_iov_put_block(data, num_data, storage, len, pos);
    } else {
        /* It's already stored; we just have to advance the output cursor. */
        pos->data_pos += len;
    }
}
