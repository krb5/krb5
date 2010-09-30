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

krb5_error_code
krb5int_c_iov_decrypt_stream(const struct krb5_keytypes *ktp, krb5_key key,
                             krb5_keyusage keyusage, const krb5_data *ivec,
                             krb5_crypto_iov *data, size_t num_data);

unsigned int
krb5int_c_padding_length(const struct krb5_keytypes *ktp, size_t data_length);

#ifdef DEBUG_IOV
static inline void
dump_block(const char *tag,
           size_t i,
           size_t j,
           unsigned char *block,
           size_t block_size)
{
    size_t k;

    printf("[%s: %lu.%lu] ", tag, i, j);

    for (k = 0; k < block_size; k++)
        printf("%02x ", block[k] & 0xFF);

    printf("\n");
}
#endif

static inline int
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
static inline int
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

/*
 * Retrieve a block from the IOV. If p is non-NULL and the next block is
 * completely contained within the current buffer, then *p will contain an
 * alias into the buffer; otherwise, a copy will be made into storage.
 *
 * After calling this function, encrypt the returned block and then call
 * krb5int_c_iov_put_block_nocopy() (with a separate output cursor). If
 * p was non-NULL on the call to get_block(), then pass that pointer in.
 */
static inline krb5_boolean
krb5int_c_iov_get_block_nocopy(unsigned char *storage,
                               size_t block_size,
                               const krb5_crypto_iov *data,
                               size_t num_data,
                               struct iov_block_state *iov_state,
                               unsigned char **p)
{
    size_t i, j = 0;

    if (p != NULL)
        *p = storage;

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

        /*
         * If we can return a pointer into a complete block, then do so.
         */
        if (p != NULL && j == 0 && nbytes == block_size) {
            *p = (unsigned char *)iov->data.data + iov_state->data_pos;
        } else {
            memcpy(storage + j, iov->data.data + iov_state->data_pos, nbytes);
        }

        iov_state->data_pos += nbytes;
        j += nbytes;

        assert(j <= block_size);

        if (j == block_size)
            break;

        assert(iov_state->data_pos == iov->data.length);

        iov_state->data_pos = 0;
    }

    iov_state->iov_pos = i;

    if (j == 0)
        return FALSE;
    else if (j != block_size)
        memset(storage + j, 0, block_size - j);

#ifdef DEBUG_IOV
    dump_block("get_block", i, j, (p && *p) ? *p : storage, block_size);
#endif

    return TRUE;
}

/*
 * Store a block retrieved with krb5int_c_iov_get_block_no_copy if
 * necessary, and advance the output cursor.
 */
static inline krb5_boolean
krb5int_c_iov_put_block_nocopy(const krb5_crypto_iov *data,
                               size_t num_data,
                               unsigned char *storage,
                               size_t block_size,
                               struct iov_block_state *iov_state,
                               unsigned char *p)
{
    size_t i, j = 0;

    assert(p != NULL);

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

        /*
         * If we had previously returned a pointer into a complete block,
         * then no action is required.
         */
        if (p == storage) {
            memcpy(iov->data.data + iov_state->data_pos, storage + j, nbytes);
        } else {
            /* Ensure correctly paired with a call to get_block_nocopy(). */
            assert(j == 0);
            assert(nbytes == 0 || nbytes == block_size);
        }

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
    dump_block("put_block", i, j, p, block_size);
#endif

    return (iov_state->iov_pos < num_data);
}

/*
 * A wrapper for krb5int_c_iov_get_block_nocopy() that always makes
 * a copy.
 */
static inline krb5_boolean
krb5int_c_iov_get_block(unsigned char *block,
                        size_t block_size,
                        const krb5_crypto_iov *data,
                        size_t num_data,
                        struct iov_block_state *iov_state)
{
    return krb5int_c_iov_get_block_nocopy(block, block_size, data, num_data,
                                          iov_state, NULL);
}

/*
 * A wrapper for krb5int_c_iov_put_block_nocopy() that always copies
 * the block.
 */
static inline krb5_boolean
krb5int_c_iov_put_block(const krb5_crypto_iov *data,
                        size_t num_data,
                        unsigned char *block,
                        size_t block_size,
                        struct iov_block_state *iov_state)
{
    return krb5int_c_iov_put_block_nocopy(data, num_data, block, block_size,
                                          iov_state, block);
}
