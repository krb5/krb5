/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
krb5int_c_locate_iov(krb5_crypto_iov *data, size_t num_data,
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
    if (i == num_data)
        return FALSE;

    if (j != block_size)
        memset(block + j, 0, block_size - j);

#ifdef DEBUG_IOV
    dump_block("get_block", i, j, block, block_size);
#endif

    return TRUE;
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
krb5int_c_iov_decrypt_stream(const struct krb5_keytypes *ktp, krb5_key key,
                             krb5_keyusage keyusage, const krb5_data *ivec,
                             krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;
    unsigned int header_len, trailer_len;
    krb5_crypto_iov *iov;
    krb5_crypto_iov *stream;
    size_t i, j;
    int got_data = 0;

    stream = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_STREAM);
    assert(stream != NULL);

    header_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);
    trailer_len = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_TRAILER);

    if (stream->data.length < header_len + trailer_len)
        return KRB5_BAD_MSIZE;

    iov = calloc(num_data + 2, sizeof(krb5_crypto_iov));
    if (iov == NULL)
        return ENOMEM;

    i = 0;

    iov[i].flags = KRB5_CRYPTO_TYPE_HEADER; /* takes place of STREAM */
    iov[i].data = make_data(stream->data.data, header_len);
    i++;

    for (j = 0; j < num_data; j++) {
        if (data[j].flags == KRB5_CRYPTO_TYPE_DATA) {
            if (got_data) {
                free(iov);
                return KRB5_BAD_MSIZE;
            }

            got_data++;

            data[j].data.data = stream->data.data + header_len;
            data[j].data.length = stream->data.length - header_len
                - trailer_len;
        }
        if (data[j].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY ||
            data[j].flags == KRB5_CRYPTO_TYPE_DATA)
            iov[i++] = data[j];
    }

    /* Use empty padding since tokens don't indicate the padding length. */
    iov[i].flags = KRB5_CRYPTO_TYPE_PADDING;
    iov[i].data = empty_data();
    i++;

    iov[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[i].data = make_data(stream->data.data + stream->data.length -
                            trailer_len, trailer_len);
    i++;

    assert(i <= num_data + 2);

    ret = ktp->decrypt(ktp, key, keyusage, ivec, iov, i);
    free(iov);
    return ret;
}

unsigned int
krb5int_c_padding_length(const struct krb5_keytypes *ktp, size_t data_length)
{
    unsigned int header, padding;

    /*
     * Add in the header length since the header is encrypted along with the
     * data.  (arcfour violates this assumption since not all of the header is
     * encrypted, but that's okay since it has no padding.  If there is ever an
     * enctype using a similar token format and a block cipher, we will have to
     * move this logic into an enctype-dependent function.)
     */
    header = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_HEADER);
    data_length += header;

    padding = ktp->crypto_length(ktp, KRB5_CRYPTO_TYPE_PADDING);
    if (padding == 0 || (data_length % padding) == 0)
        return 0;
    else
        return padding - (data_length % padding);
}
