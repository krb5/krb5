/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef CKSUMTYPES_H
#define CKSUMTYPES_H
#include "k5-int.h"
#include "etypes.h"

struct krb5_cksumtypes;

/*
 * Compute a checksum over the header, data, padding, and sign-only fields of
 * the iov array data (of size num_data).  The output buffer will already be
 * allocated with ctp->compute_size bytes available; the handler just needs to
 * fill in the contents.  If ctp->enc is not NULL, the handler can assume that
 * key is a valid-length key of an enctype which uses that enc provider.
 */
typedef krb5_error_code (*checksum_func)(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);

/*
 * Verify a checksum over the header, data, padding, and sign-only fields of
 * the iov array data (of size num_data), and store the boolean result in
 * *valid.  The handler can assume that hash has length ctp->output_size.  If
 * ctp->enc is not NULL, the handler can assume that key a valid-length key of
 * an enctype which uses that enc provider.
 */
typedef krb5_error_code (*verify_func)(const struct krb5_cksumtypes *ctp,
                                       krb5_key key, krb5_keyusage usage,
                                       const krb5_crypto_iov *data,
                                       size_t num_data,
                                       const krb5_data *input,
                                       krb5_boolean *valid);

struct krb5_cksumtypes {
    krb5_cksumtype ctype;
    char *name;
    char *aliases[2];
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
    checksum_func checksum;
    verify_func verify;         /* NULL means recompute checksum and compare */
    unsigned int compute_size;  /* Allocation size for checksum computation */
    unsigned int output_size;   /* Possibly truncated output size */
    krb5_flags flags;
};

#define CKSUM_UNKEYED          0x0001
#define CKSUM_NOT_COLL_PROOF   0x0002

extern const struct krb5_cksumtypes krb5int_cksumtypes_list[];
extern const size_t krb5int_cksumtypes_length;

krb5_error_code krb5int_unkeyed_checksum(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);

krb5_error_code krb5int_cbc_checksum(const struct krb5_cksumtypes *ctp,
                                     krb5_key key, krb5_keyusage usage,
                                     const krb5_crypto_iov *data,
                                     size_t num_data,
                                     krb5_data *output);

krb5_error_code krb5int_hmacmd5_checksum(const struct krb5_cksumtypes *ctp,
                                         krb5_key key, krb5_keyusage usage,
                                         const krb5_crypto_iov *data,
                                         size_t num_data,
                                         krb5_data *output);

krb5_error_code krb5int_cmac_checksum(const struct krb5_enc_provider *enc,
                                      krb5_key key,
                                      const krb5_crypto_iov *data,
                                      size_t num_data,
                                      krb5_data *output);

krb5_error_code krb5int_confounder_checksum(const struct krb5_cksumtypes *ctp,
                                            krb5_key key, krb5_keyusage usage,
                                            const krb5_crypto_iov *data,
                                            size_t num_data,
                                            krb5_data *output);

krb5_error_code krb5int_confounder_verify(const struct krb5_cksumtypes *ctp,
                                          krb5_key key, krb5_keyusage usage,
                                          const krb5_crypto_iov *data,
                                          size_t num_data,
                                          const krb5_data *input,
                                          krb5_boolean *valid);

static inline const struct krb5_cksumtypes *
find_cksumtype(krb5_cksumtype ctype)
{
    size_t i;

    for (i = 0; i < krb5int_cksumtypes_length; i++) {
        if (krb5int_cksumtypes_list[i].ctype == ctype)
            break;
    }

    if (i == krb5int_cksumtypes_length)
        return NULL;
    return &krb5int_cksumtypes_list[i];
}

static inline krb5_error_code
verify_key(const struct krb5_cksumtypes *ctp, krb5_key key)
{
    const struct krb5_keytypes *ktp;

    ktp = key ? find_enctype(key->keyblock.enctype) : NULL;
    if (ctp->enc != NULL && (!ktp || ktp->enc != ctp->enc))
        return KRB5_BAD_ENCTYPE;
    if (key && (!ktp || key->keyblock.length != ktp->enc->keylength))
        return KRB5_BAD_KEYSIZE;
    return 0;
}

#endif
