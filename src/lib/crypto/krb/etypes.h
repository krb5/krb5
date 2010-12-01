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

#ifndef ETYPES_H
#define ETYPES_H

#include "k5-int.h"

#define MAX_ETYPE_ALIASES 2

struct krb5_keytypes;

typedef unsigned int (*crypto_length_func)(const struct krb5_keytypes *ktp,
                                           krb5_cryptotype type);

typedef krb5_error_code (*crypt_func)(const struct krb5_keytypes *ktp,
                                      krb5_key key, krb5_keyusage keyusage,
                                      const krb5_data *ivec,
                                      krb5_crypto_iov *data, size_t num_data);

typedef krb5_error_code (*str2key_func)(const struct krb5_keytypes *ktp,
                                        const krb5_data *string,
                                        const krb5_data *salt,
                                        const krb5_data *parm,
                                        krb5_keyblock *key);

typedef krb5_error_code (*prf_func)(const struct krb5_keytypes *ktp,
                                    krb5_key key,
                                    const krb5_data *in, krb5_data *out);

typedef krb5_error_code (*init_state_func)(const struct krb5_keytypes *ktp,
                                           const krb5_keyblock *key,
                                           krb5_keyusage keyusage,
                                           krb5_data *out_state);

typedef void (*free_state_func)(const struct krb5_keytypes *ktp,
                                krb5_data *state);

struct krb5_keytypes {
    krb5_enctype etype;
    char *name;
    char *aliases[MAX_ETYPE_ALIASES];
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
    size_t prf_length;
    crypto_length_func crypto_length;
    crypt_func encrypt;
    crypt_func decrypt;
    str2key_func str2key;
    prf_func prf;
    init_state_func init_state;
    free_state_func free_state;
    krb5_cksumtype required_ctype;
    krb5_flags flags;
};

#define ETYPE_WEAK 1

extern const struct krb5_keytypes krb5int_enctypes_list[];
extern const int krb5int_enctypes_length;

static inline const struct krb5_keytypes *
find_enctype(krb5_enctype enctype)
{
    int i;

    for (i = 0; i < krb5int_enctypes_length; i++) {
        if (krb5int_enctypes_list[i].etype == enctype)
            break;
    }

    if (i == krb5int_enctypes_length)
        return NULL;
    return &krb5int_enctypes_list[i];
}

/* This belongs with the declaration of struct krb5_enc_provider... but not
 * while that's still in k5-int.h. */
/* Encrypt one block of plaintext in place. */
static inline krb5_error_code
encrypt_block(const struct krb5_enc_provider *enc, krb5_key key,
              krb5_data *block)
{
    krb5_crypto_iov iov;

    /* Verify that this is a block cipher and block is the right length. */
    if (block->length != enc->block_size || enc->block_size == 1)
        return EINVAL;
    iov.flags = KRB5_CRYPTO_TYPE_DATA;
    iov.data = *block;
    if (enc->cbc_mac != NULL)   /* One-block cbc-mac with no ivec. */
        return enc->cbc_mac(key, &iov, 1, NULL, block);
    else                        /* Assume cbc-mode encrypt. */
        return enc->encrypt(key, 0, &iov, 1);
}

krb5_error_code
krb5int_init_state_enc(const struct krb5_keytypes *ktp,
                       const krb5_keyblock *key, krb5_keyusage keyusage,
                       krb5_data *out_state);

void
krb5int_free_state_enc(const struct krb5_keytypes *ktp, krb5_data *state);

#endif
