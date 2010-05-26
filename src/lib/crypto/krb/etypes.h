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

struct krb5_keytypes {
    krb5_enctype etype;
    char *name;
    char *aliases[2];
    char *out_string;
    const struct krb5_enc_provider *enc;
    const struct krb5_hash_provider *hash;
    size_t prf_length;
    crypto_length_func crypto_length;
    crypt_func encrypt;
    crypt_func decrypt;
    str2key_func str2key;
    prf_func prf;
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

#endif
