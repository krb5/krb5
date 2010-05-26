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

#include "k5-int.h"
#include "etypes.h"
#include "cksumtypes.h"

unsigned int
krb5int_dk_crypto_length(const struct krb5_keytypes *ktp,
                         krb5_cryptotype type);

unsigned int
krb5int_aes_crypto_length(const struct krb5_keytypes *ktp,
                          krb5_cryptotype type);

krb5_error_code
krb5int_dk_encrypt(const struct krb5_keytypes *ktp, krb5_key key,
                   krb5_keyusage usage, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data);

krb5_error_code
krb5int_dk_decrypt(const struct krb5_keytypes *ktp, krb5_key key,
                   krb5_keyusage usage, const krb5_data *ivec,
                   krb5_crypto_iov *data, size_t num_data);

krb5_error_code
krb5int_dk_string_to_key(const struct krb5_keytypes *enc,
                         const krb5_data *string, const krb5_data *salt,
                         const krb5_data *params, krb5_keyblock *key);

krb5_error_code
krb5int_aes_string_to_key(const struct krb5_keytypes *enc,
                          const krb5_data *string, const krb5_data *salt,
                          const krb5_data *params, krb5_keyblock *key);

krb5_error_code
krb5int_derive_keyblock(const struct krb5_enc_provider *enc,
                        krb5_key inkey,
                        krb5_keyblock *outkey,
                        const krb5_data *in_constant);

krb5_error_code
krb5int_derive_key(const struct krb5_enc_provider *enc,
                   krb5_key inkey,
                   krb5_key *outkey,
                   const krb5_data *in_constant);

krb5_error_code
krb5int_dk_checksum(const struct krb5_cksumtypes *ctp,
                    krb5_key key, krb5_keyusage usage,
                    const krb5_crypto_iov *data, size_t num_data,
                    krb5_data *output);

krb5_error_code
krb5int_derive_random(const struct krb5_enc_provider *enc,
                      krb5_key inkey, krb5_data *outrnd,
                      const krb5_data *in_constant);
