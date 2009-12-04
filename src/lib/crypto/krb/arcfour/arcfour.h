/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef ARCFOUR_H
#define ARCFOUR_H

#include "etypes.h"

unsigned int
krb5int_arcfour_crypto_length(const struct krb5_keytypes *ktp,
                              krb5_cryptotype type);

krb5_error_code
krb5int_arcfour_encrypt(const struct krb5_keytypes *ktp, krb5_key key,
                        krb5_keyusage usage, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data);

krb5_error_code
krb5int_arcfour_decrypt(const struct krb5_keytypes *ktp, krb5_key key,
                        krb5_keyusage usage, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data);

extern krb5_error_code
krb5int_arcfour_string_to_key(
    const struct krb5_keytypes *,
    const krb5_data *,
    const krb5_data *,
    const krb5_data *,
    krb5_keyblock *);

extern const struct krb5_enc_provider krb5int_enc_arcfour;

#endif /* ARCFOUR_H */
