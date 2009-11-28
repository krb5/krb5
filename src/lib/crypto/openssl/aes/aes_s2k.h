/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/openssl/aes/aes_s2k.h
 */


extern krb5_error_code
krb5int_aes_string_to_key (const struct krb5_enc_provider *,
                           const krb5_data *, const krb5_data *,
                           const krb5_data *, krb5_keyblock *key);
