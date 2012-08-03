/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/enc_provider/camellia.c */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * CyaSSL doesn't currently support the Camellia cipher.
 */

#include "crypto_int.h"

#ifdef CAMELLIA

static krb5_error_code
krb5int_camellia_encrypt(krb5_key key, const krb5_data *ivec,
			 krb5_crypto_iov *data, size_t num_data)
{
    return KRB5_CRYPTO_INTERNAL;
}

static krb5_error_code
krb5int_camellia_decrypt(krb5_key key, const krb5_data *ivec,
			 krb5_crypto_iov *data, size_t num_data)
{
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
krb5int_camellia_cbc_mac(krb5_key key, const krb5_crypto_iov *data,
                         size_t num_data, const krb5_data *iv,
			 krb5_data *output)
{
    return KRB5_CRYPTO_INTERNAL; 
} 

static krb5_error_code
krb5int_camellia_init_state (const krb5_keyblock *key, krb5_keyusage usage,
			     krb5_data *state)
{
    return KRB5_CRYPTO_INTERNAL; 
} 
   
const struct krb5_enc_provider krb5int_enc_camellia128 = {
    16,
    16, 16,
    krb5int_camellia_encrypt,
    krb5int_camellia_decrypt,
    krb5int_camellia_cbc_mac,
    krb5int_camellia_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_camellia256 = {
    16,
    32, 32,
    krb5int_camellia_encrypt,
    krb5int_camellia_decrypt,
    krb5int_camellia_cbc_mac,
    krb5int_camellia_init_state,
    krb5int_default_free_state
};

#else /* CAMELLIA */

/* These won't be used, but are still in the export table. */

krb5_error_code
krb5int_camellia_cbc_mac(krb5_key key, const krb5_crypto_iov *data,
                         size_t num_data, const krb5_data *iv,
			 krb5_data *output)
{
    return EINVAL;
}

const struct krb5_enc_provider krb5int_enc_camellia128 = {
};

const struct krb5_enc_provider krb5int_enc_camellia256 = {
};

#endif /* CAMELLIA */
