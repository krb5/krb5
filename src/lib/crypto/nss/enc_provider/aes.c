/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/enc_provider/aes.c
 *
 * Copyright (c) 2010 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 *  * Neither the name of Red Hat, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "enc_provider.h"
#include "rand2key.h"
#include "aead.h"
#include "nss_gen.h"


krb5_error_code
krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_AES_CBC, CKA_ENCRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_cts_iov(key, CKM_AES_CBC, CKA_ENCRYPT,
                              ivec, data, num_data);
}

krb5_error_code
krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    krb5_error_code ret;

    ret = k5_nss_gen_import(key, CKM_AES_CBC, CKA_DECRYPT);
    if (ret != 0)
        return ret;
    return k5_nss_gen_cts_iov(key, CKM_AES_CBC, CKA_DECRYPT,
                              ivec, data, num_data);
}

/*
 * perhaps we should store the NSS context in the krb5_data state here?
 */
static krb5_error_code
aes_init_state(const krb5_keyblock *key, krb5_keyusage usage,
               krb5_data *state)
{
    state->length = 16;
    state->data = (void *) malloc(16);
    if (state->data == NULL)
        return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}

const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_make_key,
    aes_init_state,
    krb5int_default_free_state,
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_make_key,
    aes_init_state,
    krb5int_default_free_state,
    k5_nss_gen_cleanup
};
