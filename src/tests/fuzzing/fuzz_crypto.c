/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_crypto.c */
/*
 * Copyright (C) 2024 by Arjun. All rights reserved.
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
 * Fuzzing harness implementation for checksum, encrypt-decrypt and prf.
 */

#include "autoconf.h"
#include <k5-int.h>
#include <crypto_int.h>

#define kMinInputLength 2
#define kMaxInputLength 512

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void
fuzz_checksum(krb5_keyblock keyblock, krb5_data data,
              krb5_cksumtype sumtype, krb5_keyusage usage)
{
    krb5_error_code ret;
    krb5_boolean valid;
    krb5_checksum cksum;

    ret = krb5_c_make_checksum(NULL, sumtype, &keyblock, usage, &data, &cksum);
    if (ret)
        return;

    krb5_c_verify_checksum(NULL, &keyblock, usage, &data, &cksum, &valid);
    if (ret) {
        krb5_free_checksum_contents(NULL, &cksum);
        return;
    }

    if (!valid)
        abort();

    krb5_free_checksum_contents(NULL, &cksum);
}

static void
fuzz_crypt(krb5_keyblock keyblock, krb5_data data,
           krb5_enctype enctype, krb5_keyusage usage)
{
    krb5_error_code ret;
    krb5_enc_data encoded;
    krb5_data decoded;
    size_t enclen;

    ret = krb5_c_encrypt_length(NULL, enctype, data.length, &enclen);
    if (ret)
        return;

    encoded.magic = KV5M_ENC_DATA;
    encoded.enctype = enctype;
    encoded.kvno = 0;

    ret = alloc_data(&encoded.ciphertext, enclen);
    if (ret)
        return;

    ret = alloc_data(&decoded, data.length);
    if (ret) {
        krb5_free_data_contents(NULL, &encoded.ciphertext);
        return;
    }

    ret = krb5_c_encrypt(NULL, &keyblock, usage, NULL, &data, &encoded);
    if (ret)
        goto cleanup;

    ret = krb5_c_decrypt(NULL, &keyblock, usage, NULL, &encoded, &decoded);
    if (ret)
        goto cleanup;

    ret = memcmp(data.data, decoded.data, data.length);
    if (ret)
        abort();

cleanup:
    krb5_free_data_contents(NULL, &encoded.ciphertext);
    krb5_free_data_contents(NULL, &decoded);
}

static void
fuzz_prf(krb5_keyblock keyblock, krb5_data data, krb5_enctype enctype)
{
    krb5_error_code ret;
    krb5_data output;
    size_t prfsz;

    ret = krb5_c_prf_length(NULL, enctype, &prfsz);
    if (ret)
        return;

    ret = alloc_data(&output, prfsz);
    if (ret)
        return;

    krb5_c_prf(NULL, &keyblock, &data, &output);

    krb5_free_data_contents(NULL, &output);
}

static void
fuzz_setup(krb5_data data, krb5_enctype enctype,
           krb5_cksumtype sumtype, krb5_keyusage usage)
{
    krb5_error_code ret;
    krb5_keyblock keyblock;

    ret = krb5_c_make_random_key(NULL, enctype, &keyblock);
    if (ret)
        return;

    fuzz_checksum(keyblock, data, sumtype, usage);
    fuzz_crypt(keyblock, data, enctype, usage);
    fuzz_prf(keyblock, data, enctype);

    krb5_free_keyblock_contents(NULL, &keyblock);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_data data_in;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    data_in = make_data((void *)data, size);

    fuzz_setup(data_in, ENCTYPE_DES3_CBC_SHA1, CKSUMTYPE_HMAC_SHA1_DES3, 0);
    fuzz_setup(data_in, ENCTYPE_ARCFOUR_HMAC, CKSUMTYPE_MD5_HMAC_ARCFOUR, 1);
    fuzz_setup(data_in, ENCTYPE_ARCFOUR_HMAC, CKSUMTYPE_HMAC_MD5_ARCFOUR, 2);
    fuzz_setup(data_in, ENCTYPE_ARCFOUR_HMAC_EXP, CKSUMTYPE_RSA_MD4, 3);
    fuzz_setup(data_in, ENCTYPE_ARCFOUR_HMAC_EXP, CKSUMTYPE_RSA_MD5, 4);
    fuzz_setup(data_in, ENCTYPE_ARCFOUR_HMAC_EXP, CKSUMTYPE_SHA1, 5);
    fuzz_setup(data_in, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
                        CKSUMTYPE_HMAC_SHA1_96_AES128, 6);
    fuzz_setup(data_in, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                        CKSUMTYPE_HMAC_SHA1_96_AES256, 7);
    fuzz_setup(data_in, ENCTYPE_CAMELLIA128_CTS_CMAC,
                        CKSUMTYPE_CMAC_CAMELLIA128, 8);
    fuzz_setup(data_in, ENCTYPE_CAMELLIA256_CTS_CMAC,
                        CKSUMTYPE_CMAC_CAMELLIA256, 9);
    fuzz_setup(data_in, ENCTYPE_AES128_CTS_HMAC_SHA256_128,
                        CKSUMTYPE_HMAC_SHA256_128_AES128, 10);
    fuzz_setup(data_in, ENCTYPE_AES256_CTS_HMAC_SHA384_192,
                        CKSUMTYPE_HMAC_SHA384_192_AES256, 11);

    return 0;
}
