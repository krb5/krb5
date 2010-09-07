/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/crypto_tests/t_camellia_ccm.c
 *
 * Copyright 2010 by the Massachusetts Institute of Technology.
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
 *
 *
 * Test vectors for camellia-ccm enctypes.
 *
 * Currently we have no way of controlling the random generated during
 * encryption.  This test program can be used to generate test vectors with
 * random nonces, and to verify existing test vectors via decryption.
 *
 * Usage:
 *   ./t_camellia_ccm -ge <usage> <text> <additional>
 *   ./t_camellia_ccm -gc <usage> <text>
 *   ./t_camellia_ccm
 */

#include "k5-int.h"

#ifdef CAMELLIA_CCM

static krb5_keyblock key_128 = {
    KV5M_KEYBLOCK,
    ENCTYPE_CAMELLIA128_CCM_128,
    16, (unsigned char *)
    "\xF0\x10\x02\xD2\xB1\xF9\xA1\xAD\xE2\x57\xEE\xF7\x52\x9C\x2A\x16"
};

static krb5_keyblock key_256 = {
    KV5M_KEYBLOCK,
    ENCTYPE_CAMELLIA256_CCM_128,
    32, (unsigned char *)
    "\xD7\xEF\x37\xE2\xD1\x05\x5E\xB7\xD7\x6B\x06\x39\x6E\xF7\x00\x52"
    "\x3D\xA4\xB0\xB7\xA0\x53\xF5\xCC\x5F\xAE\x4A\x39\xCF\xC5\x75\x0F"
};

static struct enc_test {
    krb5_keyusage usage;
    char *input;
    char *addl;
    krb5_data cipher_128;
    krb5_data cipher_256;
} enc_tests[] = {
    {
        0, "", "",
        { KV5M_DATA, 28,
          "\x44\xE7\x08\x7D\xDF\x12\x8F\x02\x56\x10\xF5\x34"
          "\xA1\x0C\x14\x58\x97\x38\xDD\x6B\x0D\x44\x12\x87\xAC\x2C\xC8\xD8" },
        { KV5M_DATA, 28,
          "\xE1\x8C\x74\x93\xA7\x15\x58\x11\x58\x6A\xB4\x0E"
          "\x82\xC1\xFD\xB6\xA7\x05\x5B\x78\xD3\x1D\xE2\x34\xBA\xC3\xC0\x5A" }
    },
    {
        1, "input", "additional",
        { KV5M_DATA, 33,
          "\x44\xE7\x08\x7D\xDF\x12\x8F\x02\x56\x10\xF5\x34"
          "\x32\x69\x98\x26\xE4"
          "\xE4\x4E\x85\x75\xA0\x37\x60\xDF\x0A\x96\xEC\x24\xB2\xBE\x4A\xA4" },
        { KV5M_DATA, 33,
          "\xE1\x8C\x74\x93\xA7\x15\x58\x11\x58\x6A\xB4\x0E"
          "\x55\x9E\xB8\xB8\x22"
          "\x7C\xD0\x38\x61\xC6\x81\x3C\x64\xB1\x72\xE3\x3D\x38\x36\x42\x72" }
    },
    {
        100,
        "this input spans multiple blocks",
        "the additional data also spans multiple blocks",
        { KV5M_DATA, 60,
          "\x44\xE7\x08\x7D\xDF\x12\x8F\x02\x56\x10\xF5\x34"
          "\x29\x1B\xAF\x6E\x2E\x31\xC6\xDD\xB2\xC9\xE1\xDD\xB4\x82\xAD\x5E"
          "\x87\xE2\x9A\x65\xF5\x53\x28\x75\x84\x40\x96\x1B\x56\x02\xAD\x31"
          "\xDD\x15\x22\x61\xB6\x10\xAD\x80\x42\x44\x32\x85\xFD\xFA\x82\x1A" },
        { KV5M_DATA, 60,
          "\xE1\x8C\x74\x93\xA7\x15\x58\x11\x58\x6A\xB4\x0E"
          "\xD0\x9E\x5A\xFB\xFB\x56\x13\x5F\xB6\x29\x07\x0A\x54\x80\xAE\xB9"
          "\x37\xC5\x25\x6E\xA3\x65\xD4\x2D\x92\x0A\x15\xF9\xED\x6B\x07\xC3"
          "\x3D\x6B\x68\x9C\x2D\xC9\x7C\x69\x86\xAA\x7C\xCC\x37\x75\x33\x1C" }
    }
};

static struct cksum_test {
    krb5_keyusage usage;
    char *input;
    unsigned char expected_128[16];
    unsigned char expected_256[16];
} cksum_tests[] = {
    {
        0, "",
        "\xEE\x29\xC4\x6D\xA1\x37\x1D\x27\xD7\x32\x12\xFA\x14\xE8\x25\xB3",
        "\x19\x7A\xD0\x4B\x76\x82\x99\xA8\xD7\xBD\x51\x2C\xA8\x65\x65\x5D"
    },
    {
        5, "input",
        "\xA4\x40\x3B\x18\xC2\xAE\xFF\x04\xEA\x9E\xE2\x8F\xB0\x1F\x1C\x26",
        "\xC2\x11\x53\x9B\x99\xC2\x76\xDB\xC4\x55\x4F\x73\xFE\xD9\x76\x38"
    },
    {
        99, "a somewhat longer input spanning multiple blocks",
        "\x4A\x29\x54\x12\x9D\xF8\x0D\x04\x33\x2C\xD2\xA6\xC4\x14\x10\xDA",
        "\x0F\xAD\xE4\x38\xEA\xB4\xCB\x3C\x29\x5F\xBE\x69\x6F\xA4\x9F\x52"
    }
};

static void
print_hex(const char *heading, unsigned char *data, size_t len)
{
    size_t i;

    printf("  %s:\n    ", heading);
    for (i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if (i + 1 < len)
            printf("%s", (i % 16) == 15 ? "\n    " : " ");
    }
    printf("\n");
}

static void
generate_enc1(krb5_context context, krb5_keyusage usage, char *text,
              char *addl, krb5_keyblock *keyblock)
{
    krb5_crypto_iov iov[4];
    unsigned char nonce[12], tag[16];
    char *ciphertext = strdup(text);

    iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
    iov[0].data = make_data(nonce, sizeof(nonce));
    iov[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    iov[1].data = string2data(addl);
    iov[2].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[2].data = string2data(ciphertext);
    iov[3].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[3].data = make_data(tag, sizeof(tag));
    assert(krb5_c_encrypt_iov(context, keyblock, usage, NULL, iov, 4) == 0);
    print_hex("Nonce", nonce, sizeof(nonce));
    print_hex("Ciphertext", (unsigned char *)ciphertext, strlen(ciphertext));
    print_hex("Tag", tag, sizeof(tag));
}

static void
generate_enc(krb5_context context, krb5_keyusage usage, char *text, char *addl)
{
    printf("camellia128-ccm-128 ciphertext:\n");
    generate_enc1(context, usage, text, addl, &key_128);
    printf("camellia256-ccm-128 ciphertext:\n");
    generate_enc1(context, usage, text, addl, &key_256);
}

static void
generate_cksum1(krb5_context context, krb5_keyusage usage, char *text,
                krb5_keyblock *keyblock)
{
    krb5_checksum sum;
    krb5_data input = string2data(text);

    assert(krb5_c_make_checksum(context, 0, keyblock, usage, &input,
                                &sum) == 0);
    print_hex("Checksum", sum.contents, sum.length);
    krb5_free_checksum_contents(context, &sum);
}

static void
generate_cksum(krb5_context context, krb5_keyusage usage, char *text)
{
    printf("cmac-128-camellia128 checksum:\n");
    generate_cksum1(context, usage, text, &key_128);
    printf("cmac-128-camellia256 checksum:\n");
    generate_cksum1(context, usage, text, &key_256);
}

static void
verify_enc1(krb5_context context, krb5_keyblock *keyblock, krb5_keyusage usage,
            krb5_data *cipher, char *input, char *addl)
{
    krb5_crypto_iov iov[3];

    iov[0].flags = KRB5_CRYPTO_TYPE_STREAM;
    assert(alloc_data(&iov[0].data, cipher->length) == 0);
    memcpy(iov[0].data.data, cipher->data, cipher->length);
    iov[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    iov[1].data = string2data(addl);
    iov[2].flags = KRB5_CRYPTO_TYPE_DATA;
    assert(krb5_c_decrypt_iov(context, keyblock, usage, NULL, iov, 3) == 0);
    assert(data_eq_string(iov[2].data, input));
}

static void
verify_enc(krb5_context context)
{
    size_t i;
    struct enc_test *test;

    for (i = 0; i < sizeof(enc_tests) / sizeof(*enc_tests); i++) {
        test = &enc_tests[i];
        verify_enc1(context, &key_128, test->usage, &test->cipher_128,
                    test->input, test->addl);
        verify_enc1(context, &key_256, test->usage, &test->cipher_256,
                    test->input, test->addl);
    }
}

static void
verify_cksum1(krb5_context context, krb5_keyblock *keyblock,
              krb5_keyusage usage, char *text, unsigned char *expected)
{
    krb5_checksum sum;
    krb5_data input = string2data(text);

    assert(krb5_c_make_checksum(context, 0, keyblock, usage, &input,
                                &sum) == 0);
    assert(sum.length == 16);
    assert(memcmp(sum.contents, expected, 16) == 0);
    krb5_free_checksum_contents(context, &sum);
}

static void
verify_cksum(krb5_context context)
{
    size_t i;
    struct cksum_test *test;

    for (i = 0; i < sizeof(cksum_tests) / sizeof(*cksum_tests); i++) {
        test = &cksum_tests[i];
        verify_cksum1(context, &key_128, test->usage, test->input,
                      test->expected_128);
        verify_cksum1(context, &key_256, test->usage, test->input,
                      test->expected_256);
    }
}

#endif /* CAMELLIA_CCM */

int
main(int argc, char **argv)
{
#ifdef CAMELLIA_CCM
    krb5_context context = NULL;
    krb5_data seed = string2data("seed");

    assert(krb5_c_random_seed(context, &seed) == 0);
    if (argc >= 5 && strcmp(argv[1], "-ge") == 0) {
        generate_enc(context, atoi(argv[2]), argv[3], argv[4]);
    } else if (argc >= 4 && strcmp(argv[1], "-gc") == 0) {
        generate_cksum(context, atoi(argv[2]), argv[3]);
    } else {
        verify_enc(context);
        verify_cksum(context);
    }
#endif /* CAMELLIA_CCM */
    return 0;
}
