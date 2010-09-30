/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/crypto_tests/t_str2key.c
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * String-to-key test vectors
 */

#include "k5-int.h"

struct test {
    krb5_enctype enctype;
    char *string;
    char *salt;
    krb5_data params;
    krb5_data expected_key;
} test_cases[] = {
    /* Test vectors from RFC 3962 appendix B. */
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 16,
          "\x42\x26\x3C\x6E\x89\xF4\xFC\x28\xB8\xDF\x68\xEE\x09\x79\x9F\x15" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 32,
          "\xFE\x69\x7B\x52\xBC\x0D\x3C\xE1\x44\x32\xBA\x03\x6A\x92\xE6\x5B"
          "\xBB\x52\x28\x09\x90\xA2\xFA\x27\x88\x39\x98\xD7\x2A\xF3\x01\x61" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 16,
          "\xC6\x51\xBF\x29\xE2\x30\x0A\xC2\x7F\xA4\x69\xD6\x93\xBD\xDA\x13" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 32,
          "\xA2\xE1\x6D\x16\xB3\x60\x69\xC1\x35\xD5\xE9\xD2\xE2\x5F\x89\x61"
          "\x02\x68\x56\x18\xB9\x59\x14\xB4\x67\xC6\x76\x22\x22\x58\x24\xFF" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\x4C\x01\xCD\x46\xD6\x32\xD0\x1E\x6D\xBE\x23\x0A\x01\xED\x64\x2A" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\x55\xA6\xAC\x74\x0A\xD1\x7B\x48\x46\x94\x10\x51\xE1\xE8\xB0\xA7"
          "\x54\x8D\x93\xB0\xAB\x30\xA8\xBC\x3F\xF1\x62\x80\x38\x2B\x8C\x2A" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 16,
          "\xE9\xB2\x3D\x52\x27\x37\x47\xDD\x5C\x35\xCB\x55\xBE\x61\x9D\x8E" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 32,
          "\x97\xA4\xE7\x86\xBE\x20\xD8\x1A\x38\x2D\x5E\xBC\x96\xD5\x90\x9C"
          "\xAB\xCD\xAD\xC8\x7C\xA4\x8F\x57\x45\x04\x15\x9F\x16\xC3\x6E\x31" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\x59\xD1\xBB\x78\x9A\x82\x8B\x1A\xA5\x4E\xF9\xC2\x88\x3F\x69\xED" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\x89\xAD\xEE\x36\x08\xDB\x8B\xC7\x1F\x1B\xFB\xFE\x45\x94\x86\xB0"
          "\x56\x18\xB7\x0C\xBA\xE2\x20\x92\x53\x4E\x56\xC5\x53\xBA\x4B\x34" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\xCB\x80\x05\xDC\x5F\x90\x17\x9A\x7F\x02\x10\x4C\x00\x18\x75\x1D" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\xD7\x8C\x5C\x9C\xB8\x72\xA8\xC9\xDA\xD4\x69\x7F\x0B\xB5\xB2\xD2"
          "\x14\x96\xC8\x2B\xEB\x2C\xAE\xDA\x21\x12\xFC\xEE\xA0\x57\x40\x1B" }
    },
    { 
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        "\xF0\x9D\x84\x9E",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 16,
          "\xF1\x49\xC1\xF2\xE1\x54\xA7\x34\x52\xD4\x3E\x7F\xE6\x2A\x56\xE5" }
    },
    { 
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        "\xF0\x9D\x84\x9E",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 32,
          "\x4B\x6D\x98\x39\xF8\x44\x06\xDF\x1F\x09\xCC\x16\x6D\xB4\xB8\x3C"
          "\x57\x18\x48\xB7\x84\xA3\xD6\xBD\xC3\x46\x58\x9A\x3E\x39\x3F\x9E" }
    },

#ifdef CAMELLIA_CCM
    /* The same inputs applied to camellia-ccm enctypes. */
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 16,
          "\xF0\x10\x02\xD2\xB1\xF9\xA1\xAD\xE2\x57\xEE\xF7\x52\x9C\x2A\x16" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 32,
          "\xD7\xEF\x37\xE2\xD1\x05\x5E\xB7\xD7\x6B\x06\x39\x6E\xF7\x00\x52"
          "\x3D\xA4\xB0\xB7\xA0\x53\xF5\xCC\x5F\xAE\x4A\x39\xCF\xC5\x75\x0F" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 16,
          "\xDD\x74\x90\xC0\x57\x4A\x44\x6B\x10\x3A\xB3\x1B\x6D\xE4\x77\x4F" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 32,
          "\x68\xC1\x64\x74\x09\x42\x8F\x59\x47\x9B\x26\xC3\x98\x6D\x5B\xB8"
          "\x66\x1C\xDE\x3C\x66\x79\xA0\xF5\x2C\x89\x01\xBD\x78\xDC\xEB\xA2" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\x1A\xA9\x0A\xA6\x1E\x0B\x3C\xB8\x6A\xA5\xA7\x7E\xD8\x44\x9D\x3B" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\xF8\x29\xBC\xE4\xBB\xB1\xA2\x4B\x01\xA0\xE8\xB1\xA7\x09\x52\x0A"
          "\x61\x38\xE9\xAF\xE5\x13\x84\x59\xB2\x0B\xAC\xCA\xB2\x4D\x5F\xAA" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 16,
          "\x35\x70\xC6\x68\x0D\xC6\xE9\xB0\x2E\x01\x28\x8B\xD0\xD2\xB6\x9B" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 32,
          "\x40\xB3\xB7\xC8\xF9\xC3\xB8\x65\x18\x10\xDC\x28\x42\x2D\x5F\x6D"
          "\x10\xA6\xB3\xE9\xE1\x2A\x71\xFF\xA6\x35\x41\x08\x4A\xFA\x2C\xA2" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\xFF\x99\x18\x52\x84\x8E\x67\x50\x4C\x09\x4F\x94\x68\xC9\xD6\x05" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\x56\x5C\x0A\x29\xC0\x58\xCD\xDC\x3C\xD8\xA9\xF3\x0A\x92\xAA\xD7"
          "\xFE\x30\xEA\xD4\x16\xC1\x51\xAA\x9B\x54\x75\x56\x62\xF0\x95\xDD" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\xAC\x83\x28\x64\x10\xA2\x8C\x76\x64\x79\x60\xF6\xA0\x37\x88\x03" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\xD3\x25\x4A\x5B\x45\x1F\x27\x9C\x1A\xD6\x29\x3E\x72\xF0\x69\x55"
          "\xEB\xFF\x36\xB6\x47\xDF\x97\x48\x97\x18\xD7\x5C\xF0\x6C\x40\x7C" }
    },
    { 
        ENCTYPE_CAMELLIA128_CCM_128,
        "\xf0\x9d\x84\x9e",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 16,
          "\x5D\xBD\x71\x57\x09\x38\x59\x81\xDA\xAB\xA2\x8A\x43\x10\xD7\x20" }
    },
    { 
        ENCTYPE_CAMELLIA256_CCM_128,
        "\xf0\x9d\x84\x9e",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 32,
          "\x6A\x1F\x10\xE5\x74\x4E\x32\xDD\x33\x49\x03\xA8\xEB\xD1\x42\x7E"
          "\x4C\x8D\x3D\x6D\xA5\x76\x77\x50\x4C\x38\x4C\x24\x33\x0B\x60\x3D" }
    }
#endif /* CAMELLIA_CCM */
};

static void
printkey(krb5_keyblock *keyblock)
{
    unsigned int i;

    for (i = 0; i < keyblock->length; i++) {
        printf("%02X", keyblock->contents[i]);
        if (i + 1 < keyblock->length)
            printf(" ");
    }
    printf("\n");
}

int
main(int argc, char **argv)
{
    krb5_context context = NULL;
    krb5_data string, salt;
    krb5_error_code ret;
    krb5_keyblock *keyblock;
    size_t i;
    struct test *test;
    krb5_boolean verbose = FALSE;

    if (argc >= 2 && strcmp(argv[1], "-v") == 0)
        verbose = TRUE;
    for (i = 0; i < sizeof(test_cases) / sizeof(*test_cases); i++) {
        test = &test_cases[i];
        string = string2data(test->string);
        salt = string2data(test->salt);
        assert(krb5_init_keyblock(context, test->enctype, 0, &keyblock) == 0);
        ret = krb5_c_string_to_key_with_params(context, test->enctype,
                                               &string, &salt, &test->params,
                                               keyblock);
        if (ret != 0) {
            com_err(argv[0], ret, "in krb5_c_string_to_key_with_params");
            exit(1);
        }
        if (verbose) {
            printf("Test %02d: ", (int)i);
            printkey(keyblock);
        }
        assert(keyblock->length == test->expected_key.length);
        if (memcmp(keyblock->contents, test->expected_key.data,
                   keyblock->length) != 0) {
            printf("str2key test %d failed\n", (int)i);
            exit(1);
        }
        krb5_free_keyblock(context, keyblock);
    }
    return 0;
}
