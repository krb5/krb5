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

#ifdef CAMELLIA
    /* The same inputs applied to Camellia enctypes. */
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 16,
          "\x01\xCD\x91\xED\x3E\x06\x7D\x3D\xA1\x3C\x13\xA4\xBB\xEC\xFC\xAE" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\1" },
        { KV5M_DATA, 32,
          "\xC2\x21\x09\x04\x02\x9D\x7C\x23\xD4\x85\x7B\xA9\x6E\xC4\x8C\xE5"
          "\x5F\xB6\x07\x69\x4A\xFC\x4F\xE4\xFD\x3A\x18\xB0\xD8\x02\x8D\xCB" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 16,
          "\xF7\x45\xEE\x4A\xA0\x4B\x0E\xAC\x30\x82\x25\xF3\xDB\xE0\x6C\xB4" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\0\2" },
        { KV5M_DATA, 32,
          "\x31\x79\x77\x0E\x5F\x2E\xDD\x28\xFE\x11\x21\xB9\x17\xCF\xA7\x48"
          "\x0C\xA6\x73\x63\x67\x17\xFC\x74\xCB\x23\x4A\x84\x1B\xA9\x0F\xAF" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\x12\xCA\xCB\x5B\xFD\xD2\x46\x88\xCF\x8C\x48\xFB\x01\x4E\x9F\xCD" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "password",
        "ATHENA.MIT.EDUraeburn",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\xE8\x50\x13\x56\xD1\x94\x84\x7B\xB2\x92\x14\xF8\x8E\x76\xB6\x36"
          "\x0B\x5C\x1F\x91\xB9\xE1\xD7\x9B\xD7\x99\x3A\x4B\x8E\x73\x0A\x55" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 16,
          "\xE7\x88\xB8\x1C\x48\x92\x51\x89\x5A\x6D\x2A\xAE\x0B\x79\xAE\x50" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "password",
        "\x12\x34\x56\x78\x78\x56\x34\x12",
        { KV5M_DATA, 4, "\0\0\0\5" },
        { KV5M_DATA, 32,
          "\xB5\x04\xFD\xB2\x5A\xE5\x77\x92\x02\xAE\xE2\x85\x4B\x7D\xE5\xFD"
          "\xF3\x62\x7F\xEF\x7B\x48\x2F\xB4\x77\xD4\xFA\x9C\xE7\x31\x0E\xF0" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\xC4\x3F\x01\x7B\x6D\x13\x51\xF4\xD0\xBF\x0F\x4A\x75\xB1\xF1\xD2" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase equals block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\x38\xF7\xFC\x25\xD6\x7E\x41\xAC\xDD\xDB\xC0\x5F\x66\xAE\x11\x13"
          "\x22\x53\x47\xDC\xBC\x24\x67\xF2\x09\xA9\x7E\x0A\xFB\x30\xDE\x9D" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 16,
          "\xD9\xC3\x63\xF7\xED\x5E\x4B\x9A\x17\x8F\xF4\xD8\x4B\x3E\x51\x73" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "pass phrase exceeds block size",
        { KV5M_DATA, 4, "\0\0\x04\xB0" }, /* 1200 */
        { KV5M_DATA, 32,
          "\x0D\x88\xB2\xB3\x47\xD6\x79\xDA\xD2\xFF\xAE\x25\x6B\x64\xAD\x9A"
          "\x0F\x09\xB9\x16\x5E\xA8\x32\xB4\x01\xB4\x55\x31\xB9\xE0\xE3\x05" }
    },
    { 
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        "\xf0\x9d\x84\x9e",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 16,
          "\xF1\x64\xCF\xBB\xC3\x27\xE1\x70\x34\x93\x40\x92\xDC\xEA\x61\x5B" }
    },
    { 
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        "\xf0\x9d\x84\x9e",
        "EXAMPLE.COMpianist",
        { KV5M_DATA, 4, "\0\0\0\x32" }, /* 50 */
        { KV5M_DATA, 32,
          "\xBC\xD7\x5F\x07\x22\x5F\x25\xEC\xD4\x35\xA1\x74\x68\xE9\xAD\x64"
          "\x49\x83\x63\xF7\x87\xD1\xAE\xE9\x2A\xFE\xA9\xCB\x5C\x95\xEE\xAB" }
    }
#endif /* CAMELLIA */
};

static void
printkey(krb5_keyblock *keyblock)
{
    unsigned int i;

    for (i = 0; i < keyblock->length; i++) {
        printf("\\x%02X", keyblock->contents[i]);
/*        if (i + 1 < keyblock->length)
          printf(" "); */
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
