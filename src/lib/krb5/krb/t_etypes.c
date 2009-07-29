/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * t_etypes.c -- test program for krb5int_parse_enctype_list
 *
 * Copyright 2009  by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include <stdio.h>
#include "com_err.h"

static struct {
    const char *str;
    krb5_enctype defaults[64];
    krb5_enctype expected_noweak[64];
    krb5_enctype expected[64];
} tests[] = {
    /* Empty string, unused default list */
    { "",
      { ENCTYPE_DES_CBC_CRC, 0 },
      { 0 },
      { 0 }
    },
    /* Single weak enctype */
    { "des-cbc-md4",
      { 0 },
      { 0 },
      { ENCTYPE_DES_CBC_MD4, 0 }
    },
    /* Single non-weak enctype */
    { "aes128-cts-hmac-sha1-96",
      { 0 },
      { ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 },
      { ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 }
    },
    /* Two enctypes, one an alias, one weak */
    { "rc4-hmac des-cbc-md5",
      { 0 },
      { ENCTYPE_ARCFOUR_HMAC, 0 },
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_DES_CBC_MD5, 0 }
    },
    /* Three enctypes, all weak, case variation, funky separators */
    { "  deS-HMac-shA1 , arCFour-hmaC-mD5-exp\tdeS3-Cbc-RAw\n",
      { 0 },
      { 0 },
      { ENCTYPE_DES_HMAC_SHA1, ENCTYPE_ARCFOUR_HMAC_EXP,
        ENCTYPE_DES3_CBC_RAW, 0 }
    },
    /* Default set with enctypes added (one weak in each pair) */
    { "DEFAULT des-cbc-raw +des3-hmac-sha1",
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_ARCFOUR_HMAC_EXP, 0 },
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_DES3_CBC_SHA1, 0 },
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_ARCFOUR_HMAC_EXP,
        ENCTYPE_DES_CBC_RAW, ENCTYPE_DES3_CBC_SHA1, 0 }
    },
    /* Default set with enctypes removed */
    { "default -aes128-cts -des-hmac-sha1",
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_DES_CBC_MD5, ENCTYPE_DES_HMAC_SHA1, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_DES_CBC_MD5, 0 }
    },
    /* Family followed by enctype */
    { "aes des3-cbc-sha1-kd",
      { 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_DES3_CBC_SHA1, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_DES3_CBC_SHA1, 0 }
    },
    /* Enctype followed by two families */
    { "+rc4-hmAC des3 +des",
      { 0 },
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_DES3_CBC_SHA1, 0 },
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_DES3_CBC_SHA1, ENCTYPE_DES_CBC_CRC,
        ENCTYPE_DES_CBC_MD5, ENCTYPE_DES_CBC_MD4 }
    },
    /* Default set with family added and enctype removed */
    { "DEFAULT +aes -arcfour-hmac-md5",
      { ENCTYPE_ARCFOUR_HMAC, ENCTYPE_DES3_CBC_SHA1, ENCTYPE_DES_CBC_CRC, 0 },
      { ENCTYPE_DES3_CBC_SHA1, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 },
      { ENCTYPE_DES3_CBC_SHA1, ENCTYPE_DES_CBC_CRC,
        ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 }
    },
    /* Default set with families removed and enctypes added (one redundant) */
    { "DEFAULT -des -des3 rc4-hmac rc4-hmac-exp",
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_DES3_CBC_SHA1, ENCTYPE_ARCFOUR_HMAC,
        ENCTYPE_DES_CBC_CRC, ENCTYPE_DES_CBC_MD5, ENCTYPE_DES_CBC_MD4, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_ARCFOUR_HMAC, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_ARCFOUR_HMAC, ENCTYPE_ARCFOUR_HMAC_EXP, 0 }
    },
    /* Default set with family moved to front */
    { "des3 +DEFAULT",
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_DES3_CBC_SHA1, 0 },
      { ENCTYPE_DES3_CBC_SHA1, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 },
      { ENCTYPE_DES3_CBC_SHA1, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96, 0 }
    },
    /* Two families with default set removed (exotic case), enctype added */
    { "aes +rc4 -DEFaulT des3-hmac-sha1",
      { ENCTYPE_AES128_CTS_HMAC_SHA1_96, ENCTYPE_DES3_CBC_SHA1,
        ENCTYPE_ARCFOUR_HMAC, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_DES3_CBC_SHA1, 0 },
      { ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_DES3_CBC_SHA1, 0 }
    }
};

static void show_enctypes(krb5_context ctx, krb5_enctype *list)
{
    unsigned int i;

    for (i = 0; list[i]; i++) {
        fprintf(stderr, "%d", (int) list[i]);
        if (list[i + 1])
            fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
}

static void compare(krb5_context ctx, krb5_enctype *result,
                    krb5_enctype *expected, const char *profstr,
                    krb5_boolean weak)
{
    unsigned int i;

    for (i = 0; result[i]; i++) {
        if (result[i] != expected[i])
            break;
    }
    if (!result[i] && !expected[i]) /* Success! */
        return;
    fprintf(stderr, "Unexpected result while parsing: %s\n", profstr);
    fprintf(stderr, "Expected: ");
    show_enctypes(ctx, expected);
    fprintf(stderr, "Result: ");
    show_enctypes(ctx, result);
    fprintf(stderr, "allow_weak_crypto was %s\n", weak ? "true" : "false");
    exit(1);
}

int
main(int argc, char **argv)
{
    krb5_context ctx;
    krb5_error_code ret;
    krb5_enctype *list;
    krb5_boolean weak;
    unsigned int i;
    char *copy;

    ret = krb5_init_context(&ctx);
    if (ret) {
        com_err("krb5_init_context", ret, "");
        return 2;
    }
    for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
        for (weak = FALSE; weak <= TRUE; weak++) {
            ctx->allow_weak_crypto = weak;
            copy = strdup(tests[i].str);
            ret = krb5int_parse_enctype_list(ctx, copy, tests[i].defaults,
                                             &list);
            if (ret) {
                com_err("krb5int_parse_enctype_list", ret, "");
                return 2;
            }
            compare(ctx, list,
                    (weak) ? tests[i].expected : tests[i].expected_noweak,
                    tests[i].str, weak);
            free(copy);
            free(list);
        }
    }
    return 0;
}

