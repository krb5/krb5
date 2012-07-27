/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/asn.1/make-vectors.c - Generate ASN.1 test vectors using asn1c */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
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
 */

/*
 * This program generates test vectors using asn1c, to be included in other
 * test programs which exercise the krb5 ASN.1 encoder and decoder functions.
 * It is intended to be used via "make test-vectors".  Currently, test vectors
 * are only generated for OTP preauth objects.
 */

#include <OTP-TOKENINFO.h>
#include <PA-OTP-CHALLENGE.h>
#include <PA-OTP-REQUEST.h>
#include <PA-OTP-ENC-REQUEST.h>

static unsigned char buf[8192];
static size_t buf_pos;

/* Minimal OTP-TOKENINFO */
static OTP_TOKENINFO_t token_info_1 = { { "\0\0\0\0", 4, 0 } };

/* Maximal OTP-TOKENINFO */
static UTF8String_t vendor = { "Examplecorp", 11 };
static OCTET_STRING_t challenge = { "hark!", 5 };
static Int32_t otp_length = 10;
static OTPFormat_t otp_format; /* Initialized to 2 in main(). */
static OCTET_STRING_t token_id = { "yourtoken", 9 };
static AnyURI_t otp_alg = { "urn:ietf:params:xml:ns:keyprov:pskc:hotp", 40 };
static unsigned int sha256_arcs[] = { 2, 16, 840, 1, 101, 3, 4, 2, 1 };
static unsigned int sha1_arcs[] = { 1, 3, 14, 3, 2, 26 };
static AlgorithmIdentifier_t alg_sha256, alg_sha1; /* Initialized in main(). */
static AlgorithmIdentifier_t *algs[] = { &alg_sha256, &alg_sha1 };
static struct supportedHashAlg hash_algs = { algs, 2, 2 };
static Int32_t iter_count = 1000;
/* Flags are nextOTP | combine | collect-pin | must-encrypt-nonce |
 * separate-pin-required | check-digit */
static OTP_TOKENINFO_t token_info_2 = { { "\x77\0\0\0", 4, 0 }, &vendor,
                                        &challenge, &otp_length, &otp_format,
                                        &token_id, &otp_alg, &hash_algs,
                                        &iter_count };

/* Minimal PA-OTP-CHALLENGE */
static OTP_TOKENINFO_t *tinfo_1[] = { &token_info_1 };
static PA_OTP_CHALLENGE_t challenge_1 = { { "minnonce", 8 }, NULL,
                                          { { tinfo_1, 1, 1 } } };

/* Maximal PA-OTP-CHALLENGE */
static OTP_TOKENINFO_t *tinfo_2[] = { &token_info_1, &token_info_2 };
static UTF8String_t service = { "testservice", 11 };
static KerberosString_t salt = { "keysalt", 7 };
static OCTET_STRING_t s2kparams = { "1234", 4 };
static PA_OTP_CHALLENGE_t challenge_2 = { { "maxnonce", 8 }, &service,
                                          { { tinfo_2, 2, 2 } }, &salt,
                                          &s2kparams };

/* Minimal PA-OTP-REQUEST */
static UInt32_t kvno;           /* Initialized to 5 in main(). */
static PA_OTP_REQUEST_t request_1 = { { "\0\0\0\0", 4, 0 }, NULL,
                                      { 0, &kvno,
                                        { "krbASN.1 test message", 21 } } };

/* Maximal PA-OTP-REQUEST */
/* Flags are nextOTP | combine */
static OCTET_STRING_t nonce = { "nonce", 5 };
static OCTET_STRING_t otp_value = { "frogs", 5 };
static UTF8String_t otp_pin = { "myfirstpin", 10 };
/* Corresponds to Unix time 771228197 */
static KerberosTime_t otp_time = { "19940610060317Z", 15 };
static OCTET_STRING_t counter = { "346", 3 };
static PA_OTP_REQUEST_t request_2 = { { "\x60\0\0\0", 4, 0 }, &nonce,
                                      { 0, &kvno,
                                        { "krbASN.1 test message", 21 } },
                                      &alg_sha256, &iter_count, &otp_value,
                                      &otp_pin, &challenge, &otp_time,
                                      &counter, &otp_format, &token_id,
                                      &otp_alg, &vendor };

/* PA-OTP-ENC-REQUEST */
static PA_OTP_ENC_REQUEST_t enc_request = { { "krb5data", 8 } };

static int
consume(const void *data, size_t size, void *dummy)
{
    memcpy(buf + buf_pos, data, size);
    buf_pos += size;
    return 0;
}

/* Display a C string literal representing the contents of buf, and
 * reinitialize buf_pos for the next encoding operation. */
static void
printbuf(void)
{
    size_t i;

    for (i = 0; i < buf_pos; i++) {
        printf("%02X", buf[i]);
        if (i + 1 < buf_pos)
            printf(" ");
    }
    buf_pos = 0;
}

int
main()
{
    /* Initialize values which can't use static initializers. */
    asn_long2INTEGER(&otp_format, 2);  /* Alphanumeric */
    asn_long2INTEGER(&kvno, 5);
    OBJECT_IDENTIFIER_set_arcs(&alg_sha256.algorithm, sha256_arcs,
                               sizeof(*sha256_arcs),
                               sizeof(sha256_arcs) / sizeof(*sha256_arcs));
    OBJECT_IDENTIFIER_set_arcs(&alg_sha1.algorithm, sha1_arcs,
                               sizeof(*sha1_arcs),
                               sizeof(sha1_arcs) / sizeof(*sha1_arcs));

    printf("Minimal OTP-TOKEN-INFO:\n");
    der_encode(&asn_DEF_OTP_TOKENINFO, &token_info_1, consume, NULL);
    printbuf();

    printf("\nMaximal OTP-TOKEN-INFO:\n");
    der_encode(&asn_DEF_OTP_TOKENINFO, &token_info_2, consume, NULL);
    printbuf();

    printf("\nMinimal PA-OTP-CHALLENGE:\n");
    der_encode(&asn_DEF_PA_OTP_CHALLENGE, &challenge_1, consume, NULL);
    printbuf();

    printf("\nMaximal PA-OTP-CHALLENGE:\n");
    der_encode(&asn_DEF_PA_OTP_CHALLENGE, &challenge_2, consume, NULL);
    printbuf();

    printf("\nMinimal PA-OTP-REQUEST:\n");
    der_encode(&asn_DEF_PA_OTP_REQUEST, &request_1, consume, NULL);
    printbuf();

    printf("\nMaximal PA-OTP-REQUEST:\n");
    der_encode(&asn_DEF_PA_OTP_REQUEST, &request_2, consume, NULL);
    printbuf();

    printf("\nPA-OTP-ENC-REQUEST:\n");
    der_encode(&asn_DEF_PA_OTP_ENC_REQUEST, &enc_request, consume, NULL);
    printbuf();

    printf("\n");
    return 0;
}
