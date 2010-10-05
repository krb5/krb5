/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/builtin/t_sha256.c */
/*
 * Copyright (c) 1995 - 2002 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <k5-int.h>
#include "sha2.h"

#ifndef FORTUNA
int
main (void)
{
    return 0;
}

#else

#define ONE_MILLION_A "one million a's"

struct test {
    char *str;
    unsigned char hash[64];
};

struct test tests[] = {
    { "abc",
      { 0xba, 0x78, 0x16, 0xbf,  0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde,  0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3,  0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61,  0xf2, 0x00, 0x15, 0xad }},
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      { 0x24, 0x8d, 0x6a, 0x61,  0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93,  0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59,  0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4,  0x19, 0xdb, 0x06, 0xc1 }},
    { ONE_MILLION_A,
      {0xcd,0xc7,0x6e,0x5c, 0x99,0x14,0xfb,0x92,
       0x81,0xa1,0xc7,0xe2, 0x84,0xd7,0x3e,0x67,
       0xf1,0x80,0x9a,0x48, 0xa4,0x97,0x20,0x0e,
       0x04,0x6d,0x39,0xcc, 0xc7,0x11,0x2c,0xd0 }},
    { NULL }
};

int
main (void)
{
    struct test *t;
    void *ctx = malloc(sizeof(SHA256_CTX));
    unsigned char *res = malloc(SHA256_DIGEST_LENGTH);
    char buf[1000];

    for (t = tests; t->str; ++t) {
    
        sha2Init(ctx);
        if(strcmp(t->str, ONE_MILLION_A) == 0) {
            int i;
            memset(buf, 'a', sizeof(buf));
            for(i = 0; i < 1000; i++) {
                sha2Update(ctx, buf, sizeof(buf));
            }
        } else {
            sha2Update(ctx, (unsigned char *)t->str, strlen(t->str));
        }

        sha2Final(res, ctx);
        if (memcmp (res, t->hash, SHA256_DIGEST_LENGTH) != 0) {
            int i;

            printf ("%s(\"%s\") failed\n", "SHA- 256", t->str);
            printf("should be:  ");
            for(i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                if(i > 0 && (i % 16) == 0)
                printf("\n            ");
                printf("%02x ", t->hash[i]);
            }
            printf("\nresult was: ");
            for(i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            if(i > 0 && (i % 16) == 0)
                printf("\n            ");
                printf("%02x ", res[i]);
            }
            printf("\n");
            return 1;
        }
    
        if (memcmp (res, t->hash, SHA256_DIGEST_LENGTH) != 0) {
            printf("EVP %s failed here old function where successful!\n", "SHA-256");
            return 1;
        }
    }
    free(ctx);
    free(res);
    printf ("success\n");
    return 0;
}
#endif /* FORTUNA */
