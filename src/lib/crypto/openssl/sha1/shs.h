/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _SHS_DEFINED

#include "k5-int.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

#define _SHS_DEFINED

/* Some useful types */

typedef krb5_octet      SHS_BYTE;
typedef krb5_ui_4       SHS_LONG;

/* Define the following to use the updated SHS implementation */
#define NEW_SHS         /**/

/* The SHS block size and message digest sizes, in bytes */

#define SHS_DATASIZE    64
#define SHS_DIGESTSIZE  20

/* The structure for storing SHS info */

typedef struct {
    EVP_MD_CTX ossl_sha1_ctx;
    unsigned char   digestBuf[SHS_DIGESTSIZE]; /* output */
    unsigned int    digestLen; /* output */
} SHS_INFO;

/* Message digest functions (shs.c) */
void shsInit(SHS_INFO *shsInfo);
void shsUpdate(SHS_INFO *shsInfo, const SHS_BYTE *buffer, unsigned int count);
void shsFinal(SHS_INFO *shsInfo);


/* Keyed Message digest functions (hmac_sha.c) */
krb5_error_code hmac_sha(krb5_octet *text,
                         int text_len,
                         krb5_octet *key,
                         int key_len,
                         krb5_octet *digest);


#define NIST_SHA_CKSUM_LENGTH           SHS_DIGESTSIZE
#define HMAC_SHA_CKSUM_LENGTH           SHS_DIGESTSIZE

#endif /* _SHS_DEFINED */
