/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/sha1/shs.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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

#include "shs.h"
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>
#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

/* Initialize the SHS values */
void shsInit(SHS_INFO *shsInfo)
{
    EVP_MD_CTX_init(&shsInfo->ossl_sha1_ctx );
    EVP_DigestInit_ex(&shsInfo->ossl_sha1_ctx , EVP_sha1(), NULL);
    shsInfo->digestLen = 0;
    memset(shsInfo->digestBuf, 0 , sizeof(shsInfo->digestBuf));
}

/* Update SHS for a block of data */

void shsUpdate(SHS_INFO *shsInfo, const SHS_BYTE *buffer, unsigned int count)
{
    EVP_DigestUpdate(&shsInfo->ossl_sha1_ctx , buffer, count);
}
/* Final wrapup - pad to SHS_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void shsFinal(SHS_INFO *shsInfo)
{
    EVP_DigestFinal_ex(&shsInfo->ossl_sha1_ctx ,(unsigned char *)shsInfo->digestBuf , &shsInfo->digestLen);
    EVP_MD_CTX_cleanup(&shsInfo->ossl_sha1_ctx );
}
