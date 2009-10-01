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


