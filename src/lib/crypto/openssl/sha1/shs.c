#include "shs.h"
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <string.h>

/* Initialize the SHS values */
void shsInit(SHS_INFO *shsInfo)
{
    EVP_MD_CTX_init(&shsInfo->ossl_sha1_ctx );
    EVP_DigestInit_ex(&shsInfo->ossl_sha1_ctx , EVP_sha1(), NULL);
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
    unsigned char *digest_buf = NULL;

    digest_buf =  (unsigned char *)OPENSSL_malloc( sizeof(shsInfo->digest));

    EVP_DigestFinal_ex(&shsInfo->ossl_sha1_ctx , digest_buf , &shsInfo->digest_len); 

    memcpy(shsInfo->digest, digest_buf, shsInfo->digest_len);
    OPENSSL_free(digest_buf);
    EVP_MD_CTX_cleanup(&shsInfo->ossl_sha1_ctx );
}
