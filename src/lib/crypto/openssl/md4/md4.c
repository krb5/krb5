/*
 *	lib/crypto/openssl/md4/md4.c
 */

#include "k5-int.h"
#include "rsa-md4.h"
#include <openssl/evp.h>
#include <openssl/md4.h>

void
krb5_MD4Init (krb5_MD4_CTX *mdContext)
{
    EVP_MD_CTX_init(&mdContext->ossl_md4_ctx );
    EVP_DigestInit_ex(&mdContext->ossl_md4_ctx, EVP_md4(), NULL);

}
void
krb5_MD4Update (krb5_MD4_CTX *mdContext, const unsigned char *inBuf, unsigned int inLen)
{
    EVP_DigestUpdate(&mdContext->ossl_md4_ctx, inBuf, inLen);
}

void
krb5_MD4Final (krb5_MD4_CTX *mdContext)
{
    EVP_DigestFinal_ex(&mdContext->ossl_md4_ctx, mdContext->digest , NULL);
    EVP_MD_CTX_cleanup(&mdContext->ossl_md4_ctx );
}

