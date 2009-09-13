
#include "k5-int.h"
#include "rsa-md5.h"
#include <openssl/evp.h>
#include <openssl/md5.h>

/* The routine krb5_MD5Init initializes the message-digest context
   mdContext. All fields are set to zero.
 */
void 
krb5_MD5Init (krb5_MD5_CTX *mdContext)
{
    EVP_MD_CTX_init(&mdContext->ossl_md5_ctx);
    EVP_DigestInit_ex(&mdContext->ossl_md5_ctx, EVP_md5(), NULL);
}

/* The routine krb5_MD5Update updates the message-digest context to
   account for the presence of each of the characters inBuf[0..inLen-1]
   in the message whose digest is being computed.
 */
void
krb5_MD5Update (krb5_MD5_CTX *mdContext, const unsigned char *inBuf, unsigned int inLen)
{
    EVP_DigestUpdate(&mdContext->ossl_md5_ctx, inBuf, inLen);
}

/* The routine krb5_MD5Final terminates the message-digest computation and
   ends with the desired message digest in mdContext->digest[0...15].
 */
void
krb5_MD5Final (krb5_MD5_CTX *mdContext)
{
    EVP_DigestFinal_ex(&mdContext->ossl_md5_ctx, mdContext->digest, NULL);
    EVP_MD_CTX_cleanup(&mdContext->ossl_md5_ctx);
}

