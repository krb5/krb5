
#ifndef    KRB5_RSA_MD5__
#define    KRB5_RSA_MD5__

#include <openssl/evp.h>
#include <openssl/md5.h>

/* Data structure for MD5 (Message-Digest) computation */
typedef struct {
    EVP_MD_CTX ossl_md5_ctx;
    krb5_int32 * digest_len;
    krb5_ui_4 i[2];              /* number of _bits_ handled mod 2^64 */
    krb5_ui_4 buf[4];            /* scratch buffer */
    unsigned char in[64];        /* input buffer */
    unsigned char digest[16];    /* actual digest after MD5Final call */
} krb5_MD5_CTX;

extern void krb5_MD5Init(krb5_MD5_CTX *);
extern void krb5_MD5Update(krb5_MD5_CTX *,const unsigned char *,unsigned int);
extern void krb5_MD5Final(krb5_MD5_CTX *);

#define    RSA_MD5_CKSUM_LENGTH            16
#define    OLD_RSA_MD5_DES_CKSUM_LENGTH    16
#define    NEW_RSA_MD5_DES_CKSUM_LENGTH    24
#define    RSA_MD5_DES_CONFOUND_LENGTH     8

#endif /* KRB5_RSA_MD5__ */
