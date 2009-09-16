/*
 */

#include "k5-int.h"
#include "des_int.h"
#include "enc_provider.h"
#include <aead.h>
#include <rand2key.h>
#include <openssl/evp.h>

#define DES_BLOCK_SIZE  8
#define DES_KEY_BYTES   7

static krb5_error_code
k5_des_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
           const krb5_data *input, krb5_data *output)
{
    int ret = 0, tmp_len = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    if (key->length != KRB5_MIT_DES_KEYSIZE)
        return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
    return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
    return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
    return(KRB5_BAD_MSIZE);

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    if ( ivec && ivec->data ) {
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
    }

    tmp_buf=OPENSSL_malloc(output->length);
    if (!tmp_buf)
        return ENOMEM;
    memset(tmp_buf,0,output->length);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_cbc(), NULL, keybuf,
                             (ivec && ivec->data) ? iv : NULL);
    if (ret) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf,  &tmp_len,
                                (unsigned char *)input->data, input->length);
        if (ret) {
            output->length = tmp_len;
            ret = EVP_EncryptFinal_ex(&ciph_ctx, tmp_buf + tmp_len, &tmp_len);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret)
        memcpy(output->data,tmp_buf, output->length);

    memset(tmp_buf,0,output->length);
    OPENSSL_free(tmp_buf);

    if (!ret)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
k5_des_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
           const krb5_data *input, krb5_data *output)
{
    /* key->enctype was checked by the caller */
    int ret = 0, tmp_len = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    if (key->length != KRB5_MIT_DES_KEYSIZE)
        return(KRB5_BAD_KEYSIZE);
    if ((input->length%8) != 0)
        return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
        return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
        return(KRB5_BAD_MSIZE);

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    if ( ivec != NULL && ivec->data ){
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
    }

    tmp_buf=OPENSSL_malloc(output->length);
    if (!tmp_buf)
        return ENOMEM;
    memset(tmp_buf,0,output->length);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_des_cbc(), NULL, keybuf,
                             (ivec && ivec->data) ? iv : NULL);
    if (ret) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
        ret = EVP_DecryptUpdate(&ciph_ctx, tmp_buf,  &tmp_len,
                                (unsigned char *)input->data, input->length);
        if (ret) {
            output->length = tmp_len;
            ret = EVP_DecryptFinal_ex(&ciph_ctx, tmp_buf+tmp_len, &tmp_len);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret)
        memcpy(output->data,tmp_buf, output->length);

    memset(tmp_buf,0,output->length );
    OPENSSL_free(tmp_buf);

    if (!ret)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
k5_des_encrypt_iov(const krb5_keyblock *key,
            const krb5_data *ivec,
            krb5_crypto_iov *data,
            size_t num_data)
{
    int ret = 0, tmp_len = 0;
    unsigned int i = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf = NULL ;
    krb5_crypto_iov *iov    = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    if (ivec  && ivec->data){
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
     }

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_cbc(), NULL,
                             keybuf, (ivec && ivec->data) ? iv : NULL);
    if (!ret)
        return KRB5_CRYPTO_INTERNAL;

    for (i = 0; i < num_data; i++) {
        iov = &data[i];
        if (iov->data.length <= 0) break;
        tmp_len = iov->data.length;

        if (ENCRYPT_DATA_IOV(iov)) {
            tmp_buf=(unsigned char *)iov->data.data;
            ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf, &tmp_len,
                                    (unsigned char *)iov->data.data, iov->data.length);
            if (!ret) break;
            iov->data.length = tmp_len;
        }
    }
    if(ret)
        ret = EVP_EncryptFinal_ex(&ciph_ctx, (unsigned char *)tmp_buf, &tmp_len);

    if (ret)
        iov->data.length += tmp_len;

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (!ret)
        return KRB5_CRYPTO_INTERNAL;
    return 0;

}

static krb5_error_code
k5_des_decrypt_iov(const krb5_keyblock *key,
           const krb5_data *ivec,
           krb5_crypto_iov *data,
           size_t num_data)
{
    int ret = 0, tmp_len = 0;
    unsigned int i = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf = NULL ;
    krb5_crypto_iov *iov    = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    if (ivec  && ivec->data){
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
     }

    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_des_cbc(), NULL,
                             keybuf, (ivec && ivec->data) ? iv : NULL);
    if (!ret)
        return KRB5_CRYPTO_INTERNAL;

    for (i = 0; i < num_data; i++) {
        iov = &data[i];
        if (iov->data.length <= 0) break;
        tmp_len = iov->data.length;

        if (ENCRYPT_DATA_IOV(iov)) {
            tmp_buf=(unsigned char *)iov->data.data;
            ret = EVP_DecryptUpdate(&ciph_ctx, tmp_buf, &tmp_len,
                                    (unsigned char *)iov->data.data, iov->data.length);
            if (!ret) break;
            iov->data.length = tmp_len;
        }
    }
    if(ret)
        ret = EVP_DecryptFinal_ex(&ciph_ctx, (unsigned char *)tmp_buf, &tmp_len);

    if (ret)
        iov->data.length += tmp_len;

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (!ret)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

const struct krb5_enc_provider krb5int_enc_des = {
    DES_BLOCK_SIZE,
    DES_KEY_BYTES, KRB5_MIT_DES_KEYSIZE,
    k5_des_encrypt,
    k5_des_decrypt,
    krb5int_des_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state,
    k5_des_encrypt_iov,
    k5_des_decrypt_iov
};

