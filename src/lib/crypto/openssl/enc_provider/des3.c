/* lib/crypto/openssl/enc_provider/des3.c
 */

#include "k5-int.h"
#include "des_int.h"
#include <aead.h>
#include <rand2key.h>
#include <openssl/evp.h>


#define DES_BLOCK_SIZE  8

static krb5_error_code
validate(const krb5_keyblock *key, const krb5_data *ivec,
		      const krb5_data *input, const krb5_data *output)
{
    /* key->enctype was checked by the caller */

    if (key->length != KRB5_MIT_DES3_KEYSIZE)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%DES_BLOCK_SIZE) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

    return 0;
}

static krb5_error_code
validate_iov(const krb5_keyblock *key, const krb5_data *ivec,
			  const krb5_crypto_iov *data, size_t num_data)
{
    size_t i, input_length;

    for (i = 0, input_length = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];
	if (ENCRYPT_IOV(iov))
	    input_length += iov->data.length;
    }

    if (key->length != KRB5_MIT_DES3_KEYSIZE)
	return(KRB5_BAD_KEYSIZE);
    if ((input_length%DES_BLOCK_SIZE) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);

    return 0;
}

static krb5_error_code
k5_des3_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
		const krb5_data *input, krb5_data *output)
{
    int              ret = 0, tmp_len = 0;
    unsigned int     tmp_buf_len = 0;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf = NULL;
    EVP_CIPHER_CTX   ciph_ctx;

    ret = validate(key, ivec, input, output);
    if (ret)
	return ret;

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    tmp_buf_len = output->length * 2;
    tmp_buf = OPENSSL_malloc(tmp_buf_len);
    if (!tmp_buf)
        return ENOMEM;

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL, keybuf,
                             (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf, &tmp_len,
                                (unsigned char *)input->data, input->length);
        if (!ret || output->length < (unsigned int)tmp_len) {
            ret = KRB5_CRYPTO_INTERNAL;
        } else {
            output->length = tmp_len;
            ret = EVP_EncryptFinal_ex(&ciph_ctx, tmp_buf+tmp_len, &tmp_len);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret == 1)
        memcpy(output->data,tmp_buf, output->length);

    memset(tmp_buf, 0, tmp_buf_len);
    OPENSSL_free(tmp_buf);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;

    return 0;

}

static krb5_error_code
k5_des3_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
		const krb5_data *input, krb5_data *output)
{
    int              ret = 0, tmp_len = 0;
    unsigned int     tmp_buf_len = 0;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf = NULL;
    EVP_CIPHER_CTX   ciph_ctx;

    ret = validate(key, ivec, input, output);
    if (ret)
	return ret;

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    tmp_buf_len = output->length;
    tmp_buf=OPENSSL_malloc(tmp_buf_len);
    if (!tmp_buf)
        return ENOMEM;

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL, keybuf,
                             (ivec) ? (unsigned char*)ivec->data: NULL);
    if (ret) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
        ret = EVP_DecryptUpdate(&ciph_ctx, tmp_buf,  &tmp_len,
                                (unsigned char *)input->data, input->length);
        if (!ret || output->length < (unsigned int)tmp_len) {
            ret = KRB5_CRYPTO_INTERNAL;
        } else {
            output->length = tmp_len;
            ret = EVP_DecryptFinal_ex(&ciph_ctx, tmp_buf+tmp_len, &tmp_len);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    if (ret == 1)
        memcpy(output->data,tmp_buf, output->length);

    memset(tmp_buf,0,tmp_buf_len);
    OPENSSL_free(tmp_buf);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;
    return 0;

}

static krb5_error_code
k5_des3_encrypt_iov(const krb5_keyblock *key,
		    const krb5_data *ivec,
		    krb5_crypto_iov *data,
		    size_t num_data)
{
    int                    ret = 0;
    int                    tmp_len = MIT_DES_BLOCK_LENGTH;
    int                    oblock_len = MIT_DES_BLOCK_LENGTH*num_data;
    unsigned char         *iblock = NULL, *oblock = NULL;
    unsigned char         *keybuf = NULL;
    struct iov_block_state input_pos, output_pos;
    EVP_CIPHER_CTX         ciph_ctx;

    ret = validate_iov(key, ivec, data, num_data);
    if (ret)
        return ret;

    iblock = OPENSSL_malloc(MIT_DES_BLOCK_LENGTH);
    if (!iblock)
        return ENOMEM;
    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock){
        OPENSSL_free(iblock);
        return ENOMEM;
    }

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    memset(oblock, 0, oblock_len);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL,
                             keybuf, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (!ret){
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        OPENSSL_free(iblock);
        OPENSSL_free(oblock);
        return KRB5_CRYPTO_INTERNAL;
    }

    EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblock, MIT_DES_BLOCK_LENGTH,
                                     data, num_data, &input_pos))
            break;

        if (input_pos.iov_pos == num_data)
            break;

        ret = EVP_EncryptUpdate(&ciph_ctx, oblock, &tmp_len,
                                (unsigned char *)iblock, input_pos.data_pos);
        if (!ret) break;

        krb5int_c_iov_put_block(data, num_data,
                                oblock, MIT_DES_BLOCK_LENGTH, &output_pos);
    }

    if(ret)
        ret = EVP_EncryptFinal_ex(&ciph_ctx, oblock+input_pos.data_pos, &tmp_len);

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    memset(iblock,0,sizeof(iblock));
    memset(oblock,0,sizeof(oblock));
    OPENSSL_free(iblock);
    OPENSSL_free(oblock);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
k5_des3_decrypt_iov(const krb5_keyblock *key,
		    const krb5_data *ivec,
		    krb5_crypto_iov *data,
		    size_t num_data)
{
    int                    ret = 0;
    int                    tmp_len = MIT_DES_BLOCK_LENGTH;
    int                    oblock_len = MIT_DES_BLOCK_LENGTH * num_data;
    unsigned char         *iblock = NULL, *oblock = NULL;
    unsigned char         *keybuf = NULL ;
    struct iov_block_state input_pos, output_pos;
    EVP_CIPHER_CTX         ciph_ctx;

    ret = validate_iov(key, ivec, data, num_data);
    if (ret)
        return ret;

    iblock = OPENSSL_malloc(MIT_DES_BLOCK_LENGTH);
    if (!iblock)
        return ENOMEM;
    oblock = OPENSSL_malloc(oblock_len);
    if (!oblock){
        OPENSSL_free(iblock);
        return ENOMEM;
    }

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    memset(oblock, 0, oblock_len);

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL,
                             keybuf, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (!ret){
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        OPENSSL_free(iblock);
        OPENSSL_free(oblock);
        return KRB5_CRYPTO_INTERNAL;
    }

    EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);

    for (;;) {

        if (!krb5int_c_iov_get_block(iblock, MIT_DES_BLOCK_LENGTH,
                                     data, num_data, &input_pos))
            break;

        if (input_pos.iov_pos == num_data)
            break;

        ret = EVP_DecryptUpdate(&ciph_ctx, oblock, &tmp_len,
                                (unsigned char *)iblock, input_pos.data_pos);
        if (!ret) break;

        krb5int_c_iov_put_block(data, num_data,
                                oblock, MIT_DES_BLOCK_LENGTH, &output_pos);
    }

    if(ret)
        ret = EVP_DecryptFinal_ex(&ciph_ctx,
                                  oblock + input_pos.data_pos, &tmp_len);

    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    memset(iblock,0,sizeof(iblock));
    memset(oblock,0,sizeof(oblock));
    OPENSSL_free(iblock);
    OPENSSL_free(oblock);

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

const struct krb5_enc_provider krb5int_enc_des3 = {
    DES_BLOCK_SIZE,
    KRB5_MIT_DES3_KEY_BYTES, KRB5_MIT_DES3_KEYSIZE,
    k5_des3_encrypt,
    k5_des3_decrypt,
    krb5int_des3_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state,
    k5_des3_encrypt_iov,
    k5_des3_decrypt_iov
};

