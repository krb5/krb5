/*
 */

#include "k5-int.h"
#include "des_int.h"
#include <aead.h>
#include <openssl/evp.h>


#define DES_BLOCK_SIZE  8
#define DES3_KEY_BYTES  21
#define DES3_KEY_LEN    24

static krb5_error_code
validate(const krb5_keyblock *key, const krb5_data *ivec,
		      const krb5_data *input, const krb5_data *output)
{
    mit_des3_key_schedule schedule;

    /* key->enctype was checked by the caller */

    if (key->length != DES3_KEY_LEN)
	return(KRB5_BAD_KEYSIZE);
    if ((input->length%DES_BLOCK_SIZE) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);
    if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

    switch (mit_des3_key_sched(*(mit_des3_cblock *)key->contents,
			       schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }
    return 0;
}

static krb5_error_code
validate_iov(const krb5_keyblock *key, const krb5_data *ivec,
			  const krb5_crypto_iov *data, size_t num_data)
{
    size_t i, input_length;
    mit_des3_key_schedule schedule;

    for (i = 0, input_length = 0; i < num_data; i++) {
	const krb5_crypto_iov *iov = &data[i];

	if (ENCRYPT_IOV(iov))
	    input_length += iov->data.length;
    }

    if (key->length != DES3_KEY_LEN)
	return(KRB5_BAD_KEYSIZE);
    if ((input_length%DES_BLOCK_SIZE) != 0)
	return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
	return(KRB5_BAD_MSIZE);

    switch (mit_des3_key_sched(*(mit_des3_cblock *)key->contents,
			       schedule)) {
    case -1:
	return(KRB5DES_BAD_KEYPAR);
    case -2:
	return(KRB5DES_WEAK_KEY);
    }
    return 0;
}

static krb5_error_code
k5_des3_encrypt(const krb5_keyblock *key, const krb5_data *ivec,
		const krb5_data *input, krb5_data *output)
{

    int ret = 0, tmp_len = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    ret = validate(key, ivec, input, output);
    if (ret)
	return ret;

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    if (ivec && ivec->data) {
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
    }

    tmp_buf = OPENSSL_malloc(output->length);
    if (!tmp_buf)
        return ENOMEM;

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL, keybuf,
                             (ivec && ivec->data) ? iv : NULL);
    if (ret) {
        EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
        ret = EVP_EncryptUpdate(&ciph_ctx, tmp_buf,  &tmp_len,
                                (unsigned char *)input->data, input->length);
        if (ret) {
            output->length = tmp_len;
            ret = EVP_EncryptFinal_ex(&ciph_ctx, tmp_buf+tmp_len, &tmp_len);
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
k5_des3_decrypt(const krb5_keyblock *key, const krb5_data *ivec,
		const krb5_data *input, krb5_data *output)
{
    int ret = 0, tmp_len = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf  = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    ret = validate(key, ivec, input, output);
    if (ret)
	return ret;

    keybuf=key->contents;
    keybuf[key->length] = '\0';

    if (ivec && ivec->data) {
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
    }

    tmp_buf=OPENSSL_malloc(output->length);
    if (!tmp_buf)
        return ENOMEM;

    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL, keybuf,
                             (ivec && ivec->data) ? iv: NULL);
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

    memset(tmp_buf,0,output->length);
    OPENSSL_free(tmp_buf);

    if (!ret)
        return KRB5_CRYPTO_INTERNAL;
    return 0;

}

static krb5_error_code
k5_des3_make_key(const krb5_data *randombits, krb5_keyblock *key)
{
    int i;

    if (key->length != DES3_KEY_LEN)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != DES3_KEY_BYTES)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;

    /* take the seven bytes, move them around into the top 7 bits of the
       8 key bytes, then compute the parity bits.  Do this three times. */

    for (i=0; i<3; i++) {
	memcpy(key->contents+i*8, randombits->data+i*7, 7);
	key->contents[i*8+7] = (((key->contents[i*8]&1)<<1) |
				((key->contents[i*8+1]&1)<<2) |
				((key->contents[i*8+2]&1)<<3) |
				((key->contents[i*8+3]&1)<<4) |
				((key->contents[i*8+4]&1)<<5) |
				((key->contents[i*8+5]&1)<<6) |
				((key->contents[i*8+6]&1)<<7));

	mit_des_fixup_key_parity(key->contents+i*8);
    }

    return(0);
}

static krb5_error_code
validate_and_schedule_iov(const krb5_keyblock *key, const krb5_data *ivec,
                          const krb5_crypto_iov *data, size_t num_data,
                          mit_des3_key_schedule *schedule)
{
    size_t i, input_length;

    for (i = 0, input_length = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    if (key->length != 24)
        return(KRB5_BAD_KEYSIZE);
    if ((input_length%8) != 0)
        return(KRB5_BAD_MSIZE);
    if (ivec && (ivec->length != 8))
        return(KRB5_BAD_MSIZE);

    switch (mit_des3_key_sched(*(mit_des3_cblock *)key->contents,
                               *schedule)) {
    case -1:
        return(KRB5DES_BAD_KEYPAR);
    case -2:
        return(KRB5DES_WEAK_KEY);
    }
    return 0;
}

static krb5_error_code
k5_des3_encrypt_iov(const krb5_keyblock *key,
		    const krb5_data *ivec,
		    krb5_crypto_iov *data,
		    size_t num_data)
{
#if 0
    int ret = 0, tmp_len = 0;
    unsigned int i = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    unsigned char   *keybuf = NULL ;
    krb5_crypto_iov *iov    = NULL;
    unsigned char   *tmp_buf = NULL;
    unsigned char   iv[EVP_MAX_IV_LENGTH];

    ret = validate_iov(key, ivec, data, num_data);
    if (ret)
	return ret;

    if (ivec && ivec->data){
        memset(iv,0,sizeof(iv));
        memcpy(iv,ivec->data,ivec->length);
    }


    EVP_CIPHER_CTX_init(&ciph_ctx);

    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_des_ede3_cbc(), NULL,
                             keybuf, (ivec && ivec->data) ? iv : NULL);
    if (!ret)
        return KRB5_CRYPTO_INTERNAL;

    for (i = 0; i < num_data; i++) {
        iov = &data[i];
        if (iov->data.length <= 0) break;
        tmp_len = iov->data.length;

        if (ENCRYPT_IOV(iov)) {
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
#endif

//#if 0
    mit_des3_key_schedule schedule;
    krb5_error_code err;

    err = validate_and_schedule_iov(key, ivec, data, num_data, &schedule);
    if (err)
        return err;

    /* this has a return value, but the code always returns zero */
    krb5int_des3_cbc_encrypt_iov(data, num_data,
			     schedule[0], schedule[1], schedule[2],
			     ivec != NULL ? (unsigned char *) ivec->data : NULL);

    zap(schedule, sizeof(schedule));
    return(0);
//#endif
}

static krb5_error_code
k5_des3_decrypt_iov(const krb5_keyblock *key,
		    const krb5_data *ivec,
		    krb5_crypto_iov *data,
		    size_t num_data)
{
    mit_des3_key_schedule schedule;
    krb5_error_code err;

    err = validate_and_schedule_iov(key, ivec, data, num_data, &schedule);
    if (err)
        return err;

    /* this has a return value, but the code always returns zero */
    krb5int_des3_cbc_decrypt_iov(data, num_data,
                                 schedule[0], schedule[1], schedule[2],
                                 ivec != NULL ? (unsigned char *) ivec->data : NULL);

    zap(schedule, sizeof(schedule));

    return(0);
}

const struct krb5_enc_provider krb5int_enc_des3 = {
    DES_BLOCK_SIZE,
    DES3_KEY_BYTES, DES3_KEY_LEN,
    k5_des3_encrypt,
    k5_des3_decrypt,
    k5_des3_make_key,
    krb5int_des_init_state,
    krb5int_default_free_state,
    k5_des3_encrypt_iov,
    k5_des3_decrypt_iov
};

