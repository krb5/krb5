#include "k5-int.h"

krb5_error_code
krb5_encrypt_helper(context, key, usage, plain, cipher)
     krb5_context context;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *plain;
     krb5_enc_data *cipher;
{
    krb5_error_code ret;
    size_t enclen;

    if (ret = krb5_c_encrypt_length(context, key->enctype, plain->length,
				    &enclen))
	return(ret);

    cipher->ciphertext.length = enclen;
    if ((cipher->ciphertext.data = (char *) malloc(enclen)) == NULL)
	return(ret);

    if (ret = krb5_c_encrypt(context, key, usage, 0, plain, cipher))
	free(cipher->ciphertext.data);

    return(ret);
}
	
