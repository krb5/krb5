#include "k5-int.h"
#include "etypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_c_make_random_key(context, enctype, random_key)
     krb5_context context;
     krb5_enctype enctype;
     krb5_keyblock *random_key;
{
    int i;
    krb5_error_code ret;
    struct krb5_enc_provider *enc;
    size_t keybytes, keylength;
    krb5_data random;
    unsigned char *bytes;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    enc = krb5_enctypes_list[i].enc;

    (*(enc->keysize))(&keybytes, &keylength);

    if ((bytes = (unsigned char *) malloc(keybytes)) == NULL)
	return(ENOMEM);
    if ((random_key->contents = (krb5_octet *) malloc(keylength)) == NULL) {
	free(bytes);
	return(ENOMEM);
    }

    random.data = bytes;
    random.length = keybytes;

    if (ret = krb5_c_random_make_octets(context, &random))
	goto cleanup;

    random_key->magic = KV5M_KEYBLOCK;
    random_key->enctype = enctype;
    random_key->length = keylength;

    ret = ((*(enc->make_key))(&random, random_key));

cleanup:
    memset(bytes, 0, keybytes);
    free(bytes);

    if (ret) {
	memset(random_key->contents, 0, keylength);
	free(random_key->contents);
    }

    return(ret);
}
