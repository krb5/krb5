#include "k5-int.h"

static unsigned char kerberos[] = "kerberos";
#define kerberos_len (sizeof(kerberos)-1)

krb5_error_code
krb5_dk_string_to_key(enc, string, salt, key)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const krb5_data *string;
     krb5_const krb5_data *salt;
     krb5_keyblock *key;
{
    krb5_error_code ret;
    size_t keybytes, keylength, concatlen;
    unsigned char *concat, *foldstring, *foldkeydata;
    krb5_data indata;
    krb5_keyblock foldkey;

    /* key->length is checked by krb5_derive_key */

    (*(enc->keysize))(&keybytes, &keylength);

    concatlen = string->length+(salt?salt->length:0);

    if ((concat = (unsigned char *) malloc(concatlen)) == NULL)
	return(ENOMEM);
    if ((foldstring = (unsigned char *) malloc(keybytes)) == NULL) {
	free(concat);
	return(ENOMEM);
    }
    if ((foldkeydata = (unsigned char *) malloc(keylength)) == NULL) {
	free(foldstring);
	free(concat);
	return(ENOMEM);
    }

    /* construct input string ( = string + salt), fold it, make_key it */

    memcpy(concat, string->data, string->length);
    if (salt)
	memcpy(concat+string->length, salt->data, salt->length);

    krb5_nfold(concatlen*8, concat, keybytes*8, foldstring);

    indata.length = keybytes;
    indata.data = foldstring;
    foldkey.length = keylength;
    foldkey.contents = foldkeydata;

    (*(enc->make_key))(&indata, &foldkey);

    /* now derive the key from this one */

    indata.length = kerberos_len;
    indata.data = kerberos;

    if (ret = krb5_derive_key(enc, &foldkey, key, &indata))
	memset(key->contents, 0, key->length);

    /* ret is set correctly by the prior call */

    memset(concat, 0, concatlen);
    memset(foldstring, 0, keybytes);
    memset(foldkeydata, 0, keylength);

    free(foldkeydata);
    free(foldstring);
    free(concat);

    return(ret);
}
