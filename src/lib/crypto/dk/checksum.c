#include "k5-int.h"
#include "etypes.h"
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

krb5_error_code
krb5_dk_make_checksum(hash, key, usage, input, output)
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    int i;
    struct krb5_enc_provider *enc;
    size_t blocksize, keybytes, keylength;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain;
    unsigned char *kcdata;
    krb5_keyblock kc;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    enc = krb5_enctypes_list[i].enc;

    /* allocate and set to-be-derived keys */

    (*(enc->block_size))(&blocksize);
    (*(enc->keysize))(&keybytes, &keylength);

    /* key->length will be tested in enc->encrypt
       output->length will be tested in krb5_hmac */

    if ((kcdata = (unsigned char *) malloc(keylength)) == NULL)
	return(ENOMEM);

    kc.contents = kcdata;
    kc.length = keylength;

    /* derive the key */
 
    datain.data = constantdata;
    datain.length = K5CLENGTH;

    datain.data[0] = (usage>>24)&0xff;
    datain.data[1] = (usage>>16)&0xff;
    datain.data[2] = (usage>>8)&0xff;
    datain.data[3] = usage&0xff;

    datain.data[4] = 0x99;

    if (ret = krb5_derive_key(enc, key, &kc, &datain))
	goto cleanup;

    /* hash the data */

    datain = *input;

    if (ret = krb5_hmac(hash, &kc, 1, &datain, output))
	memset(output->data, 0, output->length);

    /* ret is set correctly by the prior call */

cleanup:
    memset(kcdata, 0, keylength);

    free(kcdata);

    return(ret);
}
