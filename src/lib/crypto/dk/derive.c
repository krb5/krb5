#include "k5-int.h"
#include "dk.h"

krb5_error_code
krb5_derive_key(enc, inkey, outkey, in_constant)
     krb5_const struct krb5_enc_provider *enc;
     krb5_const krb5_keyblock *inkey;
     krb5_keyblock *outkey;
     krb5_const krb5_data *in_constant;
{
    size_t blocksize, keybytes, keylength, n;
    unsigned char *inblockdata, *outblockdata, *rawkey;
    krb5_data inblock, outblock;

    (*(enc->block_size))(&blocksize);
    (*(enc->keysize))(&keybytes, &keylength);

    if ((inkey->length != keylength) ||
	(outkey->length != keylength))
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate and set up buffers */

    if ((inblockdata = (unsigned char *) malloc(blocksize)) == NULL)
	return(ENOMEM);

    if ((outblockdata = (unsigned char *) malloc(blocksize)) == NULL) {
	return(ENOMEM);
	free(inblockdata);
    }

    if ((rawkey = (unsigned char *) malloc(keybytes)) == NULL) {
	return(ENOMEM);
	free(outblockdata);
	free(inblockdata);
    }

    inblock.data = inblockdata;
    inblock.length = blocksize;

    outblock.data = outblockdata;
    outblock.length = blocksize;

    /* initialize the input block */

    if (in_constant->length == inblock.length) {
	memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
	krb5_nfold(in_constant->length*8, in_constant->data,
		   inblock.length*8, inblock.data);
    }

    /* loop encrypting the blocks until enough key bytes are generated */

    n = 0;
    while (n < keybytes) {
	(*(enc->encrypt))(inkey, 0, &inblock, &outblock);

	if ((keybytes - n) <= outblock.length) {
	    memcpy(rawkey+n, outblock.data, (keybytes - n));
	    break;
	}

	memcpy(rawkey+n, outblock.data, outblock.length);
	memcpy(inblock.data, outblock.data, outblock.length);
	n += outblock.length;
    }

    /* postprocess the key */

    inblock.data = rawkey;
    inblock.length = keybytes;

    (*(enc->make_key))(&inblock, outkey);

    /* clean memory, free resources and exit */

    memset(inblockdata, 0, blocksize);
    memset(outblockdata, 0, blocksize);
    memset(rawkey, 0, keybytes);

    free(rawkey);
    free(outblockdata);
    free(inblockdata);

    return(0);
}

