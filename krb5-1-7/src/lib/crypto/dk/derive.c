/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "dk.h"

krb5_error_code
krb5_derive_key(const struct krb5_enc_provider *enc,
		const krb5_keyblock *inkey, krb5_keyblock *outkey,
		const krb5_data *in_constant)
{
    size_t blocksize, keybytes, keylength, n;
    unsigned char *inblockdata, *outblockdata, *rawkey;
    krb5_data inblock, outblock;

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;

    if ((inkey->length != keylength) ||
	(outkey->length != keylength))
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate and set up buffers */

    if ((inblockdata = (unsigned char *) malloc(blocksize)) == NULL)
	return(ENOMEM);

    if ((outblockdata = (unsigned char *) malloc(blocksize)) == NULL) {
	free(inblockdata);
	return(ENOMEM);
    }

    if ((rawkey = (unsigned char *) malloc(keybytes)) == NULL) {
	free(outblockdata);
	free(inblockdata);
	return(ENOMEM);
    }

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* initialize the input block */

    if (in_constant->length == inblock.length) {
	memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
	krb5_nfold(in_constant->length*8, (unsigned char *) in_constant->data,
		   inblock.length*8, (unsigned char *) inblock.data);
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

    inblock.data = (char *) rawkey;
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


krb5_error_code
krb5_derive_random(const struct krb5_enc_provider *enc,
		   const krb5_keyblock *inkey, krb5_data *outrnd,
		   const krb5_data *in_constant)
{
    size_t blocksize, keybytes, keylength, n;
    unsigned char *inblockdata, *outblockdata, *rawkey;
    krb5_data inblock, outblock;

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;

    if ((inkey->length != keylength) ||
	(outrnd->length != keybytes))
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate and set up buffers */

    if ((inblockdata = (unsigned char *) malloc(blocksize)) == NULL)
	return(ENOMEM);

    if ((outblockdata = (unsigned char *) malloc(blocksize)) == NULL) {
	free(inblockdata);
	return(ENOMEM);
    }

    if ((rawkey = (unsigned char *) malloc(keybytes)) == NULL) {
	free(outblockdata);
	free(inblockdata);
	return(ENOMEM);
    }

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* initialize the input block */

    if (in_constant->length == inblock.length) {
	memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
	krb5_nfold(in_constant->length*8, (unsigned char *) in_constant->data,
		   inblock.length*8, (unsigned char *) inblock.data);
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

    memcpy (outrnd->data, rawkey, keybytes);

    /* clean memory, free resources and exit */

    memset(inblockdata, 0, blocksize);
    memset(outblockdata, 0, blocksize);
    memset(rawkey, 0, keybytes);

    free(rawkey);
    free(outblockdata);
    free(inblockdata);

    return(0);
}

#if 0
#include "etypes.h"
void
krb5_random2key (krb5_enctype enctype, krb5_data *inblock,
		 krb5_keyblock *outkey)
{
    int i;
    const struct krb5_enc_provider *enc;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	abort ();

    enc = krb5_enctypes_list[i].enc;

    enc->make_key (inblock, outkey);
}
#endif
