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
#include "etypes.h"
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

krb5_error_code
krb5_dk_make_checksum(hash, key, usage, input, output)
     const struct krb5_hash_provider *hash;
     const krb5_keyblock *key;
     krb5_keyusage usage;
     const krb5_data *input;
     krb5_data *output;
{
    int i;
    const struct krb5_enc_provider *enc;
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
 
    datain.data = (char *) constantdata;
    datain.length = K5CLENGTH;

    datain.data[0] = (usage>>24)&0xff;
    datain.data[1] = (usage>>16)&0xff;
    datain.data[2] = (usage>>8)&0xff;
    datain.data[3] = usage&0xff;

    datain.data[4] = (char) 0x99;

    if ((ret = krb5_derive_key(enc, key, &kc, &datain)) != 0)
	goto cleanup;

    /* hash the data */

    datain = *input;

    if ((ret = krb5_hmac(hash, &kc, 1, &datain, output)) != 0)
	memset(output->data, 0, output->length);

    /* ret is set correctly by the prior call */

cleanup:
    memset(kcdata, 0, keylength);

    free(kcdata);

    return(ret);
}

#ifdef ATHENA_DES3_KLUDGE
krb5_error_code
krb5_marc_dk_make_checksum(hash, key, usage, input, output)
     const struct krb5_hash_provider *hash;
     const krb5_keyblock *key;
     krb5_keyusage usage;
     const krb5_data *input;
     krb5_data *output;
{
    int i;
    struct krb5_enc_provider *enc;
    size_t blocksize, keybytes, keylength;
    krb5_error_code ret;
    unsigned char constantdata[K5CLENGTH];
    krb5_data datain[2];
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
 
    datain[0].data = constantdata;
    datain[0].length = K5CLENGTH;

    datain[0].data[0] = (usage>>24)&0xff;
    datain[0].data[1] = (usage>>16)&0xff;
    datain[0].data[2] = (usage>>8)&0xff;
    datain[0].data[3] = usage&0xff;

    datain[0].data[4] = 0x99;

    if ((ret = krb5_derive_key(enc, key, &kc, &datain[0])) != 0)
	goto cleanup;

    /* hash the data */

    datain[0].length = 4;
    datain[0].data[0] = (input->length>>24)&0xff;
    datain[0].data[1] = (input->length>>16)&0xff;
    datain[0].data[2] = (input->length>>8)&0xff;
    datain[0].data[3] = input->length&0xff;

    datain[1] = *input;

    if ((ret = krb5_hmac(hash, &kc, 2, datain, output)) != 0)
	memset(output->data, 0, output->length);

    /* ret is set correctly by the prior call */

cleanup:
    memset(kcdata, 0, keylength);

    free(kcdata);

    return(ret);
}
#endif /* ATHENA_DES3_KLUDGE */
