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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_c_string_to_key(context, enctype, string, salt, key)
     krb5_context context;
     krb5_enctype enctype;
     krb5_const krb5_data *string;
     krb5_const krb5_data *salt;
     krb5_keyblock *key;
{
    int i;
    krb5_error_code ret;
    struct krb5_enc_provider *enc;
    size_t keybytes, keylength;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    enc = krb5_enctypes_list[i].enc;

    (*(enc->keysize))(&keybytes, &keylength);

    if ((key->contents = (krb5_octet *) malloc(keylength)) == NULL)
	return(ENOMEM);

    key->magic = KV5M_KEYBLOCK;
    key->enctype = enctype;
    key->length = keylength;

    if (ret = ((*(krb5_enctypes_list[i].str2key))(enc, string, salt, key))) {
	memset(key->contents, 0, keylength);
	free(key->contents);
    }

    return(ret);
}
