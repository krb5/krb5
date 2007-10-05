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
#include "cksumtypes.h"
#include "etypes.h"
#include "dk.h"

krb5_error_code KRB5_CALLCONV
krb5_c_make_checksum(krb5_context context, krb5_cksumtype cksumtype,
		     const krb5_keyblock *key, krb5_keyusage usage,
		     const krb5_data *input, krb5_checksum *cksum)
{
    int i, e1, e2;
    krb5_data data;
    krb5_error_code ret;
    size_t cksumlen;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    if (krb5_cksumtypes_list[i].keyhash)
	cksumlen = krb5_cksumtypes_list[i].keyhash->hashsize;
    else
	cksumlen = krb5_cksumtypes_list[i].hash->hashsize;

    cksum->length = cksumlen;

    if ((cksum->contents = (krb5_octet *) malloc(cksum->length)) == NULL)
	return(ENOMEM);

    data.length = cksum->length;
    data.data = (char *) cksum->contents;

    if (krb5_cksumtypes_list[i].keyhash) {
	/* check if key is compatible */

	if (krb5_cksumtypes_list[i].keyed_etype) {
	    for (e1=0; e1<krb5_enctypes_length; e1++) 
		if (krb5_enctypes_list[e1].etype ==
		    krb5_cksumtypes_list[i].keyed_etype)
		    break;

	    for (e2=0; e2<krb5_enctypes_length; e2++) 
		if (krb5_enctypes_list[e2].etype == key->enctype)
		    break;

	    if ((e1 == krb5_enctypes_length) ||
		(e2 == krb5_enctypes_length) ||
		(krb5_enctypes_list[e1].enc != krb5_enctypes_list[e2].enc)) {
		ret = KRB5_BAD_ENCTYPE;
		goto cleanup;
	    }
	}

	ret = (*(krb5_cksumtypes_list[i].keyhash->hash))(key, usage, 0, input, &data);
    } else if (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE) {
	ret = krb5_dk_make_checksum(krb5_cksumtypes_list[i].hash,
				    key, usage, input, &data);
    } else {
	/* no key is used */

	ret = (*(krb5_cksumtypes_list[i].hash->hash))(1, input, &data);
    }

    if (!ret) {
	cksum->magic = KV5M_CHECKSUM;
	cksum->checksum_type = cksumtype;
	if (krb5_cksumtypes_list[i].trunc_size) {
	    krb5_octet *trunc;
	    cksum->length = krb5_cksumtypes_list[i].trunc_size;
	    trunc = (krb5_octet *) realloc(cksum->contents, cksum->length);
	    if (trunc)
		cksum->contents = trunc;
	}
    }

cleanup:
    if (ret) {
	memset(cksum->contents, 0, cksum->length);
	free(cksum->contents);
	cksum->contents = NULL;
    }

    return(ret);
}
