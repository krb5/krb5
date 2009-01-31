/*
 * lib/crypto/keyblocks.c
 *
 * Copyright (C) 2002, 2005 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * 
 *
 * krb5_init_keyblock- a function to set up 
 *  an empty keyblock
 */


#include "k5-int.h"
#include <assert.h>

krb5_error_code   krb5int_c_init_keyblock
	(krb5_context context, krb5_enctype enctype,
	 size_t length, krb5_keyblock **out)
{
    krb5_keyblock *kb;
    kb = malloc (sizeof(krb5_keyblock));
    assert (out);
    *out = NULL;
    if (!kb) {
	return ENOMEM;
    }
    kb->magic = KV5M_KEYBLOCK;
    kb->enctype = enctype;
    kb->length = length;
    if(length) {
	kb->contents = malloc (length);
	if(!kb->contents) {
	    free (kb);
	    return ENOMEM;
	}
    } else {
	kb->contents = NULL;
    }
    *out = kb;
    return 0;
}


void 
krb5int_c_free_keyblock(krb5_context context, register krb5_keyblock *val)
{
    krb5int_c_free_keyblock_contents(context, val);
    free(val);
}

void 
krb5int_c_free_keyblock_contents(krb5_context context, krb5_keyblock *key)
{
    if (key && key->contents) {
	krb5int_zap_data (key->contents, key->length);
	free(key->contents);
	key->contents = 0;
    }
}
