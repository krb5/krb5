/*
 * lib/krb425/set_key.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb_set_key for krb425
 */


#include "krb425.h"

int
krb_set_key(key, cvt)
char *key;
int cvt;
{
	if (cvt) {
		if (_krb425_servkey.contents)
			krb5_xfree(_krb425_servkey.contents);
		mit_des_string_to_key(KEYTYPE_DES, &_krb425_servkey, 0, 0);
	} else {
		if (!_krb425_servkey.contents &&
		    !(_krb425_servkey.contents = (krb5_octet *)malloc(8))) {
			return(KFAILURE);
		}
		_krb425_servkey.length = 8;
		_krb425_servkey.keytype = KEYTYPE_DES;
		memcpy((char *)_krb425_servkey.contents, (char *)key, 8);
	}
	return(KSUCCESS);
}
