/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_set_key for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_set_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

int
krb_set_key(key, cvt)
char *key;
int cvt;
{
	if (cvt) {
		if (_krb425_servkey.contents)
			xfree(_krb425_servkey.contents);
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
