/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

#include <krb5/copyright.h>
#include "krb425.h"

int
krb_set_key(key, cvt)
char *key;
int cvt;
{
	static krb5_keyblock keyblock;

	if (cvt) {
		if (keyblock.contents)
			free((char *)keyblock.contents);
		mit_des_string_to_key(KEYTYPE_DES, &keyblock, 0, 0);
	} else {
		if (!keyblock.contents &&
		    !(keyblock.contents = (krb5_octet *)malloc(8))) {
			return(KFAILURE);
		}
		keyblock.length = 8;
		keyblock.keytype = KEYTYPE_DES;
		bcopy(key, keyblock.contents,8);
	}
	return(KSUCCESS);
}
