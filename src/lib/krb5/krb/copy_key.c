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
 * krb5_copy_keyblock()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_key_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * Copy a keyblock, including alloc'ed storage.
 */
krb5_error_code
krb5_copy_keyblock(from, to)
const krb5_keyblock *from;
krb5_keyblock **to;
{
	krb5_keyblock	*new_key;

	if (!(new_key = (krb5_keyblock *) malloc(sizeof(krb5_keyblock))))
		return ENOMEM;
	*new_key = *from;
	if (!(new_key->contents = (krb5_octet *)malloc(new_key->length))) {
		xfree(new_key);
		return(ENOMEM);
	}
	memcpy((char *)new_key->contents, (char *)from->contents,
	       new_key->length);
	*to = new_key;
	return 0;
}
