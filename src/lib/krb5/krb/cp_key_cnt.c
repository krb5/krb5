/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_copy_keyblock()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_key_cnt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * Copy a keyblock, including alloc'ed storage.
 */
krb5_error_code
krb5_copy_keyblock_contents(from, to)
const krb5_keyblock *from;
krb5_keyblock *to;
{
    *to = *from;
    to->contents = (krb5_octet *)malloc(to->length);
    if (!to->contents)
	return ENOMEM;
    memcpy((char *)to->contents, (char *)from->contents, to->length);
    return 0;
}
