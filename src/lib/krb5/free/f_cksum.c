/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_checksum()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_cksum_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_checksum(val)
register krb5_checksum *val;
{
    if (val->contents)
	xfree(val->contents);
    xfree(val);
    return;
}
