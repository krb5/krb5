/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_safe()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_safe_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_safe(val)
register krb5_safe *val;
{
    if (val->user_data.data)
	xfree(val->user_data.data);
    if (val->addresses)
	krb5_free_address(val->addresses);
    if (val->checksum)
	krb5_free_checksum(val->checksum);
    xfree(val);
    return;
}
