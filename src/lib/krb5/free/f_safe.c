/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_safe()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_safe_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_safe(val)
register krb5_safe *val;
{
    if (val->user_data.data)
	xfree(val->user_data.data);
    if (val->r_address)
	krb5_free_address(val->r_address);
    if (val->s_address)
	krb5_free_address(val->s_address);
    if (val->checksum)
	krb5_free_checksum(val->checksum);
    xfree(val);
    return;
}
