/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_address()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_addr_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_address(val)
krb5_address *val;
{
    if (val->contents)
	xfree(val->contents);
    xfree(val);
    return;
}
