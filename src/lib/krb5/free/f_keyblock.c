/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_keyblock()
 */

#if !defined(lint) && !defined(SABER)
static char f_keyblock_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

void
krb5_free_keyblock(val)
register krb5_keyblock *val;
{
    if (val->contents)
	xfree(val->contents);
    xfree(val);
    return;
}
