/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_last_req()
 */

#if !defined(lint) && !defined(SABER)
static char f_last_req_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

void
krb5_free_last_req(val)
krb5_last_req_entry **val;
{
    register krb5_last_req_entry **temp;

    for (temp = val; *temp; temp++)
	xfree(*temp);
    xfree(val);
    return;
}
