/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_tickets()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_tickets_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_tickets(val)
krb5_ticket **val;
{
    register krb5_ticket **temp;

    for (temp = val; *temp; temp++)
        krb5_free_ticket(*temp);
    xfree(val);
    return;
}
