/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_principal()
 */

#if !defined(lint) && !defined(SABER)
static char f_princ_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

void
krb5_free_principal(val)
krb5_principal val;
{
    register krb5_data **temp;

    for (temp = val; *temp; temp++)
	krb5_free_data(*temp);
    xfree(val);
    return;
}
