/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_priv_enc_part()
 */

#if !defined(lint) && !defined(SABER)
static char f_priv_enc_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

void
krb5_free_priv_enc_part(val)
register krb5_priv_enc_part *val;
{
    if (val->user_data.data)
	xfree(val->user_data.data);
    if (val->addresses)
	krb5_free_address(val->addresses);
    xfree(val);
    return;
}
