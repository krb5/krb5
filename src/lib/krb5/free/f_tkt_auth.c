/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_tkt_authent()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_tkt_authent_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_tkt_authent(val)
krb5_tkt_authent *val;
{
    if (val->ticket)
	    krb5_free_ticket(val->ticket);
    if (val->authenticator)
	    krb5_free_authenticator(val->authenticator);
    xfree(val);
    return;
}
