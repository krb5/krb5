/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_ap_req()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_ap_req_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_ap_req(val)
register krb5_ap_req *val;
{
    if (val->ticket)
	krb5_free_ticket(val->ticket);
    if (val->authenticator.data)
	xfree(val->authenticator.data);
    xfree(val);
    return;
}
