/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_kdc_req()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_kdc_req_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_kdc_req(val)
krb5_kdc_req *val;
{
    if (val->padata.data)
	xfree(val->padata.data);
    if (val->client)
	krb5_free_principal(val->client);
    if (val->server)
	krb5_free_principal(val->server);
    if (val->addresses)
	krb5_free_address(val->addresses);
    if (val->authorization_data)
	krb5_free_authdata(val->authorization_data);
    if (val->second_ticket)
	krb5_free_tickets(val->second_ticket);
    xfree(val);
    return;
}
