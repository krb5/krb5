/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_creds()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_creds_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_creds(val)
krb5_creds *val;
{
    if (val->client)
	krb5_free_principal(val->client);
    if (val->server)
	krb5_free_principal(val->server);
    if (val->keyblock.contents)
	xfree(val->keyblock.contents);
    if (val->ticket.data)
	xfree(val->ticket.data);
    if (val->second_ticket.data)
	xfree(val->second_ticket.data);
    if (val->addresses)
	krb5_free_address(val->addresses);
    xfree(val);
    return;
}
