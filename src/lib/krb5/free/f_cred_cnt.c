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
 * krb5_free_cred_contents()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_cred_cnt_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * krb5_free_cred_contents zeros out the session key, and then frees
 * the credentials structures 
 */

void
krb5_free_cred_contents(val)
krb5_creds *val;
{
    if (val->client)
	krb5_free_principal(val->client);
    if (val->server)
	krb5_free_principal(val->server);
    if (val->keyblock.contents) {
	memset((char *)val->keyblock.contents, 0, val->keyblock.length);
	xfree(val->keyblock.contents);
    }
    if (val->ticket.data)
	xfree(val->ticket.data);
    if (val->second_ticket.data)
	xfree(val->second_ticket.data);
    if (val->addresses)
	krb5_free_address(val->addresses);
    if (val->authdata)
	krb5_free_authdata(val->authdata);
    return;
}
