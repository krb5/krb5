/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
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
	krb5_xfree(val->keyblock.contents);
    }
    if (val->ticket.data)
	krb5_xfree(val->ticket.data);
    if (val->second_ticket.data)
	krb5_xfree(val->second_ticket.data);
    if (val->addresses)
	krb5_free_addresses(val->addresses);
    if (val->authdata)
	krb5_free_authdata(val->authdata);
    return;
}
