/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * krb5_copy_cred()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_creds_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>


/*
 * Copy credentials, allocating fresh storage where needed.
 */

krb5_error_code
krb5_copy_creds(incred, outcred)
const krb5_creds *incred;
krb5_creds **outcred;
{
    krb5_creds *tempcred;
    krb5_error_code retval;
    krb5_data *scratch;

    if (!(tempcred = (krb5_creds *)malloc(sizeof(*tempcred))))
	return ENOMEM;

    *tempcred = *incred;		/* copy everything quickly */
    retval = krb5_copy_principal(incred->client, &tempcred->client);
    if (retval)
	goto cleanlast;
    retval = krb5_copy_principal(incred->server, &tempcred->server);
    if (retval)
	goto cleanclient;
    retval = krb5_copy_keyblock_contents(&incred->keyblock,
					 &tempcred->keyblock);
    if (retval)
	goto cleanserver;
    retval = krb5_copy_addresses(incred->addresses, &tempcred->addresses);
    if (retval)
	goto cleanblock;
    retval = krb5_copy_data(&incred->ticket, &scratch);
    if (retval)
	goto cleanaddrs;
    tempcred->ticket = *scratch;
    xfree(scratch);
    retval = krb5_copy_data(&incred->second_ticket, &scratch);
    if (retval)
	goto cleanticket;

    tempcred->second_ticket = *scratch;
    xfree(scratch);

    *outcred = tempcred;
    return 0;

 cleanticket:
    free(tempcred->ticket.data);
 cleanaddrs:
    krb5_free_addresses(tempcred->addresses);
 cleanblock:
    xfree(tempcred->keyblock.contents);
 cleanserver:
    krb5_free_principal(tempcred->server);
 cleanclient:
    krb5_free_principal(tempcred->client);
 cleanlast:
    xfree(tempcred);
    return retval;
}
