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
    if (retval = krb5_copy_principal(incred->client, &tempcred->client))
	goto cleanlast;
    if (retval = krb5_copy_principal(incred->server, &tempcred->server))
	goto cleanclient;
    if (retval = krb5_copy_keyblock_contents(&incred->keyblock,
					     &tempcred->keyblock))
	goto cleanserver;
    if (retval = krb5_copy_addresses(incred->addresses, &tempcred->addresses))
	goto cleanblock;
    if (retval = krb5_copy_data(&incred->ticket, &scratch))
	goto cleanaddrs;
    tempcred->ticket = *scratch;
    xfree(scratch);
    if (retval = krb5_copy_data(&incred->second_ticket,
				&scratch))
	goto cleanticket;

    tempcred->second_ticket = *scratch;
    xfree(scratch);

    *outcred = tempcred;
    return 0;

 cleanticket:
    free(tempcred->ticket.data);
 cleanaddrs:
    krb5_free_address(tempcred->addresses);
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
