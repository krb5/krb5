/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_copy_cred()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_cred_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

#include <errno.h>


/*
 * Copy credentials, allocating fresh storage where needed.
 */

krb5_error_code
krb5_copy_cred(incred, outcred)
krb5_creds *incred, **outcred;
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
    if (retval = krb5_copy_keyblock(&incred->keyblock, &tempcred->keyblock))
	goto cleanserver;
    if (retval = krb5_copy_data(&incred->ticket, &scratch))
	goto cleanblock;
    tempcred->ticket = *scratch;
    free((char *)scratch);
    if (retval = krb5_copy_data(&incred->second_ticket,
				&scratch))
	goto cleanticket;

    tempcred->second_ticket = *scratch;
    free((char *)scratch);

    *outcred = tempcred;
    return 0;

 cleanticket:
    free(tempcred->ticket.data);
 cleanblock:
    free((char *)tempcred->keyblock.contents);
 cleanserver:
    krb5_free_principal(tempcred->server);
 cleanclient:
    krb5_free_principal(tempcred->client);
 cleanlast:
    free((char *)tempcred);
    return retval;
}
