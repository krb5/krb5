/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_authenticator()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_authent_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_authenticator(val)
krb5_authenticator *val;
{
    if (val->checksum)
	xfree(val->checksum);
    if (val->client)
	krb5_free_principal(val->client);
    if (val->subkey)
	krb5_free_keyblock(val->subkey);
    xfree(val);
    return;
}
