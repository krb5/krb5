/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_enc_tkt_part()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_enc_tkt_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_enc_tkt_part(val)
krb5_enc_tkt_part *val;
{
    if (val->session)
	krb5_free_keyblock(val->session);
    if (val->client)
	krb5_free_principal(val->client);
    if (val->transited.tr_contents.data)
	xfree(val->transited.tr_contents.data);
    if (val->caddrs)
	krb5_free_addresses(val->caddrs);
    if (val->authorization_data)
	krb5_free_authdata(val->authorization_data);
    xfree(val);
    return;
}
