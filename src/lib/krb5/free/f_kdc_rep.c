/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_kdc_rep()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_kdc_rep_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_kdc_rep(val)
krb5_kdc_rep *val;
{
    if (val->padata)
	krb5_free_pa_data(val->padata);
    if (val->client)
	krb5_free_principal(val->client);
    if (val->ticket)
	krb5_free_ticket(val->ticket);
    if (val->enc_part.ciphertext.data)
	xfree(val->enc_part.ciphertext.data);
    if (val->enc_part2)
	krb5_free_enc_kdc_rep_part(val->enc_part2);
    xfree(val);
    return;
}
