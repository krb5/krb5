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
 * krb5_free_priv()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_priv_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_priv(val)
register krb5_priv *val;
{
    if (val->enc_part.ciphertext.data)
	xfree(val->enc_part.ciphertext.data);
    xfree(val);
    return;
}
