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
 * krb5_free_ap_rep_enc_part()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_arep_enc_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_ap_rep_enc_part(val)
krb5_ap_rep_enc_part *val;
{
    if (val->subkey)
	krb5_free_keyblock(val->subkey);
    xfree(val);
    return;
}
