/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_creds()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_creds_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_creds(val)
krb5_creds *val;
{
    krb5_free_cred_contents(val);
    xfree(val);
    return;
}
