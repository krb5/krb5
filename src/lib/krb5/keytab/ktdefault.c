/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Get a default keytab.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktdefault_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <errno.h>

krb5_error_code krb5_kt_default(id)
krb5_keytab *id;
{
    return EOPNOTSUPP;
}



