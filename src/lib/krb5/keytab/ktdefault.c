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
 * Get a default keytab.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktdefault_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <stdio.h>

krb5_error_code krb5_kt_default(id)
krb5_keytab *id;
{
    char defname[BUFSIZ];
    krb5_error_code retval;

    if (retval = krb5_kt_default_name(defname, sizeof(defname)))
	return retval;
    return krb5_kt_resolve(defname, id);
}



