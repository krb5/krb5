/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_ktfile_start_seq_get()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_ssget_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_start_seq_get(id, cursorp)
krb5_keytab id;
krb5_kt_cursor *cursorp;
{
    krb5_error_code retval;
    long *fileoff;

    if (retval = krb5_ktfileint_openr(id))
	return retval;

    if (!(fileoff = (long *)malloc(sizeof(*fileoff)))) {
	krb5_ktfileint_close(id);
	return ENOMEM;
    }
    *fileoff = ftell(KTFILEP(id));
    cursorp = (krb5_kt_cursor *)fileoff;

    return 0;
}
