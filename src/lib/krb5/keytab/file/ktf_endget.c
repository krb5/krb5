/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_ktfile_end_get()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_endget_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_end_get(id, cursor)
krb5_keytab id;
krb5_kt_cursor *cursor;
{
    xfree(*cursor);
    return krb5_ktfileint_close(id);
}
