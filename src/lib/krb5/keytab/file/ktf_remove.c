/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_ktfile_add()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_add_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_remove(id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    return EOPNOTSUPP;
}
