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
 * krb5_ktfile_add()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_add_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_add(id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    krb5_error_code retval;

    if (retval = krb5_ktfileint_openw(id))
	return retval;
    if (fseek(KTFILEP(id), 0, 2) == -1)
	return KRB5_KT_END;
    retval = krb5_ktfileint_write_entry(id, entry);
    krb5_ktfileint_close(id);
    return retval;
}
