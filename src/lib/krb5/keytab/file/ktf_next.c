/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_ktfile_get_next()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_next_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_get_next(id, entry, cursor)
krb5_keytab id;
krb5_keytab_entry *entry;
krb5_kt_cursor *cursor;
{
    long *fileoff = (long *)cursor;
    krb5_keytab_entry *cur_entry;
    krb5_error_code kerror;

    if (fseek(KTFILEP(id), *fileoff, 0) == -1)
	return KRB5_KT_END;
    if (kerror = krb5_ktfileint_read_entry(id, &cur_entry))
	return kerror;
    *fileoff = ftell(KTFILEP(id));
    *entry = *cur_entry;
    xfree(cur_entry);
    return 0;
}
