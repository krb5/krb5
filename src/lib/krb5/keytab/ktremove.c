/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_kt_remove_entry()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktremove_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

krb5_error_code
krb5_kt_remove_entry (id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    if (id->ops->remove)
	return (*id->ops->remove)(id, entry);
    else
	return KRB5_KT_NOWRITE;
}
