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
 * krb5_kt_add_entry()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktadd_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

krb5_error_code
krb5_kt_add_entry (id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    if (id->ops->add)
	return (*id->ops->add)(id, entry);
    else
	return KRB5_KT_NOWRITE;
}
