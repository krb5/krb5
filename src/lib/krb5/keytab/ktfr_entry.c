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
 * krb5_kt_free_entry()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktfr_entry_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

krb5_error_code
krb5_kt_free_entry (entry)
krb5_keytab_entry *entry;
{
    krb5_free_principal(entry->principal);
    memset((char *)entry->key.contents, 0, entry->key.length);
    xfree(entry->key.contents);
    return 0;
}
