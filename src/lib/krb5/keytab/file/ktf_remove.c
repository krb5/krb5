/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
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
krb5_ktfile_remove(id, entry)
krb5_keytab id;
krb5_keytab_entry *entry;
{
    krb5_keytab_entry   *cur_entry;
    krb5_error_code     kerror;
    krb5_int32          delete_point;
    krb5_boolean        found = FALSE;

    if (kerror = krb5_ktfileint_openw(id)) {
	return kerror;
    }

    /* 
     * For efficiency and simplicity, we'll use a while true that 
     * is exited with a break statement.
     */
    while (TRUE) {
	cur_entry = 0;
	if (kerror = krb5_ktfileint_internal_read_entry(id, &cur_entry,
                                                            &delete_point))
  	    break;

	if ((entry->vno == cur_entry->vno) &&
            (entry->key.keytype == cur_entry->key.keytype) &&
	    krb5_principal_compare(entry->principal, cur_entry->principal)) {
	    /* found a match */
            found = TRUE;
            krb5_kt_free_entry(cur_entry);
	    break;
	}
	krb5_kt_free_entry(cur_entry);
    }

    if (kerror && kerror != KRB5_KT_END) {
	(void) krb5_ktfileint_close(id);
	return kerror;
    }

    if (found) {
        kerror = krb5_ktfileint_delete_entry(id, delete_point);
    } else {
        kerror = KRB5_KT_NOTFOUND;
    }

    if (kerror) {
	(void) krb5_ktfileint_close(id);
    } else {
        kerror = krb5_ktfileint_close(id);
    }

    return kerror;
}
