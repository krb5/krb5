/*
 * lib/krb5/keytab/file/ktf_get_en.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * This is the get_entry routine for the file based keytab implementation.
 * It opens the keytab file, and either retrieves the entry or returns
 * an error.
 */

#include "k5-int.h"
#include "ktfile.h"

krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_entry(context, id, principal, kvno, enctype, entry)
   krb5_context context;
   krb5_keytab id;
   krb5_const_principal principal;
   krb5_kvno kvno;
   krb5_enctype enctype;
   krb5_keytab_entry * entry;
{
    krb5_keytab_entry cur_entry, new_entry;
    krb5_error_code kerror = 0;
    int found_wrong_kvno = 0;
    krb5_boolean similar;

    /* Open the keyfile for reading */
    if ((kerror = krb5_ktfileint_openr(context, id)))
	return(kerror);
    
    /* 
     * For efficiency and simplicity, we'll use a while true that 
     * is exited with a break statement.
     */
    cur_entry.principal = 0;
    cur_entry.vno = 0;
    cur_entry.key.contents = 0;

    while (TRUE) {
	if ((kerror = krb5_ktfileint_read_entry(context, id, &new_entry)))
	    break;

	/* by the time this loop exits, it must either free cur_entry,
	   and copy new_entry there, or free new_entry.  Otherwise, it
	   leaks. */

	/* if the enctype is not ignored and doesn't match, free new_entry
	   and continue to the next */

	if (enctype != IGNORE_ENCTYPE) {
	    if ((kerror = krb5_c_enctype_compare(context, enctype, 
						 new_entry.key.enctype,
						 &similar))) {
		krb5_kt_free_entry(context, &new_entry);
		break;
	    }

	    if (!similar) {
		krb5_kt_free_entry(context, &new_entry);
		continue;
	    }
	}

	/* if the principal isn't the one requested, free new_entry
	   and continue to the next. */

	if (!krb5_principal_compare(context, principal, new_entry.principal)) {
	    krb5_kt_free_entry(context, &new_entry);
	    continue;
	}

	if (kvno == IGNORE_VNO) {
	    /* if this is the first match, or if the new vno is
	       bigger, free the current and keep the new.  Otherwise,
	       free the new. */
	       
	    if (! cur_entry.principal ||
		(new_entry.vno > cur_entry.vno)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
	    } else {
		krb5_kt_free_entry(context, &new_entry);
	    }
	} else {
	    /* if this kvno matches, free the current (will there ever
	       be one?), keep the new, and break out.  Otherwise, remember
	       that we were here so we can return the right error, and
	       free the new */

	    if (new_entry.vno == kvno) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
		break;
	    } else {
		found_wrong_kvno++;
		krb5_kt_free_entry(context, &new_entry);
	    }
	}
    }

    if (kerror == KRB5_KT_END) {
	 if (cur_entry.principal)
	      kerror = 0;
	 else if (found_wrong_kvno)
	      kerror = KRB5_KT_KVNONOTFOUND;
	 else
	      kerror = KRB5_KT_NOTFOUND;
    }
    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	krb5_kt_free_entry(context, &cur_entry);
	return kerror;
    }
    if ((kerror = krb5_ktfileint_close(context, id)) != 0) {
	krb5_kt_free_entry(context, &cur_entry);
	return kerror;
    }
    *entry = cur_entry;
    return 0;
}
