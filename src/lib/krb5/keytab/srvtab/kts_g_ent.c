/*
 * lib/krb5/keytab/file/kts_g_ent.c
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
#include "ktsrvtab.h"

krb5_error_code
krb5_ktsrvtab_get_entry(context, id, principal, kvno, enctype, entry)
    krb5_context context;
    krb5_keytab id;
    krb5_principal principal;
    krb5_kvno kvno;
    krb5_enctype enctype;
    krb5_keytab_entry * entry;
{
    krb5_keytab_entry best_entry, ent;
    krb5_error_code kerror = 0;
    int found_wrong_kvno = 0;

    /* Open the srvtab. */
    if ((kerror = krb5_ktsrvint_open(context, id)))
	return(kerror);

    /* srvtab files only have DES_CBC_CRC keys. */
    switch (enctype) {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_RAW:
    case IGNORE_ENCTYPE:
	break;
    default:
	return KRB5_KT_NOTFOUND;
    }

    best_entry.principal = 0;
    best_entry.vno = 0;
    best_entry.key.contents = 0;
    while ((kerror = krb5_ktsrvint_read_entry(context, id, &ent)) == 0) {
	if (krb5_principal_compare(context, principal, ent.principal)) {
	    if (kvno == IGNORE_VNO) {
		if (!best_entry.principal || (best_entry.vno < ent.vno)) {
		    krb5_kt_free_entry(context, &best_entry);
		    best_entry = ent;
		}
	    } else {
		if (ent.vno == kvno) {
		    best_entry = ent;
		    break;
		} else {
		    found_wrong_kvno = 1;
		}
	    }
	} else {
	    krb5_kt_free_entry(context, &ent);
	}
    }
    if (kerror == KRB5_KT_END) {
	 if (best_entry.principal)
	      kerror = 0;
	 else if (found_wrong_kvno)
	      kerror = KRB5_KT_KVNONOTFOUND;
	 else
	      kerror = KRB5_KT_NOTFOUND;
    }
    if (kerror) {
	(void) krb5_ktsrvint_close(context, id);
	krb5_kt_free_entry(context, &best_entry);
	return kerror;
    }
    if ((kerror = krb5_ktsrvint_close(context, id)) != 0) {
	krb5_kt_free_entry(context, &best_entry);
	return kerror;
    }
    *entry = best_entry;
    return 0;
}
