/*
 * lib/krb5/asn.1/kkey2enck.c
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */


#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_EncryptionKey *
krb5_keyblock2KRB5_EncryptionKey(val, error)
const krb5_keyblock *val;
register int *error;
{
    PE pe;
    register struct type_KRB5_EncryptionKey *retval;
    struct qbuf *temp;

    pe = gens2prim(val->contents, val->length);
    if (!pe) {
    nomem:
	*error = ENOMEM;
	return(0);
    } else
	*error = 0;

    temp = prim2qb(pe);
    if (!temp)
	*error = pe->pe_errno + ISODE_50_PE_ERR_NONE;
    (void) pe_free(pe);

    if (!temp)
	return(0);

    retval = (struct type_KRB5_EncryptionKey *) xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }

    retval->keytype = val->keytype;
    retval->keyvalue = temp;
    
    return(retval);
}
