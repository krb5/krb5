/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kkey2enck_c[] =
"$Id$";
#endif	/* lint || saber */

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
