/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_prin2kprin_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_principal
KRB5_PrincipalName2krb5_principal(val, realm, error)
const struct type_KRB5_PrincipalName *val;
const struct type_KRB5_Realm *realm;
register int *error;
{
    register krb5_principal retval;
    register int i;

    /* plus one for the realm, plus one for null term */
    retval = (krb5_principal) xcalloc(val->nelem + 2, sizeof(krb5_data *));
					     
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }

    retval[0] = qbuf2krb5_data(realm, error);
    if (!retval[0]) {
	xfree(retval);
	return(0);
    }
    for (i = 0; i < val->nelem; i++) {
	retval[i+1] = qbuf2krb5_data(val->GeneralString[i], error);
	if (!retval[i+1]) {
	    krb5_free_principal(retval);
	    return(0);
	}
    }
    retval[i+1] = 0;
    return(retval);
}
