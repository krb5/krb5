/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_prin2kprin_c[] =
"$Id$";
#endif	/* lint || saber */

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
#if 0
    /* this code is for -h2 style ISODE structures.  However, pepsy
       generates horribly broken when given -h2. */

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
#endif

    register krb5_principal retval;
    register int i;
    register const struct type_KRB5_PrincipalName *rv;

    for (i = 1, rv = val; rv->next; i++, rv = rv->next)
	;

    /* plus one for the realm, plus one for null term */
    retval = (krb5_principal) xcalloc(i + 2, sizeof(krb5_data *));
					     
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }

    retval[0] = qbuf2krb5_data(realm, error);
    if (!retval[0]) {
	xfree(retval);
	return(0);
    }
    for (i = 1, rv = val; rv; rv = rv->next, i++) {
	retval[i] = qbuf2krb5_data(rv->GeneralString, error);
	if (!retval[i]) {
	    krb5_free_principal(retval);
	    return(0);
	}
    }
    retval[i] = 0;
    return(retval);
}
