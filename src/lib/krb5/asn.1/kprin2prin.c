/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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

#if !defined(lint) && !defined(SABER)
static char rcsid_kprin2prin_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_PrincipalName *
krb5_principal2KRB5_PrincipalName(val, error)
krb5_const_principal val;
register int *error;
{
    register struct type_KRB5_PrincipalName *retval = 0;
    register struct element_KRB5_6 *namestring = 0, *rv1 = 0, *rv2;
    register int i;
    int nelem = krb5_princ_size(val);

    retval = (struct type_KRB5_PrincipalName *) xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    
    retval->name__type = krb5_princ_type(val);

    /* still skipping realm */
    for (i = 0; i < nelem; i++, rv1 = rv2) { 
	rv2 = (struct element_KRB5_6 *) xmalloc(sizeof(*rv2));
	if (!rv2) {
	    if (retval)
		free_KRB5_PrincipalName(retval);
	    *error = ENOMEM;
	    return(0);
	}
	if (rv1)
	    rv1->next = rv2;
	xbzero((char *)rv2, sizeof (*rv2));
	if (!namestring)
	    namestring = rv2;

	rv2->GeneralString = krb5_data2qbuf(krb5_princ_component(val, i));
	if (!rv2->GeneralString) {
	    /* clean up */
	    if (retval)
		free_KRB5_PrincipalName(retval);
	    *error = ENOMEM;
	    return(0);
	}
    }

    retval->name__string = namestring;

    return(retval);
}
