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
static char rcsid_kprin2prin_c[] =
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

struct type_KRB5_PrincipalName *
krb5_principal2KRB5_PrincipalName(val, error)
krb5_const_principal val;
register int *error;
{
#if 0
    /* this code is for -h2 style ISODE structures.  However, pepsy
       generates horribly broken when given -h2. */

    register int i;
    register struct type_KRB5_PrincipalName *retval;

    /* count elements */
    for (i = 0; val[i]; i++);

    i--;				/* skip the realm */

    retval = (struct type_KRB5_PrincipalName *)
	xmalloc(sizeof(*retval)+max(0,i-1)*sizeof(retval->GeneralString[0]));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    retval->nelem = i;
    for (i = 1; i <= retval->nelem; i++) { /* still skipping realm */
	retval->GeneralString[i-1] = krb5_data2qbuf(val[i]);
	if (!retval->GeneralString[i-1]) {
	    /* clean up */
	    retval->nelem = i-1;
	    free_KRB5_PrincipalName(retval);
	    *error = ENOMEM;
	    return(0);
	}
    }
    return(retval);

#endif
    register struct type_KRB5_PrincipalName *retval = 0, *rv1 = 0, *rv2;
    register int i;

    /* still skipping realm */
    for (i = 1; val[i]; i++, rv1 = rv2) { 
	rv2 = (struct type_KRB5_PrincipalName *) xmalloc(sizeof(*rv2));
	if (!rv2) {
	    if (retval)
		free_KRB5_PrincipalName(retval);
	    *error = ENOMEM;
	    return(0);
	}
	if (rv1)
	    rv1->next = rv2;
	xbzero((char *)rv2, sizeof (*rv2));
	if (!retval)
	    retval = rv2;

	rv2->GeneralString = krb5_data2qbuf(val[i]);
	if (!rv2->GeneralString) {
	    /* clean up */
	    if (retval)
		free_KRB5_PrincipalName(retval);
	    *error = ENOMEM;
	    return(0);
	}
    }
    return(retval);
}
