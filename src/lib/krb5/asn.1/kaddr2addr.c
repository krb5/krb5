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
static char rcsid_kaddr2addr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_HostAddresses *
krb5_address2KRB5_HostAddresses(val, error)
register krb5_address * const *val;
register int *error;
{
    register struct type_KRB5_HostAddresses *retval;
    register krb5_address * const *temp;
    register int i;

    /* count elements */
    for (i = 0, temp = val; *temp; temp++,i++);

    retval = (struct type_KRB5_HostAddresses *)
	xmalloc(sizeof(*retval) + max(0,i-1)*sizeof(retval->element_KRB5_0[0]));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));
    retval->nelem = i;
    for (i = 0; i < retval->nelem; i++) {
	retval->element_KRB5_0[i] = (struct element_KRB5_1 *)
	    xmalloc(sizeof(*(retval->element_KRB5_0[i])));
	if (!retval->element_KRB5_0[i]) {
	errout:
	    retval->nelem = i;
	    free_KRB5_HostAddresses(retval);
	    *error = ENOMEM;
	    return(0);
	}	    
	retval->element_KRB5_0[i]->addr__type = (val[i])->addrtype;
	retval->element_KRB5_0[i]->address = str2qb((char *)(val[i])->contents,
						    (val[i])->length, 1);
	if (!retval->element_KRB5_0[i]->address) {
	    /* clean up */
	    xfree(retval->element_KRB5_0[i]);
	    goto errout;
	}
    }
    return(retval);
}
