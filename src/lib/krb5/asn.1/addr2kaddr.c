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
static char rcsid_addr2kaddr_c[] =
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



krb5_address **
KRB5_HostAddresses2krb5_address(val, error)
const struct type_KRB5_HostAddresses *val;
register int *error;
{
    register krb5_address **retval;
    register int i;

    /* plus one for null terminator */
    retval = (krb5_address **) xcalloc(val->nelem + 1, sizeof(krb5_address *));
    if (!retval) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    for (i = 0; i < val->nelem; i++) {
	if (qb_pullup(val->element_KRB5_0[i]->address) != OK) {
	    xfree(retval);
	    goto nomem;
	}
	retval[i] = (krb5_address *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_address(retval);
	    goto nomem;
	}
	retval[i]->contents = (unsigned char *)xmalloc(val->element_KRB5_0[i]->address->qb_forw->qb_len);
	if (!retval[i]->contents) {
	    xfree(retval[i]);
	    krb5_free_address(retval);
	    goto nomem;
	}
	retval[i]->addrtype = val->element_KRB5_0[i]->addr__type;
	retval[i]->length = val->element_KRB5_0[i]->address->qb_forw->qb_len;
	xbcopy(val->element_KRB5_0[i]->address->qb_forw->qb_data,
	      retval[i]->contents, retval[i]->length);
    }
    retval[i] = 0;
    return(retval);
}

