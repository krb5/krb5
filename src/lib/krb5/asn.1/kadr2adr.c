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
static char rcsid_kadr2adr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_HostAddress *
krb5_addr2KRB5_HostAddress(val, error)
register krb5_address const *val;
register int *error;
{
    register struct type_KRB5_HostAddress *retval;

    retval = (struct type_KRB5_HostAddress *) xmalloc(sizeof(*retval));
    if (!retval) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));
    retval->addr__type = val->addrtype;
    retval->address = str2qb((char *)val->contents, val->length, 1);
    if (!retval->address) {
	xfree(retval);
	goto nomem;
    }
    return(retval);
}
