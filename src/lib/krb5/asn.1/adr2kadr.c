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
static char rcsid_adr2kadr_c[] =
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



krb5_address *
KRB5_HostAddress2krb5_addr(val, error)
const struct type_KRB5_HostAddress *val;
register int *error;
{
    register krb5_address *retval;

    retval = (krb5_address *) xmalloc(sizeof(*retval));
    if (!retval) {
    nomem:
	*error = ENOMEM;
	return 0;
    }
    xbzero(retval, sizeof(*retval));

    if (qb_pullup(val->address) != OK) {
	xfree(retval);
	goto nomem;
    }
    retval->contents = (unsigned char *)xmalloc(val->address->qb_forw->qb_len);
    if (!retval->contents) {
	xfree(retval);
	goto nomem;
    }
    retval->addrtype = val->addr__type;
    retval->length = val->address->qb_forw->qb_len;
    xbcopy(val->address->qb_forw->qb_data,
	   retval->contents, retval->length);
    return(retval);
}

