/*
 * lib/krb5/asn.1/adr2kadr.c
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
    memset(retval, 0, sizeof(*retval));

    if (qb_pullup(val->address) != OK) {
	krb5_xfree(retval);
	goto nomem;
    }
    retval->contents = (unsigned char *)xmalloc(val->address->qb_forw->qb_len);
    if (!retval->contents) {
	krb5_xfree(retval);
	goto nomem;
    }
    retval->addrtype = val->addr__type;
    retval->length = val->address->qb_forw->qb_len;
    memcpy(retval->contents, val->address->qb_forw->qb_data, retval->length);
    return(retval);
}

