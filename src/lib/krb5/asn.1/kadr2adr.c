/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
