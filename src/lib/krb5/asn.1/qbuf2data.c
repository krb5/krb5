/*
 * lib/krb5/asn.1/qbuf2data.c
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

krb5_data *
qbuf2krb5_data(val, error)
const struct qbuf *val;
register int *error;
{
    krb5_data *retval;
    if (qb_pullup(val) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_data *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    /* If there is no data, don't call malloc.  This saves space on systems
       which allocate data in response to malloc(0), and saves error checking
       on systems which return NULL.  */
    if ((retval->length = val->qb_forw->qb_len) == 0) {
	retval->data = 0;
	return retval;
    }
    retval->magic = 0;
    retval->data = (char *)xmalloc(val->qb_forw->qb_len);
    if (!retval->data) {
	krb5_xfree(retval);
	goto nomem;
    }
    memcpy(retval->data, val->qb_forw->qb_data,
	   val->qb_forw->qb_len);
    return(retval);
}

