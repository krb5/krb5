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
static char rcsid_ck2kck_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_checksum *
KRB5_Checksum2krb5_checksum(val, error)
const register struct type_KRB5_Checksum *val;
register int *error;
{
    krb5_checksum *retval;

    if (!val->checksum) {
	*error = EINVAL;
	return(0);
    } else
	*error = 0;
    /* pull up, then play with the single string */
    if (qb_pullup(val->checksum) != OK) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    retval = (krb5_checksum *)xmalloc(sizeof(*retval));
    if (!retval) {
	goto nomem;
    }
    retval->contents = (unsigned char *)xmalloc(val->checksum->qb_forw->qb_len);
    if (!retval->contents) {
	xfree(retval);
	goto nomem;
    }
    retval->checksum_type = val->cksumtype;
    retval->length = val->checksum->qb_forw->qb_len;
    xbcopy(val->checksum->qb_forw->qb_data, retval->contents,
	  val->checksum->qb_forw->qb_len);
    return(retval);
}
