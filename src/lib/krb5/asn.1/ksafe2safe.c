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
static char rcsid_ksafe2safe_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_KRB__SAFE *
krb5_safe2KRB5_KRB__SAFE(val, error)
const register krb5_safe *val;
register int *error;
{
    register struct type_KRB5_KRB__SAFE *retval;
    register struct type_KRB5_KRB__SAFE__BODY *rv2;

    retval = (struct type_KRB5_KRB__SAFE *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    rv2 = (struct type_KRB5_KRB__SAFE__BODY *)xmalloc(sizeof(*rv2));
    if (!rv2) {
	krb5_xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    xbzero(rv2, sizeof(*rv2));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_SAFE;
    retval->safe__body = rv2;

    rv2->user__data = krb5_data2qbuf(&(val->user_data));
    if (!rv2->user__data) {
	krb5_xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    if (val->timestamp) {
	rv2->timestamp = unix2gentime(val->timestamp, error);
	if (!rv2->timestamp) {
	errout:
	    free_KRB5_KRB__SAFE(retval);
	    return(0);
	}
	rv2->usec = val->usec;
	rv2->optionals |= opt_KRB5_KRB__SAFE__BODY_usec;
    }
    rv2->s__address = krb5_addr2KRB5_HostAddress(val->s_address, error);
    if (!rv2->s__address) {
	goto errout;
    }
    if (val->r_address) {
	rv2->r__address = krb5_addr2KRB5_HostAddress(val->r_address, error);
	if (!rv2->r__address) {
	    goto errout;
	}
    }
    retval->cksum = krb5_checksum2KRB5_Checksum(val->checksum, error);
    if (!retval->cksum) {
	goto errout;
    }
    if (val->seq_number) {
	rv2->seq__number = val->seq_number;
	rv2->optionals |= opt_KRB5_KRB__SAFE__BODY_seq__number;
    }
    return(retval);
}
