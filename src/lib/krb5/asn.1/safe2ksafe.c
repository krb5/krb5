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
static char rcsid_safe2ksafe_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_safe *
KRB5_KRB__SAFE2krb5_safe(val, error)
const register struct type_KRB5_KRB__SAFE *val;
register int *error;
{
    register krb5_safe *retval;
    krb5_data *temp;

    retval = (krb5_safe *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    temp = qbuf2krb5_data(val->safe__body->user__data, error);
    if (temp) {
	retval->user_data = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    if (val->safe__body->timestamp) {
	if (!(val->safe__body->optionals & opt_KRB5_KRB__SAFE__BODY_usec)) {
	    /* must have usec if we have timestamp */
	    *error = ISODE_50_LOCAL_ERR_BADCOMBO;
	    goto errout;
	}
	retval->timestamp = gentime2unix(val->safe__body->timestamp, error);
	if (*error) {
	errout:
	    krb5_free_safe(retval);
	    return(0);
	}
	retval->usec = val->safe__body->usec;
    }
    retval->s_address = KRB5_HostAddress2krb5_addr(val->safe__body->s__address,
						   error);
    if (!retval->s_address) {
	goto errout;
    }
    if (val->safe__body->r__address) {
	retval->r_address =
	    KRB5_HostAddress2krb5_addr(val->safe__body->r__address, error);
	if (!retval->r_address) {
	    goto errout;
	}
    }
    retval->checksum = KRB5_Checksum2krb5_checksum(val->cksum,
						   error);
    if (!retval->checksum) {
	goto errout;
    }
    if (val->safe__body->optionals & opt_KRB5_KRB__SAFE__BODY_seq__number) {
	retval->seq_number = val->safe__body->seq__number;
    }
    return(retval);
}
