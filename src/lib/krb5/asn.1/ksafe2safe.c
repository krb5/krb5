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
static char rcsid_ksafe2safe_c[] =
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

struct type_KRB5_KRB__SAFE *
krb5_safe2KRB5_KRB__SAFE(val, error)
const register krb5_safe *val;
register int *error;
{
    register struct type_KRB5_KRB__SAFE *retval;
 
    retval = (struct type_KRB5_KRB__SAFE *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_SAFE;

    retval->user__data = krb5_data2qbuf(&(val->user_data));
    if (!retval->user__data) {
	xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    retval->timestamp = unix2gentime(val->timestamp, error);
    if (!retval->timestamp) {
    errout:
	free_KRB5_KRB__SAFE(retval);
	return(0);
    }
    retval->msec = val->msec;
    retval->addresses = krb5_address2KRB5_HostAddresses(val->addresses, error);
    if (!retval->addresses) {
	goto errout;
    }
    retval->checksum = krb5_checksum2KRB5_Checksum(val->checksum, error);
    if (!retval->checksum) {
	goto errout;
    }
    return(retval);
}
