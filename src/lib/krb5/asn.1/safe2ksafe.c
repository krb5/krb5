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
static char rcsid_safe2ksafe_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

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

    temp = qbuf2krb5_data(val->user__data, error);
    if (temp) {
	retval->user_data = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    retval->timestamp = gentime2unix(val->timestamp, error);
    if (*error) {
    errout:
	krb5_free_safe(retval);
	return(0);
    }
    retval->msec = val->msec;
    retval->s_address = KRB5_HostAddress2krb5_addr(val->s__address, error);
    if (!retval->s_address) {
	goto errout;
    }
    retval->r_address = KRB5_HostAddress2krb5_addr(val->r__address, error);
    if (!retval->r_address) {
	goto errout;
    }
    retval->checksum = KRB5_Checksum2krb5_checksum(val->cksum, error);
    if (!retval->checksum) {
	goto errout;
    }
    return(retval);
}
