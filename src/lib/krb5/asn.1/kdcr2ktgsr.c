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
static char rcsid_kdcr2ktgsr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_kdc_rep *
KRB5_KDC__REP2krb5_tgs_rep(val, error)
const register struct type_KRB5_TGS__REP *val;
register int *error;
{
    krb5_msgtype type;
    register krb5_kdc_rep *retval;

    retval = KRB5_KDC__REP2krb5_kdc_rep(val, &type, error);
    if (retval && (type != KRB5_TGS_REP)) {
	krb5_free_kdc_rep(retval);
	*error = ISODE_50_LOCAL_ERR_BADMSGTYPE;
	return 0;
    }
    return retval;
}
