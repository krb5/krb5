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
static char rcsid_aprp2kaprp_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_ap_rep *
KRB5_AP__REP2krb5_ap_rep(val, error)
const register struct type_KRB5_AP__REP *val;
register int *error;
{
    register krb5_ap_rep *retval;
    krb5_enc_data *temp;

    retval = (krb5_ap_rep *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    temp = KRB5_EncryptedData2krb5_enc_data(val->enc__part, error);
    if (temp) {
	retval->enc_part = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    return(retval);
}
