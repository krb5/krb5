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
static char rcsid_tran2ktran_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_transited *
KRB5_TransitedEncoding2krb5_transited(val, error)
const register struct type_KRB5_TransitedEncoding *val;
register int *error;
{
    register krb5_transited *retval;
    krb5_data *temp;

    retval = (krb5_transited *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->tr_type = val->tr__type;
    temp = qbuf2krb5_data(val->contents, error);
    if (temp) {
	retval->tr_contents = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    return(retval);
}
