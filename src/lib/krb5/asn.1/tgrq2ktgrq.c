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
static char rcsid_tgrq2ktgrq_c[] =
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

krb5_tgs_req *
KRB5_TGS__REQ2krb5_tgs_req(val, error)
const register struct type_KRB5_TGS__REQ *val;
register int *error;
{
    register krb5_tgs_req *retval;
    krb5_data *temp;

    retval = (krb5_tgs_req *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    temp = qbuf2krb5_data(val->header, error);
    if (temp) {
	retval->header = *temp;
	xfree(temp);
    } else {
	xfree(retval);
	return(0);
    }
    temp = qbuf2krb5_data(val->tgs__request, error);
    if (temp) {
	retval->tgs_request = *temp;
	xfree(temp);
    } else {
	xfree(retval->header.data);
	xfree(retval);
	return(0);
    }
    return(retval);
}
