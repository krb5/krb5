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
static char rcsid_ktgrq2tgrq_c[] =
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

struct type_KRB5_TGS__REQ *
krb5_tgs_req2KRB5_TGS__REQ(val, error)
const register krb5_tgs_req *val;
register int *error;
{
    register struct type_KRB5_TGS__REQ *retval;
 
    retval = (struct type_KRB5_TGS__REQ *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->header = krb5_data2qbuf(&(val->header));
    if (!retval->header) {
	xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    retval->tgs__request = krb5_data2qbuf(&(val->tgs_request));
    if (!retval->tgs__request) {
	xfree(retval->header);
	xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    return(retval);
}
