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
static char rcsid_kaprq2aprq_c[] =
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

struct type_KRB5_AP__REQ *
krb5_ap_req2KRB5_AP__REQ(val, error)
const register krb5_ap_req *val;
register int *error;
{
    register struct type_KRB5_AP__REQ *retval;

    retval = (struct type_KRB5_AP__REQ *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_AP_REQ;

    retval->ap__options = krb5_apoptions2KRB5_APOptions(val->ap_options,
							error);
    if (!retval->ap__options) {
	xfree(retval);
	return(0);
    }
    retval->ticket = krb5_ticket2KRB5_Ticket(val->ticket, error);
    if (!retval->ticket) {
	free_KRB5_AP__REQ(retval);
	return(0);
    }
    retval->authenticator = krb5_data2qbuf(&(val->authenticator));
    if (!retval->authenticator) {
	free_KRB5_AP__REQ(retval);
	*error = ENOMEM;
	return(0);
    }
    return(retval);
}
