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
static char rcsid_kaprp2aprp_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_AP__REP *
krb5_ap_rep2KRB5_AP__REP(val, error)
const register krb5_ap_rep *val;
register int *error;
{
    register struct type_KRB5_AP__REP *retval;
 
    retval = (struct type_KRB5_AP__REP *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_AP_REP;
    retval->enc__part = krb5_enc_data2KRB5_EncryptedData(&(val->enc_part),
							 error);
    if (!retval->enc__part) {
	xfree(retval);
	return(0);
    }
    return(retval);
}
