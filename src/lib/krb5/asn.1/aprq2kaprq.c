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
static char rcsid_aprq2kaprq_c[] =
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

krb5_ap_req *
KRB5_AP__REQ2krb5_ap_req(val, error)
const register struct type_KRB5_AP__REQ *val;
register int *error;
{
    register krb5_ap_req *retval;
    krb5_enc_data *temp;

    retval = (krb5_ap_req *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));
    
    retval->ap_options = KRB5_APOptions2krb5_apoptions(val->ap__options,
						       error);
    retval->ticket = KRB5_Ticket2krb5_ticket(val->ticket, error);
    if (!retval->ticket) {
	krb5_free_ap_req(retval);
	return(0);
    }
    temp = KRB5_EncryptedData2krb5_enc_data(val->authenticator, error);
    if (temp) {
	retval->authenticator = *temp;
	xfree(temp);
    } else {
	krb5_free_ap_req(retval);
	return(0);
    }
  
    return(retval);
}
