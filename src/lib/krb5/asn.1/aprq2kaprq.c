/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_aprq2kaprq_c[] =
"$Id$";
#endif	/* lint || saber */

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
	krb5_xfree(temp);
    } else {
	krb5_free_ap_req(retval);
	return(0);
    }
  
    return(retval);
}
