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
static char rcsid_kaprq2aprq_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_AP__REQ *
krb5_ap_req2KRB5_AP__REQ(val, error)
register const krb5_ap_req *val;
register int *error;
{
    register struct type_KRB5_AP__REQ *retval;

    retval = (struct type_KRB5_AP__REQ *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_AP_REQ;

    retval->ap__options = krb5_apoptions2KRB5_APOptions(val->ap_options,
							error);
    if (!retval->ap__options) {
	krb5_xfree(retval);
	return(0);
    }
    retval->ticket = krb5_ticket2KRB5_Ticket(val->ticket, error);
    if (!retval->ticket) {
	free_KRB5_AP__REQ(retval);
	return(0);
    }
    retval->authenticator =
	krb5_enc_data2KRB5_EncryptedData(&(val->authenticator),
					 error);
    if (!retval->authenticator) {
	free_KRB5_AP__REQ(retval);
	return(0);
    }
    return(retval);
}
