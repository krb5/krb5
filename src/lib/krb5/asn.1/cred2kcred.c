/*
 * lib/krb5/asn.1/cred2kcred.c
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


#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_cred *
KRB5_KRB__CRED2krb5_cred(val, error)
register const struct type_KRB5_KRB__CRED *val;
register int *error;
{
    register krb5_cred *retval;
    register int i;
    register struct element_KRB5_12 *rv;
    krb5_enc_data *temp;

    retval = (krb5_cred *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset((char *)retval, 0, sizeof(*retval));

    /* Count tickets */
    for (i = 0, rv = val->tickets; rv; i++, rv = rv->next);

    /* plus one for null terminator */
    retval->tickets = (krb5_ticket **) xcalloc(i + 1, sizeof(*retval->tickets));
    if (!retval->tickets) {
	*error = ENOMEM;
	krb5_xfree(retval);
	return(0);
    }
    
    /* Copy tickets */
    for (i = 0, rv = val->tickets; rv; rv = rv->next, i++) {
	retval->tickets[i] = (krb5_ticket *) xmalloc(sizeof(*retval->tickets[i]));
	if (!retval->tickets[i]) {
	    krb5_free_tickets(retval->tickets);
	    *error = ENOMEM;
	    krb5_xfree(retval);
	    return(0);
	}
	memset((char *)retval->tickets[i], 0, sizeof(*retval->tickets[i]));

	retval->tickets[i] = KRB5_Ticket2krb5_ticket(rv->Ticket, error);
	if (!retval->tickets[i]) {
	    krb5_free_tickets(retval->tickets);
	    krb5_xfree(retval);
	    return(0);
	}
    }
    retval->tickets[i] = 0;

    /* Copy encrypted part */
    temp = KRB5_EncryptedData2krb5_enc_data(val->enc__part, error);
    if (temp) {
	retval->enc_part = *temp;
	krb5_xfree(temp);
    } else {
	krb5_free_tickets(retval->tickets);
	krb5_xfree(retval);
	return(0);
    }

    return(retval);
}
