/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
static char rcsid_kcred2cred_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */


struct type_KRB5_KRB__CRED *
krb5_cred2KRB5_KRB__CRED(val, error)
const register krb5_cred *val;
register int *error;
{
    register struct type_KRB5_KRB__CRED *retval;
    register struct element_KRB5_12 *rv1 = 0, *rv2;
    register krb5_ticket * const *temp;
    register int i;
 
    retval = (struct type_KRB5_KRB__CRED *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero((char *)retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_CRED;

    /* Copy tickets */
    for (i = 0, temp = val->tickets; *temp; temp++, i++, rv1 = rv2) {

        rv2 = (struct element_KRB5_12 *) xmalloc(sizeof(*rv2));
        if (!rv2) {
        errout:
            while (retval->tickets) {
                free_KRB5_Ticket(retval->tickets->Ticket);
                rv1 = retval->tickets->next;
                free(retval->tickets);
                retval->tickets = rv1;
            }
            *error = ENOMEM;
            return(0);
        }
        if (rv1)
            rv1->next = rv2;
        xbzero((char *)rv2, sizeof (*rv2));
        if (!retval->tickets)
            retval->tickets = rv2;

        rv2->Ticket = (struct type_KRB5_Ticket *)
            xmalloc(sizeof(*(rv2->Ticket)));
        if (!rv2->Ticket)
            goto errout;
	
	rv2->Ticket = krb5_ticket2KRB5_Ticket(val->tickets[i], error);
	if (!rv2->Ticket) {
	    xfree(retval->tickets);
	    return(0);
	}
    }

    if (!retval->tickets) {
	xfree(retval);
	return(0);
    }

    retval->enc__part = krb5_enc_data2KRB5_EncryptedData(&(val->enc_part),
							 error);
    if (!retval->enc__part) {
	xfree(retval);
	return(0);
    }
    return(retval);
}
