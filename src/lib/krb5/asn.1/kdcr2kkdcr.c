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
static char rcsid_kdcr2kkdcr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_kdc_rep *
KRB5_KDC__REP2krb5_kdc_rep(val, error)
const register struct type_KRB5_TGS__REP *val;
register int *error;
{
    register krb5_kdc_rep *retval;
    krb5_enc_data *temp;

    retval = (krb5_kdc_rep *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->msg_type = val->msg__type;

    if (val->padata) {
	retval->padata = KRB5_PA__DATA2krb5_pa_data(val->padata, error);
	if (*error) {
	    xfree(retval);
	    return 0;

	}
    }
    retval->client = KRB5_PrincipalName2krb5_principal(val->cname,
						       val->crealm,
						       error);
    if (!retval->client) {
	xfree(retval);
	return(0);
    }

    retval->ticket = KRB5_Ticket2krb5_ticket(val->ticket, error);
    if (!retval->ticket) {
	krb5_free_kdc_rep(retval);
	return(0);
    }
    temp = KRB5_EncryptedData2krb5_enc_data(val->enc__part, error);
    if (temp) {
	retval->enc_part = *temp;
	xfree(temp);
    } else {
	krb5_free_kdc_rep(retval);
	return(0);
    }
    return(retval);
}
