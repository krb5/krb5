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


krb5_pa_data **
element_KRB5_112krb5_pa_data(val, error)
    struct element_KRB5_11 *val;
    register int *error;
{
    register krb5_pa_data **retval;
    register int i;
    register struct element_KRB5_11 *rv;

    for (i = 0, rv = val; rv; i++, rv = rv->next)
	;

    /* plus one for null terminator */
    retval = (krb5_pa_data **) xcalloc(i + 1, sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    for (i = 0, rv = val; rv; rv = rv->next, i++) {
	if (qb_pullup(rv->PA__DATA->pa__data) != OK) {
	    retval[i] = 0;
	    krb5_free_pa_data(retval);
	    *error = ENOMEM;
	    return(0);
	}
	retval[i] = (krb5_pa_data *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_pa_data(retval);
	    *error = ENOMEM;
	    return(0);
	}
	retval[i]->pa_type = rv->PA__DATA->padata__type;
	retval[i]->length = rv->PA__DATA->pa__data->qb_forw->qb_len;
	if (retval[i]->length) {
	    retval[i]->contents = (unsigned char *)xmalloc(rv->PA__DATA->pa__data->qb_forw->qb_len);
	    if (!retval[i]->contents) {
		krb5_xfree(retval[i]);
		retval[i] = 0;
		krb5_free_pa_data(retval);
		*error = ENOMEM;
		return(0);
	    }
	    xbcopy(rv->PA__DATA->pa__data->qb_forw->qb_data,
		   retval[i]->contents, retval[i]->length);
        } else
	    retval[i]->contents = 0;
    }
    retval[i] = 0;
    return(retval);
}


krb5_kdc_rep *
KRB5_KDC__REP2krb5_kdc_rep(val, error)
register const struct type_KRB5_TGS__REP *val;
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
	retval->padata = element_KRB5_112krb5_pa_data(val->padata, error);
	if (*error) {
	    krb5_xfree(retval);
	    return 0;

	}
    }
    retval->client = KRB5_PrincipalName2krb5_principal(val->cname,
						       val->crealm,
						       error);
    if (!retval->client) {
	krb5_free_kdc_rep(retval);
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
	krb5_xfree(temp);
    } else {
	krb5_free_kdc_rep(retval);
	return(0);
    }
    return(retval);
}
