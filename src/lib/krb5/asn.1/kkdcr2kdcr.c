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
static char rcsid_kkdcr2kdcr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>


struct element_KRB5_11 *krb5_pa_data2element_KRB5_11(val, error)
    krb5_pa_data **val;
    int *error;
{
    register struct element_KRB5_11 *retval = 0, *rv1 = 0, *rv2;
    register krb5_pa_data * const *temp;
    register int i;


    *error = 0;

    if (val == 0) 
	return 0;

    /* count elements */
    for (i = 0, temp = val; *temp; temp++,i++, rv1 = rv2) {

	rv2 = (struct element_KRB5_11 *) xmalloc(sizeof(*rv2));
	if (!rv2) {
	errout:
	    while (retval) {
		free_KRB5_PA__DATA(retval->PA__DATA);
		rv1 = retval->next;
		free(retval);
		retval = rv1;
	    }
	    *error = ENOMEM;
	    return(0);
	}
	if (rv1)
	    rv1->next = rv2;
	xbzero((char *)rv2, sizeof (*rv2));
	if (!retval)
	    retval = rv2;

	rv2->PA__DATA = (struct type_KRB5_PA__DATA *)
	    xmalloc(sizeof(*(rv2->PA__DATA)));
	if (!rv2->PA__DATA)
	    goto errout;
	rv2->PA__DATA->padata__type = val[i]->pa_type;
	rv2->PA__DATA->pa__data = str2qb((char *)(val[i])->contents,
					       (val[i])->length, 1);
	if (!rv2->PA__DATA->pa__data) {
	    goto errout;
	}
    }
    if (retval == 0)
	*error = ISODE_LOCAL_ERR_MISSING_PART;
    return(retval);

}

struct type_KRB5_TGS__REP *
krb5_kdc_rep2KRB5_KDC__REP(DECLARG(register const krb5_kdc_rep *,val),
			   DECLARG(register int *,error))
OLDDECLARG(register const krb5_kdc_rep *,val)
OLDDECLARG(register int *,error)
{
    register struct type_KRB5_TGS__REP *retval;

    retval = (struct type_KRB5_TGS__REP *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = val->msg_type;

    if (val->padata) {
	retval->padata = krb5_pa_data2element_KRB5_11(val->padata, error);
	if (*error) {
	    goto errout;
	}
    }

    retval->crealm = krb5_data2qbuf(krb5_princ_realm(val->client));
    if (!retval->crealm) {
	*error = ENOMEM;
    errout:
	free_KRB5_TGS__REP(retval);
	return(0);
    }
    retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
    if (!retval->cname) {
	goto errout;
    }
    retval->ticket = krb5_ticket2KRB5_Ticket(val->ticket, error);
    if (!retval->ticket) {
	goto errout;
    }
    retval->enc__part = krb5_enc_data2KRB5_EncryptedData(&(val->enc_part),
							 error);
    if (!retval->enc__part) {
	goto errout;
    }
    return(retval);
}
