/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
static char rcsid_ktgrq2tgrq_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_KDC__REQ__BODY *
krb5_kdc_req2KRB5_KDC__REQ__BODY(val, error)
const register krb5_kdc_req *val;
register int *error;
{
    register struct type_KRB5_KDC__REQ__BODY *retval;

    retval = (struct type_KRB5_KDC__REQ__BODY *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }

    xbzero(retval, sizeof(*retval));

    retval->kdc__options =
	krb5_kdcoptions2KRB5_KDCOptions(val->kdc_options,
					error);
    if (!retval->kdc__options) {
    errout:
	free_KRB5_KDC__REQ__BODY(retval);
	return(0);
    }
    if (val->client) {
	retval->cname =
	    krb5_principal2KRB5_PrincipalName(val->client, error);
	if (!retval->cname) {
	    goto errout;
	}
    }    
    retval->realm = krb5_data2qbuf(krb5_princ_realm(val->server));
    if (!retval->realm) {
	*error = ENOMEM;
	goto errout;
    }
    retval->sname = krb5_principal2KRB5_PrincipalName(val->server, error);
    if (!retval->sname) {
	goto errout;
    }
    if (val->from) {
	retval->from = unix2gentime(val->from, error);
	if (!retval->from) {
	    goto errout;
	}
    }
    retval->till = unix2gentime(val->till, error);
    if (!retval->till) {
	goto errout;
    }
    if (val->rtime) {
	retval->rtime = unix2gentime(val->rtime, error);
	if (!retval->rtime) {
	    goto errout;
	}
    }
    retval->nonce = val->nonce;
#if 0
    /* XXX !@#*)@# busted ASN.1 compiler, -h2 doesn't generate compilable
       code */
    retval->etype = (struct element_KRB5_8 *)malloc(sizeof(*retval->etype)+
						    max(0,val->netypes-1)*sizeof(integer));
    if (!retval->etype) {
	*error = ENOMEM;
	goto errout;
    }    
    for (i = 0; i < val->netypes; i++) {
	retval->etype->element_KRB5_9[i] = val->etype[i];
    }
    retval->etype->nelem = val->netypes;
#endif
    {
	register struct element_KRB5_8 *rv1 = 0, *rv2;
	register int i;

	for (i = 0; i < val->netypes; i++, rv1 = rv2) {
	    rv2 = (struct element_KRB5_8 *) xmalloc(sizeof(*rv2));
	    if (!rv2) {
		*error = ENOMEM;
		goto errout;
	    }
	    if (rv1)
		rv1->next = rv2;
	    xbzero((char *)rv2, sizeof (*rv2));
	    if (!retval->etype)
		retval->etype = rv2;
	    rv2->element_KRB5_9 = val->etype[i];
	}
    }
 
    if (val->addresses) {
	retval->addresses =
	    krb5_address2KRB5_HostAddresses(val->addresses, error);
	if (!retval->addresses) {
	    goto errout;
	}
    }
    if (val->authorization_data.ciphertext.data) {
	retval->enc__authorization__data =
	    krb5_enc_data2KRB5_EncryptedData(&(val->authorization_data),
						 error);
	if (!retval->enc__authorization__data)
	    goto errout;
    }
    if (val->second_ticket) {
#if 0
	/* code for -h2 structures, which generate bogus code from pepsy */

	struct element_KRB5_10 *adtk;
	krb5_ticket * const *temp;
	register int i;

	/* count elements */
	for (i = 0, temp = val->second_ticket; *temp; temp++,i++);

	adtk = (struct element_KRB5_10 *)xmalloc(sizeof(*adtk) +
						max(0,i-1)*sizeof(adtk->Ticket));
	if (!adtk) {
	    *error = ENOMEM;
	    goto errout;
	}
	xbzero(adtk, sizeof(*adtk));
	adtk->nelem = i;
	for (i = 0; i < adtk->nelem; i++) {
	    adtk->Ticket[i] = krb5_ticket2KRB5_Ticket(val->second_ticket[i],
						      error);
	    if (!adtk->Ticket[i]) {
		while (i >= 0) {
		    free_KRB5_Ticket(adtk->Ticket[i]);
		    i--;
		}
		krb5_xfree(adtk);
		goto errout;
	    }
	}
	retval->additional__tickets = adtk;
#endif
	register struct element_KRB5_10 *adtk = 0, *rv1 = 0, *rv2;
	krb5_ticket * const *temp;
	register int i;

	/* count elements */
	for (i = 0, temp = val->second_ticket; *temp; temp++,i++, rv1 = rv2) {

	    rv2 = (struct element_KRB5_10 *)xmalloc(sizeof(*rv2));
	    if (!rv2) {
		*error = ENOMEM;
		goto errout;
	    }
	    if (rv1)
		rv1->next = rv2;
	    xbzero((char *)rv2, sizeof (*rv2));
	    if (!adtk)
		adtk = rv2;

	    rv2->Ticket = krb5_ticket2KRB5_Ticket(val->second_ticket[i],
						   error);
	    if (!rv2->Ticket) {
		for (rv1 = adtk; rv1; rv1 = rv2) {
		    if (rv1->Ticket)
			free_KRB5_Ticket(rv1->Ticket);
		    rv2 = rv1->next;
		    krb5_xfree(rv1);
		}
		goto errout;
	    }
	}
	retval->additional__tickets = adtk;
    } else {
#if 0
	/* this was once necessary to get around faulty optional processing */

	struct element_KRB5_10 *adtk;
	adtk = (struct element_KRB5_10 *)xmalloc(sizeof(*adtk));
	if (!adtk) {
	    *error = ENOMEM;
	    goto errout;
	}
	xbzero(adtk, sizeof(*adtk));
	adtk->nelem = 0;
	retval->additional__tickets = adtk;
#endif
	retval->additional__tickets = 0;
    }
	
    return retval;
}


struct element_KRB5_7 *krb5_pa_data2element_KRB5_7(val, error)
    krb5_pa_data **val;
    int *error;
{
    register struct element_KRB5_7 *retval = 0, *rv1 = 0, *rv2;
    register krb5_pa_data * const *temp;
    register int i;


    *error = 0;

    if (val == 0) 
	return 0;

    /* count elements */
    for (i = 0, temp = val; *temp; temp++,i++, rv1 = rv2) {

	rv2 = (struct element_KRB5_7 *) xmalloc(sizeof(*rv2));
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

struct type_KRB5_KDC__REQ *
krb5_kdc_req2KRB5_KDC__REQ(val, error)
const register krb5_kdc_req *val;
register int *error;
{
    register struct type_KRB5_KDC__REQ *retval;
 
    retval = (struct type_KRB5_KDC__REQ *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));
    retval->pvno = KRB5_PVNO;
    retval->msg__type = val->msg_type;
    if (val->padata) {
	retval->padata = krb5_pa_data2element_KRB5_7(val->padata, error);
	if (*error) {
	    krb5_xfree(retval);
	    return 0;
	}
    }
    retval->req__body = krb5_kdc_req2KRB5_KDC__REQ__BODY(val, error);
    if (!retval->req__body) {
	free_KRB5_KDC__REQ(retval);
	return(0);
    }
    return(retval);
}
