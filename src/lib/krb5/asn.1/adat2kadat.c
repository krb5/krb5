/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
static char rcsid_adat2kadat_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_authdata **
KRB5_AuthorizationData2krb5_authdata(val, error)
const struct type_KRB5_AuthorizationData *val;
register int *error;
{
#if 0
    /* this code is for -h2 style ISODE structures.  However, pepsy
       generates horribly broken when given -h2. */

    register krb5_authdata **retval;
    register int i;

    /* plus one for null terminator */
    retval = (krb5_authdata **) xcalloc(val->nelem + 1,
					sizeof(krb5_authdata *));
    if (!retval) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    for (i = 0; i < val->nelem; i++) {
	if (qb_pullup(val->element_KRB5_2[i]->ad__data) != OK) {
	    xfree(retval);
	    goto nomem;
	}
	retval[i] = (krb5_authdata *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_authdata(retval);
	    goto nomem;
	}
	retval[i]->contents = (unsigned char *)xmalloc(val->element_KRB5_2[i]->ad__data->qb_forw->qb_len);
	if (!retval[i]->contents) {
	    xfree(retval[i]);
	    retval[i] = 0;
	    krb5_free_authdata(retval);
	    goto nomem;
	}
	retval[i]->ad_type = val->element_KRB5_2[i]->ad__type;
	retval[i]->length = val->element_KRB5_2[i]->ad__data->qb_forw->qb_len;
	xbcopy(val->element_KRB5_2[i]->ad__data->qb_forw->qb_data,
	      &retval[i]->contents[0], retval[i]->length);
    }
    retval[i] = 0;
    return(retval);
#endif

    register krb5_authdata **retval;
    register int i;
    register const struct type_KRB5_AuthorizationData *rv;

    for (i = 0, rv = val; rv; i++, rv = rv->next)
	;

    /* plus one for null terminator */
    retval = (krb5_authdata **) xcalloc(i + 1, sizeof(*retval));
    if (!retval) {
    nomem:
	*error = ENOMEM;
	return(0);
    }
    for (i = 0, rv = val; rv; rv = rv->next, i++) {
	if (qb_pullup(rv->element_KRB5_2->ad__data) != OK) {
	    xfree(retval);
	    goto nomem;
	}
	retval[i] = (krb5_authdata *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_authdata(retval);
	    goto nomem;
	}
	retval[i]->contents = (unsigned char *)xmalloc(rv->element_KRB5_2->ad__data->qb_forw->qb_len);
	if (!retval[i]->contents) {
	    xfree(retval[i]);
	    retval[i] = 0;
	    krb5_free_authdata(retval);
	    goto nomem;
	}
	retval[i]->ad_type = rv->element_KRB5_2->ad__type;
	retval[i]->length = rv->element_KRB5_2->ad__data->qb_forw->qb_len;
	xbcopy(rv->element_KRB5_2->ad__data->qb_forw->qb_data,
	      retval[i]->contents, retval[i]->length);
    }
    retval[i] = 0;
    return(retval);
}
