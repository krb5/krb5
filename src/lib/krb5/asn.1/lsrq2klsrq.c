/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_lsrq2klsrq_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_last_req_entry **
KRB5_LastReq2krb5_last_req(val, error)
const struct type_KRB5_LastReq *val;
register int *error;
{
#if 0
    /* this code is for -h2 style ISODE structures.  However, pepsy
       generates horribly broken when given -h2. */

    register krb5_last_req_entry **retval;
    register int i;

    /* plus one for null terminator */
    retval = (krb5_last_req_entry **) xcalloc(val->nelem + 1,
					      sizeof(krb5_last_req_entry *));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    for (i = 0; i < val->nelem; i++) {
	retval[i] = (krb5_last_req_entry *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_last_req(retval);
	    *error = ENOMEM;
	    return(0);
	}
	retval[i]->value = gentime2unix(val->element_KRB5_4[i]->lr__value,
					error);
	if (*error) {
	    /* value is zero if error, so it won't get freed... */
	    krb5_free_last_req(retval);
	    return(0);
	}
	retval[i]->lr_type = val->element_KRB5_4[i]->lr__type;
    }
    retval[i] = 0;
    return(retval);
#endif
    register krb5_last_req_entry **retval;
    register int i;
    register const struct type_KRB5_LastReq *rv;

    for (i = 0, rv = val; rv; i++, rv = rv->next)
	;

    /* plus one for null terminator */
    retval = (krb5_last_req_entry **) xcalloc(i + 1, sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    for (i = 0, rv = val; rv; rv = rv->next, i++) {
	retval[i] = (krb5_last_req_entry *) xmalloc(sizeof(*retval[i]));
	if (!retval[i]) {
	    krb5_free_last_req(retval);
	    *error = ENOMEM;
	    return(0);
	}
	retval[i]->value = gentime2unix(rv->element_KRB5_4->lr__value,
					error);
	if (*error) {
	    /* value is zero if error, so it won't get freed... */
	    krb5_free_last_req(retval);
	    return(0);
	}
	retval[i]->lr_type = rv->element_KRB5_4->lr__type;
    }
    retval[i] = 0;
    return(retval);
}
