/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_adat2kadat_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
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
}
