/*
 * lib/krb5/asn.1/err2kerr.c
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

krb5_error *
KRB5_KRB__ERROR2krb5_error(val, error)
register const struct type_KRB5_KRB__ERROR *val;
register int *error;
{
    register krb5_error *retval;
    krb5_data *temp;

    retval = (krb5_error *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));


    if (val->ctime) {
	retval->ctime = gentime2unix(val->ctime, error);
	if (*error) {
	errout:
	    krb5_free_error(retval);
	    return(0);
	}	
    }
    if (val->optionals & opt_KRB5_KRB__ERROR_cusec)
	retval->cusec = val->cusec;
    else
	retval->cusec = 0;

    retval->stime = gentime2unix(val->stime, error);
    if (*error) {
	goto errout;
    }	
    retval->susec = val->susec;
    retval->error = val->error__code;
    if (val->crealm && val->cname) {
	retval->client = KRB5_PrincipalName2krb5_principal(val->cname,
							   val->crealm,
							   error);
	if (!retval->client) {
	    goto errout;
	}
    }
    if (val->sname && val->realm) {
	retval->server = KRB5_PrincipalName2krb5_principal(val->sname,
							   val->realm,
							   error);
	if (!retval->server) {
	    goto errout;
	}
    }
    if (val->e__text) {
	temp = qbuf2krb5_data(val->e__text, error);
	if (temp) {
	    retval->text = *temp;
	    krb5_xfree(temp);
	} else {
	    goto errout;
	}
    }
    if (val->e__data) {
	temp = qbuf2krb5_data(val->e__data, error);
	if (temp) {
	    retval->e_data = *temp;
	    krb5_xfree(temp);
	} else {
	    goto errout;
	}
    }
    return(retval);
}
