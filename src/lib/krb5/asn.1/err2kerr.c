/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_err2kerr_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_error *
KRB5_KRB__ERROR2krb5_error(val, error)
const register struct type_KRB5_KRB__ERROR *val;
register int *error;
{
    register krb5_error *retval;
    krb5_data *temp;

    retval = (krb5_error *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));


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
	    xfree(temp);
	} else {
	    goto errout;
	}
    }
    if (val->e__data) {
	temp = qbuf2krb5_data(val->e__text, error);
	if (temp) {
	    retval->text = *temp;
	    xfree(temp);
	} else {
	    goto errout;
	}
    }
    return(retval);
}
