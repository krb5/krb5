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
static char rcsid_kerr2err_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_KRB__ERROR *
krb5_error2KRB5_KRB__ERROR(val, error)
const register krb5_error *val;
register int *error;
{
    register struct type_KRB5_KRB__ERROR *retval;

    retval = (struct type_KRB5_KRB__ERROR *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = KRB5_ERROR;

    retval->ctime = unix2gentime(val->ctime, error);
    if (!retval->ctime) {
	xfree(retval);
	return(0);
    }
    retval->cmsec = val->cmsec;

    retval->stime = unix2gentime(val->stime, error);
    if (!retval->stime) {
    errout:
	free_KRB5_KRB__ERROR(retval);
	return(0);
    }
    retval->smsec = val->smsec;
    retval->error = val->error;

    if (val->client) {
	retval->crealm = krb5_data2qbuf(val->client[0]);
	if (!retval->crealm) {
	    *error = ENOMEM;
	    goto errout;
	}
	retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
	if (!retval->cname) {
	    goto errout;
	}
    }

    if (val->server) {
	retval->srealm = krb5_data2qbuf(val->server[0]);
	if (!retval->srealm) {
	    *error = ENOMEM;
	    goto errout;
	}
	retval->sname = krb5_principal2KRB5_PrincipalName(val->server, error);
	if (!retval->sname) {
	    goto errout;
	}
    }
    if (val->text.data) {
	retval->e__text = krb5_data2qbuf(&val->text);
	if (!retval->e__text) {
	    *error = ENOMEM;
	    goto errout;
	}
    }
    return(retval);
}
