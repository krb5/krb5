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
static char rcsid_kerr2err_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

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

    if (val->ctime) {
	retval->ctime = unix2gentime(val->ctime, error);
	if (!retval->ctime) {
	    xfree(retval);
	    return(0);
	}
    }
    if (val->cusec) {
	retval->cusec = val->cusec;
	retval->optionals = opt_KRB5_KRB__ERROR_cusec;
    }

    retval->stime = unix2gentime(val->stime, error);
    if (!retval->stime) {
    errout:
	free_KRB5_KRB__ERROR(retval);
	return(0);
    }
    retval->susec = val->susec;
    retval->error__code = val->error;

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

    /* server is technically not optional, but... */
    if (val->server) {
	retval->realm = krb5_data2qbuf(val->server[0]);
	if (!retval->realm) {
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
    if (val->e_data.data) {
	retval->e__data = krb5_data2qbuf(&val->e_data);
	if (!retval->e__data) {
	    *error = ENOMEM;
	    goto errout;
	}
    }
    return(retval);
}
