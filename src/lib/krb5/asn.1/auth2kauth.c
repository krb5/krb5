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
static char rcsid_auth2kauth_c[] =
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

krb5_authenticator *
KRB5_Authenticator2krb5_authenticator(val, error)
const register struct type_KRB5_Authenticator *val;
register int *error;
{
    register krb5_authenticator *retval;

    retval = (krb5_authenticator *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }

    xbzero(retval, sizeof(*retval));

    retval->client = KRB5_PrincipalName2krb5_principal(val->cname,
						       val->crealm,
						       error);
    if (!retval->client) {
	xfree(retval);
	return(0);
    }

    retval->checksum = KRB5_Checksum2krb5_checksum(val->cksum, error);
    if (!retval->checksum) {
	krb5_free_authenticator(retval);
	return(0);
    }
    retval->cmsec = val->cmsec;
    retval->ctime = gentime2unix(val->ctime, error);
    if (*error) {
	krb5_free_authenticator(retval);
	return(0);
    }
    return(retval);
}
