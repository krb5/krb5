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
static char rcsid_kauth2auth_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_Authenticator *
krb5_authenticator2KRB5_Authenticator(val, error)
const register krb5_authenticator *val;
register int *error;
{
    register struct type_KRB5_Authenticator *retval;

    retval = (struct type_KRB5_Authenticator *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }

    xbzero(retval, sizeof(*retval));
    retval->authenticator__vno = (struct type_KRB5_AuthenticatorVersion *)
	xmalloc(sizeof(*retval->authenticator__vno));
    if (!retval->authenticator__vno) {
	*error = ENOMEM;
    errout:
	free_KRB5_Authenticator(retval);
	return(0);
    }
    retval->authenticator__vno->parm = KRB5_PVNO;
    retval->crealm = krb5_data2qbuf(val->client[0]);
    if (!retval->crealm) {
	*error = ENOMEM;
	goto errout;
    }
    retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
    if (!retval->cname) {
	goto errout;
    }
    retval->cksum = krb5_checksum2KRB5_Checksum(val->checksum, error);
    if (!retval->cksum) {
	goto errout;
    }
    retval->cmsec = val->cmsec;
    retval->ctime = unix2gentime(val->ctime, error);
    if (!retval->ctime) {
	goto errout;
    }
    return(retval);
}
