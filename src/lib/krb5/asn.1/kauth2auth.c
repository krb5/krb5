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
static char rcsid_kauth2auth_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

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
    retval->authenticator__vno = KRB5_PVNO;
    retval->crealm = krb5_data2qbuf(val->client[0]);
    if (!retval->crealm) {
	*error = ENOMEM;
    errout:
	free_KRB5_Authenticator(retval);
	return(0);
    }
    retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
    if (!retval->cname) {
	goto errout;
    }
    if (val->checksum) {
	retval->cksum = krb5_checksum2KRB5_Checksum(val->checksum, error);
	if (!retval->cksum) {
	    goto errout;
	}
    }
    retval->cusec = val->cusec;
    retval->ctime = unix2gentime(val->ctime, error);
    if (!retval->ctime) {
	goto errout;
    }
    if (val->subkey) {
	retval->subkey = krb5_keyblock2KRB5_EncryptionKey(val->subkey, error);
	if (!retval->subkey)
	    goto errout;
    }
    if (val->seq_number) {
	retval->seq__number = val->seq_number;
	retval->optionals |= opt_KRB5_Authenticator_seq__number;
    }
    return(retval);
}
