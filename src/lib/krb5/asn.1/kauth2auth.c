/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
register const krb5_authenticator *val;
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
    retval->crealm = krb5_data2qbuf(krb5_princ_realm(val->client));
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
    if (val->authorization_data && *val->authorization_data) {
	retval->authorization__data =
	    krb5_authdata2KRB5_AuthorizationData(val->authorization_data, error);
	if (!retval->authorization__data) {
	    goto errout;
	}
    }
    return(retval);
}
