/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990,1991 by the Massachusetts Institute of Technology.
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
static char rcsid_auth2kauth_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

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
    if (val->cksum) {
	retval->checksum = KRB5_Checksum2krb5_checksum(val->cksum, error);
	if (!retval->checksum) {
	    krb5_free_authenticator(retval);
	    return(0);
	}
    }
    retval->cusec = val->cusec;
    retval->ctime = gentime2unix(val->ctime, error);
    if (*error) {
	krb5_free_authenticator(retval);
	return(0);
    }
    if (val->subkey) {
	retval->subkey = KRB5_EncryptionKey2krb5_keyblock(val->subkey, error);
	if (!retval->subkey) {
	    krb5_free_authenticator(retval);
	    return(0);
	}
    }
    if (val->optionals & opt_KRB5_Authenticator_seq__number) {
	retval->seq_number = val->seq__number;
    }
    return(retval);
}
