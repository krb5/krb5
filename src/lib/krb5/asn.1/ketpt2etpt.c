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
static char rcsid_ketpt2etpt_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

struct type_KRB5_EncTicketPart *
krb5_enc_tkt_part2KRB5_EncTicketPart(val, error)
const register krb5_enc_tkt_part *val;
register int *error;
{
    register struct type_KRB5_EncTicketPart *retval;

    retval = (struct type_KRB5_EncTicketPart *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->flags = krb5_flags2KRB5_TicketFlags(val->flags, error);
    if (*error) {
	xfree(retval);
	return(0);
    }
    retval->key = krb5_keyblock2KRB5_EncryptionKey(val->session, error);
    if (!retval->key) {
    errout:
	free_KRB5_EncTicketPart(retval);
	return(0);
    }
    retval->crealm = krb5_data2qbuf(val->client[0]);
    if (!retval->crealm) {
	*error = ENOMEM;
	goto errout;
    }
    retval->cname = krb5_principal2KRB5_PrincipalName(val->client, error);
    if (!retval->cname) {
	goto errout;
    }
    retval->transited =
	krb5_transited2KRB5_TransitedEncoding(&(val->transited), error);
    if (!retval->transited) {
	goto errout;
    }
    retval->authtime = unix2gentime(val->times.authtime, error);
    if (!retval->authtime) {
	goto errout;
    }
    if (val->times.starttime) {
	retval->starttime = unix2gentime(val->times.starttime, error);
	if (!retval->starttime) {
	    goto errout;
	}
    }
    retval->endtime = unix2gentime(val->times.endtime, error);
    if (!retval->endtime) {
	goto errout;
    }
    if (val->flags & TKT_FLG_RENEWABLE) {
	retval->renew__till = unix2gentime(val->times.renew_till, error);
	if (!retval->renew__till) {
	    goto errout;
	}
    }
    retval->caddr = krb5_address2KRB5_HostAddresses(val->caddrs, error);
    if (!retval->caddr) {
	goto errout;
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
