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
static char rcsid_kekrp2ekrp_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_EncTGSRepPart *
krb5_enc_kdc_rep_part2KRB5_EncTGSRepPart(val, error)
const register krb5_enc_kdc_rep_part *val;
register int *error;
{
    register struct type_KRB5_EncTGSRepPart *retval;

    retval = (struct type_KRB5_EncTGSRepPart *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->key = krb5_keyblock2KRB5_EncryptionKey(val->session, error);
    if (!retval->key) {
	xfree(retval);
	return(0);
    }
    retval->last__req = krb5_last_req2KRB5_LastReq(val->last_req, error);
    if (!retval->last__req) {
    errout:
	free_KRB5_EncTGSRepPart(retval);
	return(0);
    }
    retval->nonce = val->nonce;
    if (val->key_exp) {
	retval->key__expiration = unix2gentime(val->key_exp, error);
	if (!retval->key__expiration) {
	    goto errout;
	}
    }
    retval->flags = krb5_flags2KRB5_TicketFlags(val->flags, error);
    if (!retval->flags) {
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
    retval->srealm = krb5_data2qbuf(val->server[0]);
    if (!retval->srealm) {
	*error = ENOMEM;
	goto errout;
    }
    retval->sname = krb5_principal2KRB5_PrincipalName(val->server, error);
    if (!retval->sname) {
	goto errout;
    }
    if (val->caddrs) {
	retval->caddr = krb5_address2KRB5_HostAddresses(val->caddrs, error);
	if (!retval->caddr) {
	    goto errout;
	}
    }
    return(retval);
}
