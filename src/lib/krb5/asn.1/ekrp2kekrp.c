/*
 * lib/krb5/asn.1/ekrp2kekrp.c
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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


#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_enc_kdc_rep_part *
KRB5_EncKDCRepPart2krb5_enc_kdc_rep_part(val, error)
register const struct type_KRB5_EncKDCRepPart *val;
register int *error;
{
    register krb5_enc_kdc_rep_part *retval;

    retval = (krb5_enc_kdc_rep_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));

    retval->session = KRB5_EncryptionKey2krb5_keyblock(val->key, error);
    if (!retval->session) {
	krb5_xfree(retval);
	return(0);
    }

    retval->last_req = KRB5_LastReq2krb5_last_req(val->last__req, error);
    if (!retval->last_req) {
    errout:
	krb5_free_enc_kdc_rep_part(retval);
	return(0);
    }

    retval->nonce = val->nonce;

    if (val->key__expiration) {
	retval->key_exp = gentime2unix(val->key__expiration, error);
	if (*error) {
	    goto errout;
	}
    }
    retval->flags = KRB5_TicketFlags2krb5_flags(val->flags, error);
    if (*error) {
	goto errout;
    }
    retval->times.authtime = gentime2unix(val->authtime, error);
    if (*error) {
	goto errout;
    }
    if (val->starttime) {
	retval->times.starttime = gentime2unix(val->starttime, error);
	if (*error) {
	    goto errout;
	}
    }
    retval->times.endtime = gentime2unix(val->endtime, error);
    if (retval->flags & TKT_FLG_RENEWABLE) {
	retval->times.renew_till = gentime2unix(val->renew__till, error);
	if (*error) {
	    goto errout;
	}
    }
    retval->server = KRB5_PrincipalName2krb5_principal(val->sname,
						       val->srealm,
						       error);
    if (!retval->server) {
	goto errout;
    }
    if (val->caddr) {
	retval->caddrs = KRB5_HostAddresses2krb5_address(val->caddr, error);
	if (!retval->caddrs) {
	    goto errout;
	}
    }
    return(retval);
}
