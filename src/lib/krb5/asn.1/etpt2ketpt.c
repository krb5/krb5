/*
 * $Source$
 * $Author$
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

#if !defined(lint) && !defined(SABER)
static char rcsid_etpt2ketpt_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_enc_tkt_part *
KRB5_EncTicketPart2krb5_enc_tkt_part(val, error)
register const struct type_KRB5_EncTicketPart *val;
register int *error;
{
    register krb5_enc_tkt_part *retval;
    krb5_transited *temp;

    if (!val) {
	    *error = EINVAL;
	    return 0;
    }

    retval = (krb5_enc_tkt_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset(retval, 0, sizeof(*retval));


    retval->flags = KRB5_TicketFlags2krb5_flags(val->flags, error);
    if (*error) {
	krb5_xfree(retval);
	return(0);
    }

    retval->session = KRB5_EncryptionKey2krb5_keyblock(val->key, error);
    if (!retval->session) {
    errout:
	krb5_free_enc_tkt_part(retval);
	return(0);
    }
    retval->client = KRB5_PrincipalName2krb5_principal(val->cname,
						       val->crealm,
						       error);
    if (!retval->client) {
	goto errout;
    }

    temp = KRB5_TransitedEncoding2krb5_transited(val->transited, error);
    if (temp) {
	retval->transited = *temp;
	krb5_xfree(temp);
    } else {
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
    if (*error) {
	goto errout;
    }	
    if (val->renew__till) {
	retval->times.renew_till = gentime2unix(val->renew__till, error);
	if (*error) {
	    goto errout;
	}	
    }
    if (val->caddr) {
        retval->caddrs = KRB5_HostAddresses2krb5_address(val->caddr, error);
        if (!retval->caddrs) {
	    goto errout;
        }
    }
    if (val->authorization__data) {
	retval->authorization_data =
	    KRB5_AuthorizationData2krb5_authdata(val->authorization__data,
						 error);
	if (!retval->authorization_data) {
	    goto errout;
	}
    }
    return(retval);
}
