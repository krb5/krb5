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
static char rcsid_crep2kcrep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_cred_enc_part *
KRB5_EncKrbCredPart2krb5_cred_enc_part(val, error)
const register struct type_KRB5_EncKrbCredPart *val;
register int *error;
{
    register krb5_cred_enc_part *retval;
    register int i;
    register const struct type_KRB5_EncKrbCredPart *rv;
    register const struct element_KRB5_14 *rv2;

    retval = (krb5_cred_enc_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero((char *)retval, sizeof(*retval));

    for (i = 0, rv = val; rv; i++, rv = rv->next);

    /* plus one for null terminator */
    retval->creds = (krb5_cred_enc_struct **) xcalloc(i + 1, sizeof(*retval->creds));
    if (!retval->creds) {
    nomem:
	*error = ENOMEM;
	return(0);
    }

    for (i = 0, rv = val; rv; rv = rv->next, i++) {
	rv2 = rv->element_KRB5_13;
	retval->creds[i] = (krb5_cred_enc_struct *) xmalloc(sizeof(*retval->creds[i]));
	if (!retval->creds[i]) {
	    krb5_free_cred_enc_part(retval);
	    goto nomem;
	}
	xbzero((char *)retval->creds[i], sizeof(*retval->creds[i]));

	retval->creds[i]->session = KRB5_EncryptionKey2krb5_keyblock(rv2->key, error);
	if (!retval->creds[i]->session) {
	    xfree(retval->creds[i]);
	    return(0);
	}
	
	if (rv2->optionals & opt_KRB5_element_KRB5_14_nonce)
	  retval->creds[i]->nonce = rv2->nonce;
	else
	  retval->creds[i]->nonce = 0;
	
	retval->creds[i]->timestamp = gentime2unix(rv2->timestamp, error);
	if (*error) {
	  errout:
	    krb5_free_cred_enc_part(retval->creds[i]);
	    return(0);
	}
	retval->creds[i]->usec = rv2->usec;
	
	if (rv2->s__address) {
	    retval->creds[i]->s_address = KRB5_HostAddress2krb5_addr(rv2->s__address, 
								     error);
	    if (!retval->creds[i]->s_address) {
		goto errout;
	    }
	}
	
	if (rv2->r__address) {
	    retval->creds[i]->r_address = KRB5_HostAddress2krb5_addr(rv2->r__address, 
								     error); 
	    if (!retval->creds[i]->r_address) {
		goto errout;
	    }
	}
	
	if (rv2->pname && rv2->prealm) {
	    retval->creds[i]->client = KRB5_PrincipalName2krb5_principal(rv2->pname,
									 rv2->prealm,
									 error);
	    if (!retval->creds[i]->client) {
		goto errout;
	    }
	}
	
	if (rv2->sname && rv2->srealm) {
	    retval->creds[i]->server = KRB5_PrincipalName2krb5_principal(rv2->sname,
									 rv2->srealm,
									 error);
	    if (!retval->creds[i]->server) {
		goto errout;
	    }
	}
	
	if (rv2->flags) {
	    retval->creds[i]->flags = KRB5_TicketFlags2krb5_flags(rv2->flags, error);
	    if (*error) {
		xfree(retval->creds[i]);
		return(0);
	    }
	}
	
	if (rv2->authtime) {
	    retval->creds[i]->times.authtime = gentime2unix(rv2->authtime, error);
	    if (*error) {
		goto errout;
	    }	
	}
	
	if (rv2->starttime) {
	    retval->creds[i]->times.starttime = gentime2unix(rv2->starttime, error);
	    if (*error) {
		goto errout;
	    }	
	}
	
	if (rv2->endtime) {
	    retval->creds[i]->times.endtime = gentime2unix(rv2->endtime, error);
	    if (*error) {
		goto errout;
	    }	
	}
	
	if ((retval->creds[i]->flags & TKT_FLG_RENEWABLE) && rv2->renew__till) {
	    retval->creds[i]->times.renew_till = gentime2unix(rv2->renew__till, error);
	    if (*error) {
		goto errout;
	    }	
	}
	
	if (rv2->caddr) {
	    retval->creds[i]->caddrs = KRB5_HostAddresses2krb5_address(rv2->caddr, 
								       error);
	    if (!retval->creds[i]->caddrs) {
		goto errout;
	    }
	}
    }
    retval->creds[i] = 0;
    return(retval);
}
