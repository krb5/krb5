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
static char rcsid_kcrep2crep_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_EncKrbCredPart *
krb5_cred_enc_part2KRB5_EncKrbCredPart(val, error)
const register krb5_cred_enc_part *val;
register int *error;
{
    register struct type_KRB5_EncKrbCredPart *retval = 0, *rv1 = 0, *rv2;
    register krb5_cred_enc_struct * const *temp;
    register int i;

    for (i = 0, temp = val->creds; *temp; temp++, i++, rv1 = rv2) {
 	
	rv2 = (struct type_KRB5_EncKrbCredPart *) xmalloc(sizeof(*rv2));
	if (!rv2) {
	    if (retval)
		free_KRB5_EncKrbCredPart(retval);
	    *error = ENOMEM;
	    return(0);
	}
        xbzero((char *)rv2, sizeof (*rv2));

        if (rv1)
            rv1->next = rv2;

        if (!retval)
            retval = rv2;

	rv2->element_KRB5_13 = (struct element_KRB5_14 *)
	    xmalloc(sizeof(*(rv2->element_KRB5_13)));
	if (!rv2->element_KRB5_13) {
	  errout:
	    if (retval)
		free_KRB5_AuthorizationData(retval);
	    *error = ENOMEM;
	    return(0);
	} 
        xbzero((char *)rv2->element_KRB5_13, sizeof (*rv2->element_KRB5_13));
	
	rv2->element_KRB5_13->key =
	  krb5_keyblock2KRB5_EncryptionKey(val->creds[i]->session, error);
	if (!rv2->element_KRB5_13->key) {
	    goto errout;
	}
	
	if (val->creds[i]->nonce) {
	    rv2->element_KRB5_13->nonce = val->creds[i]->nonce;
	    rv2->element_KRB5_13->optionals |= opt_KRB5_element_KRB5_14_nonce;
	}
	
	rv2->element_KRB5_13->timestamp = unix2gentime(val->creds[i]->timestamp, error);
	if (!rv2->element_KRB5_13->timestamp) {
	    goto errout;
	}
	
	rv2->element_KRB5_13->usec = val->creds[i]->usec;
	
	if (val->creds[i]->s_address) {
	    rv2->element_KRB5_13->s__address =
	      krb5_addr2KRB5_HostAddress(val->creds[i]->s_address, error); 
	    if (!rv2->element_KRB5_13->s__address) {
		goto errout;
	    }
	}
 
	if (val->creds[i]->r_address) {
	    rv2->element_KRB5_13->r__address =
	      krb5_addr2KRB5_HostAddress(val->creds[i]->r_address, error); 
	    if (!rv2->element_KRB5_13->r__address) {
		goto errout;
	    }
	}
	
	if (val->creds[i]->client) {
	    rv2->element_KRB5_13->prealm =
	      krb5_data2qbuf(krb5_princ_realm(val->creds[i]->client)); 
	    if (!rv2->element_KRB5_13->prealm) {
		goto errout;
	    }
	    rv2->element_KRB5_13->pname =
	      krb5_principal2KRB5_PrincipalName(val->creds[i]->client, error); 
	    if (!rv2->element_KRB5_13->pname) {
		goto errout;
	    }
	}
	
	if (val->creds[i]->flags) {
	    rv2->element_KRB5_13->flags =
	      krb5_flags2KRB5_TicketFlags(val->creds[i]->flags, error); 
	    if (!rv2->element_KRB5_13->flags) {
		goto errout;
	    }
	}
	
	rv2->element_KRB5_13->authtime =
	  unix2gentime(val->creds[i]->times.authtime, error); 
	if (!rv2->element_KRB5_13->authtime) {
	    goto errout;
	}
	if (val->creds[i]->times.starttime) {
	    rv2->element_KRB5_13->starttime =
	      unix2gentime(val->creds[i]->times.starttime, error); 
	    if (!rv2->element_KRB5_13->starttime) {
		goto errout;
	    }
	}
	rv2->element_KRB5_13->endtime =
	  unix2gentime(val->creds[i]->times.endtime, error); 
	if (!rv2->element_KRB5_13->endtime) {
	    goto errout;
	}
	if (val->creds[i]->flags & TKT_FLG_RENEWABLE) {
	    rv2->element_KRB5_13->renew__till =
	      unix2gentime(val->creds[i]->times.renew_till, error); 
	    if (!rv2->element_KRB5_13->renew__till) {
		goto errout;
	    }
	}
	
	if (val->creds[i]->server) {
	    rv2->element_KRB5_13->srealm =
	      krb5_data2qbuf(krb5_princ_realm(val->creds[i]->server)); 
	    if (!rv2->element_KRB5_13->srealm) {
		*error = ENOMEM;
		goto errout;
	    }
	    rv2->element_KRB5_13->sname =
	      krb5_principal2KRB5_PrincipalName(val->creds[i]->server, error); 
	    if (!rv2->element_KRB5_13->sname) {
		goto errout;
	    }
	}

	if (val->creds[i]->caddrs) {
	    rv2->element_KRB5_13->caddr =
	      krb5_address2KRB5_HostAddresses(val->creds[i]->caddrs, error); 
	    if (!rv2->element_KRB5_13->caddr) {
		goto errout;
	    }
	}
    }

    if (retval == 0)
	*error = ISODE_LOCAL_ERR_MISSING_PART;

    return(retval);
}
