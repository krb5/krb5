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
register const krb5_cred_enc_part *val;
register int *error;
{
    struct type_KRB5_EncKrbCredPart *retval = 0;
    register struct element_KRB5_13 *rv1 = 0, *rv2;
    register krb5_cred_info * const *temp;
    register int i;

    retval = (struct type_KRB5_EncKrbCredPart *) xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero((char *)retval, sizeof (*retval));

    if (val->nonce) {
	retval->nonce = val->nonce;
	retval->optionals |= opt_KRB5_EncKrbCredPart_nonce;
    }
    
    if (val->timestamp) {
	retval->timestamp = unix2gentime(val->timestamp, error);
	if (!retval->timestamp) {
	  errout:
	    if (retval)
	      free_KRB5_EncKrbCredPart(retval);
	    *error = ENOMEM;
	    return(0);
	}
    }
    
    if (val->usec) {
	retval->usec = val->usec;
	retval->optionals |= opt_KRB5_EncKrbCredPart_usec;
    }
    
    if (val->s_address) {
	retval->s__address =
	  krb5_addr2KRB5_HostAddress(val->s_address, error); 
	if (!retval->s__address) {
	    goto errout;
	}
    }
    
    if (val->r_address) {
	retval->r__address =
	  krb5_addr2KRB5_HostAddress(val->r_address, error); 
	if (!retval->r__address) {
	    goto errout;
	}
    }
	
    for (i = 0, temp = val->ticket_info; *temp; temp++, i++, rv1 = rv2) {
 	
	rv2 = (struct element_KRB5_13 *) xmalloc(sizeof(*rv2));
	if (!rv2)
	  goto errout;

        xbzero((char *)rv2, sizeof (*rv2));

        if (rv1)
            rv1->next = rv2;

        if (!retval->ticket__info)
            retval->ticket__info = rv2;

	rv2->KRB__CRED__INFO = (struct type_KRB5_KRB__CRED__INFO *)
            xmalloc(sizeof(*(rv2->KRB__CRED__INFO)));
        if (!rv2->KRB__CRED__INFO)
            goto errout;
        xbzero((char *)rv2->KRB__CRED__INFO, sizeof (*rv2->KRB__CRED__INFO));

	rv2->KRB__CRED__INFO->key =
	  krb5_keyblock2KRB5_EncryptionKey(val->ticket_info[i]->session, 
					   error);
	if (!rv2->KRB__CRED__INFO->key) {
	    goto errout;
	}
	
	if (val->ticket_info[i]->client) {
	    rv2->KRB__CRED__INFO->prealm =
	      krb5_data2qbuf(krb5_princ_realm(val->ticket_info[i]->client)); 
	    if (!rv2->KRB__CRED__INFO->prealm) {
		goto errout;
	    }
	    rv2->KRB__CRED__INFO->pname =
	      krb5_principal2KRB5_PrincipalName(val->ticket_info[i]->client, 
						error); 
	    if (!rv2->KRB__CRED__INFO->pname) {
		goto errout;
	    }
	}
	
	if (val->ticket_info[i]->flags) {
	    rv2->KRB__CRED__INFO->flags =
	      krb5_flags2KRB5_TicketFlags(val->ticket_info[i]->flags, error); 
	    if (!rv2->KRB__CRED__INFO->flags) {
		goto errout;
	    }
	}
	
	if (val->ticket_info[i]->times.authtime) {
	    rv2->KRB__CRED__INFO->authtime =
	      unix2gentime(val->ticket_info[i]->times.authtime, error); 
	    if (!rv2->KRB__CRED__INFO->authtime) {
		goto errout;
	    }
	}

	if (val->ticket_info[i]->times.starttime) {
	    rv2->KRB__CRED__INFO->starttime =
	      unix2gentime(val->ticket_info[i]->times.starttime, error); 
	    if (!rv2->KRB__CRED__INFO->starttime) {
		goto errout;
	    }
	}

	if (val->ticket_info[i]->times.endtime) {
	    rv2->KRB__CRED__INFO->endtime =
	      unix2gentime(val->ticket_info[i]->times.endtime, error); 
	    if (!rv2->KRB__CRED__INFO->endtime) {
		goto errout;
	    }
	}

	if (val->ticket_info[i]->flags & TKT_FLG_RENEWABLE) {
	    rv2->KRB__CRED__INFO->renew__till =
	      unix2gentime(val->ticket_info[i]->times.renew_till, error); 
	    if (!rv2->KRB__CRED__INFO->renew__till) {
		goto errout;
	    }
	}
	
	if (val->ticket_info[i]->server) {
	    rv2->KRB__CRED__INFO->srealm =
	      krb5_data2qbuf(krb5_princ_realm(val->ticket_info[i]->server)); 
	    if (!rv2->KRB__CRED__INFO->srealm) {
		*error = ENOMEM;
		goto errout;
	    }
	    rv2->KRB__CRED__INFO->sname =
	      krb5_principal2KRB5_PrincipalName(val->ticket_info[i]->server, 
						error); 
	    if (!rv2->KRB__CRED__INFO->sname) {
		goto errout;
	    }
	}

	if (val->ticket_info[i]->caddrs) {
	    rv2->KRB__CRED__INFO->caddr =
	      krb5_address2KRB5_HostAddresses(val->ticket_info[i]->caddrs, 
					      error); 
	    if (!rv2->KRB__CRED__INFO->caddr) {
		goto errout;
	    }
	}
    }

    return(retval);
}
