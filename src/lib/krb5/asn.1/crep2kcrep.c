/*
 * lib/krb5/asn.1/crep2kcrep.c
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

krb5_cred_enc_part *
KRB5_EncKrbCredPart2krb5_cred_enc_part(val, error)
register const struct type_KRB5_EncKrbCredPart *val;
register int *error;
{
    register krb5_cred_enc_part *retval;
    register int i;
    register const struct element_KRB5_13 *rv;

    retval = (krb5_cred_enc_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    memset((char *)retval, 0, sizeof(*retval));

    /* Count ticket_info */
    for (i = 0, rv = val->ticket__info; rv; i++, rv = rv->next);

    /* plus one for null terminator */
    retval->ticket_info = (krb5_cred_info **) 
      xcalloc(i + 1, sizeof(*retval->ticket_info));
    if (!retval->ticket_info) {
	*error = ENOMEM;
	krb5_xfree(retval);
	return(0);
    }
    
    if (val->optionals & opt_KRB5_EncKrbCredPart_nonce)
      retval->nonce = val->nonce;
    else
      retval->nonce = 0;
    
    if (val->timestamp) {
	if (!(val->optionals & opt_KRB5_EncKrbCredPart_usec)) {
	    /* must have usec if we have timestamp */
	    *error = ISODE_50_LOCAL_ERR_BADCOMBO;
	    goto errout;
	}
	
	retval->timestamp = gentime2unix(val->timestamp, error);
	if (*error) {
	  errout:
	    krb5_free_cred_enc_part(retval);
	    return(0);
	}
	retval->usec = val->usec;
    } else {
	retval->timestamp = 0;
	retval->usec = 0;
    }
	
    if (val->s__address) {
	retval->s_address = 
	  KRB5_HostAddress2krb5_addr(val->s__address, 
				     error);
	if (!retval->s_address) {
	    goto errout;
	}
    }
    
    if (val->r__address) {
	retval->r_address =
	  KRB5_HostAddress2krb5_addr(val->r__address, 
				     error); 
	if (!retval->r_address) {
	    goto errout;
	}
    }
    
    for (i = 0, rv = val->ticket__info; rv; rv = rv->next, i++) {
	retval->ticket_info[i] = (krb5_cred_info *) 
	  xmalloc(sizeof(*retval->ticket_info[i]));
	if (!retval->ticket_info[i]) {
	    *error = ENOMEM;
	    goto errout;
	}
	memset((char *)retval->ticket_info[i], 0, 
	       sizeof(*retval->ticket_info[i]));

	retval->ticket_info[i]->session = 
	  KRB5_EncryptionKey2krb5_keyblock(rv->KRB__CRED__INFO->key, error);
	if (!retval->ticket_info[i]->session)
	  goto errout;
	
	if (rv->KRB__CRED__INFO->pname && rv->KRB__CRED__INFO->prealm) {
	    retval->ticket_info[i]->client = 
	      KRB5_PrincipalName2krb5_principal(rv->KRB__CRED__INFO->pname,
						rv->KRB__CRED__INFO->prealm,
						error);
	    if (!retval->ticket_info[i]->client)
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->sname && rv->KRB__CRED__INFO->srealm) {
	    retval->ticket_info[i]->server = 
	      KRB5_PrincipalName2krb5_principal(rv->KRB__CRED__INFO->sname,
						rv->KRB__CRED__INFO->srealm,
						error);
	    if (!retval->ticket_info[i]->server)
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->flags) {
	    retval->ticket_info[i]->flags =
	      KRB5_TicketFlags2krb5_flags(rv->KRB__CRED__INFO->flags, error);
	    if (*error)
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->authtime) {
	    retval->ticket_info[i]->times.authtime =
	      gentime2unix(rv->KRB__CRED__INFO->authtime, error);
	    if (*error) 
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->starttime) {
	    retval->ticket_info[i]->times.starttime = 
	      gentime2unix(rv->KRB__CRED__INFO->starttime, error);
	    if (*error)
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->endtime) {
	    retval->ticket_info[i]->times.endtime = 
	      gentime2unix(rv->KRB__CRED__INFO->endtime, error);
	    if (*error)
	      goto errout;
	}
	
	if ((retval->ticket_info[i]->flags & TKT_FLG_RENEWABLE) && 
	    rv->KRB__CRED__INFO->renew__till) {
	    retval->ticket_info[i]->times.renew_till = 
	      gentime2unix(rv->KRB__CRED__INFO->renew__till, error);
	    if (*error)
	      goto errout;
	}
	
	if (rv->KRB__CRED__INFO->caddr) {
	    retval->ticket_info[i]->caddrs = 
	      KRB5_HostAddresses2krb5_address(rv->KRB__CRED__INFO->caddr, 
					      error);
	    if (!retval->ticket_info[i]->caddrs)
	      goto errout;
	}
    }

    retval->ticket_info[i] = 0;
    return(retval);
}
