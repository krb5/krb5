/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktgrq2tgrq_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include "KRB5-types.h"
#include "asn1glue.h"
#include "asn1defs.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

struct type_KRB5_TGS__REQ *
krb5_kdc_req2KRB5_TGS__REQ(val, error)
const register krb5_kdc_req *val;
register int *error;
{
    register struct type_KRB5_TGS__REQ *retval;
 
    retval = (struct type_KRB5_TGS__REQ *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->pvno = KRB5_PVNO;
    retval->msg__type = val->msg_type;
    retval->padata__type = val->padata_type;
    retval->padata = krb5_data2qbuf(&(val->padata));
    if (!retval->padata) {
	xfree(retval);
	*error = ENOMEM;
	return(0);
    }
    retval->req__body->kdc__options =
	krb5_kdcoptions2KRB5_KDCOptions(val->kdc_options,
					error);
    if (!retval->req__body->kdc__options) {
    errout:
	free_KRB5_TGS__REQ(retval);
	return(0);
    }
    if (val->client) {
	retval->req__body->cname =
	    krb5_principal2KRB5_PrincipalName(val->client, error);
	if (!retval->req__body->cname) {
	    goto errout;
	}
    }    
    retval->req__body->realm = krb5_data2qbuf(val->server[0]);
    if (!retval->req__body->realm) {
	*error = ENOMEM;
	goto errout;
    }
    retval->req__body->sname = krb5_principal2KRB5_PrincipalName(val->server,
								 error);
    if (!retval->req__body->sname) {
	goto errout;
    }
    retval->req__body->from = unix2gentime(val->from, error);
    if (!retval->req__body->from) {
	goto errout;
    }
    retval->req__body->till = unix2gentime(val->till, error);
    if (!retval->req__body->till) {
	goto errout;
    }
    if (val->kdc_options & KDC_OPT_RENEWABLE) {
	retval->req__body->rtime = unix2gentime(val->rtime, error);
	if (!retval->req__body->rtime) {
	    goto errout;
	}
    }
    retval->req__body->ctime = unix2gentime(val->ctime, error);
    if (!retval->req__body->ctime) {
	goto errout;
    }
    retval->req__body->nonce = val->nonce;
    retval->req__body->etype = val->etype;
 
    if (val->addresses) {
	retval->req__body->addresses =
	    krb5_address2KRB5_HostAddresses(val->addresses, error);
	if (!retval->req__body->addresses) {
	    goto errout;
	}
    }
    if (val->authorization_data) {
	retval->req__body->authorization__data =
	    krb5_authdata2KRB5_AuthorizationData(val->authorization_data,
						 error);
	if (!retval->req__body->authorization__data)
	    goto errout;
    }
    if (val->second_ticket) {
	struct element_KRB5_9 *adtk;
	krb5_ticket * const *temp;
	register int i;

	/* count elements */
	for (i = 0, temp = val->second_ticket; *temp; temp++,i++);

	adtk = (struct element_KRB5_9 *)xmalloc(sizeof(*retval) +
						max(0,i-1)*sizeof(adtk->Ticket));
	if (!adtk) {
	    *error = ENOMEM;
	    goto errout;
	}
	xbzero(adtk, sizeof(adtk));
	adtk->nelem = i;
	for (i = 0; i < adtk->nelem; i++) {
	    adtk->Ticket[i] = krb5_ticket2KRB5_Ticket(val->second_ticket[i],
						      error);
	    if (!adtk->Ticket[i]) {
		while (i >= 0) {
		    free_KRB5_Ticket(adtk->Ticket[i]);
		    i--;
		}
		xfree(adtk);
		goto errout;
	    }
	}
	retval->req__body->additional__tickets = adtk;
    }
    return(retval);
}
