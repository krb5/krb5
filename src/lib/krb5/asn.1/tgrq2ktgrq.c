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
static char rcsid_tgrq2ktgrq_c[] =
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

krb5_kdc_req *
KRB5_TGS__REQ2krb5_kdc_req(val, error)
const register struct type_KRB5_TGS__REQ *val;
register int *error;
{
    register krb5_kdc_req *retval;
    krb5_data *temp;

    retval = (krb5_kdc_req *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->msg_type = val->msg__type;
    retval->padata_type = val->padata__type;
    if (val->padata) {
	temp = qbuf2krb5_data(val->padata, error);
	if (temp) {
	    retval->padata = *temp;
	    xfree(temp);
	} else {
	    goto errout;
	}
    }	

    retval->kdc_options =
	KRB5_KDCOptions2krb5_kdcoptions(val->req__body->kdc__options,
					error);
    if (*error) {
    errout:
	krb5_free_kdc_req(retval);
	return(0);
    }
    if (val->req__body->cname)
	retval->client =
	    KRB5_PrincipalName2krb5_principal(val->req__body->cname,
					      val->req__body->realm,
					      error);
    retval->server = KRB5_PrincipalName2krb5_principal(val->req__body->sname,
						       val->req__body->realm,
						       error);
    if (!retval->server) {
	goto errout;
    }
    retval->from = gentime2unix(val->req__body->from, error);
    if (*error) {
	goto errout;
    }
    retval->till = gentime2unix(val->req__body->till, error);
    if (*error) {
	goto errout;
    }
    if (retval->kdc_options & KDC_OPT_RENEWABLE) {
	retval->rtime = gentime2unix(val->req__body->rtime, error);
	if (*error) {
	    goto errout;
	}
    }
    retval->ctime = gentime2unix(val->req__body->ctime, error);
    if (*error) {
	goto errout;
    }
    retval->nonce = val->req__body->nonce;

    retval->etype = val->req__body->etype;


    if (val->req__body->addresses) {
	retval->addresses =
	    KRB5_HostAddresses2krb5_address(val->req__body->addresses, error);
	if (!retval->addresses) {
	    goto errout;
	}
    }
    if (val->req__body->authorization__data) {
	retval->authorization_data =
	    KRB5_AuthorizationData2krb5_authdata(val->req__body->
						 authorization__data,
						 error);
	if (*error)
	    goto errout;
    }
    if (val->req__body->additional__tickets) {
	register krb5_ticket **aticks;
        register struct element_KRB5_9 *tptr;
	register int i;

	tptr = val->req__body->additional__tickets;
	/* plus one for null terminator */
	aticks = (krb5_ticket **) xcalloc(tptr->nelem + 1,
					  sizeof(*aticks));
	for (i = 0; i < tptr->nelem; i++) {
	    aticks[i] = KRB5_Ticket2krb5_ticket(tptr->Ticket[i], error);
	    if (!aticks[i]) {
		while (i >= 0) {
		    krb5_free_ticket(aticks[i]);
		    i--;
		}
		goto errout;
	    }
	}
	retval->second_ticket = aticks;
    }
    return(retval);
}
