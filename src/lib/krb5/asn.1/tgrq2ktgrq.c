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
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */
#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

krb5_kdc_req *
KRB5_KDC__REQ__BODY2krb5_kdc_req(val, error)
const register struct type_KRB5_KDC__REQ__BODY *val;
register int *error;
{
    register krb5_kdc_req *retval;
    krb5_enc_data *temp;

    retval = (krb5_kdc_req *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->kdc_options =
	KRB5_KDCOptions2krb5_kdcoptions(val->kdc__options,
					error);
    if (*error) {
    errout:
	krb5_free_kdc_req(retval);
	return(0);
    }
    if (val->cname)
	retval->client =
	    KRB5_PrincipalName2krb5_principal(val->cname,
					      val->realm,
					      error);
    retval->server = KRB5_PrincipalName2krb5_principal(val->sname,
						       val->realm,
						       error);
    if (!retval->server) {
	goto errout;
    }
    retval->from = gentime2unix(val->from, error);
    if (*error) {
	goto errout;
    }
    retval->till = gentime2unix(val->till, error);
    if (*error) {
	goto errout;
    }
    if (retval->kdc_options & KDC_OPT_RENEWABLE) {
	retval->rtime = gentime2unix(val->rtime, error);
	if (*error) {
	    goto errout;
	}
    }
    retval->nonce = val->nonce;

    retval->etype = (krb5_enctype *) xmalloc(sizeof(*(retval->etype))*min(1,val->etype->nelem));
    if (!retval->etype)
	goto errout;
#if 0
    for (i = 0; i < val->etype->nelem; i++) {
	retval->etype[i] = val->etype->element_KRB5_9[i];
    }
    val->netypes = val->etype->nelem;
#else
    /* XXX @#$#@ broken ASN.1 compiler */
    retval->etype[0] = val->etype->element_KRB5_9;
    retval->netypes = 1;
#endif

    if (val->addresses) {
	retval->addresses =
	    KRB5_HostAddresses2krb5_address(val->addresses, error);
	if (!retval->addresses) {
	    goto errout;
	}
    }
    if (val->enc__authorization__data) {
	temp = KRB5_EncryptedData2krb5_enc_data(val->enc__authorization__data,
						error);
	if (temp) {
	    retval->authorization_data = *temp;
	    xfree(temp);
	} else
	    goto errout;
    }
    if (val->additional__tickets) {
	register krb5_ticket **aticks;
        register struct element_KRB5_10 *tptr;
	register int i;

	tptr = val->additional__tickets;
	/* plus one for null terminator */
	aticks = (krb5_ticket **) xcalloc(tptr->nelem + 1,
					  sizeof(*aticks));
	for (i = 0; (i < tptr->nelem) && tptr->Ticket[i]; i++) {
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
    return retval;
}

krb5_kdc_req *
KRB5_TGS__REQ2krb5_kdc_req(val, error)
const register struct type_KRB5_TGS__REQ *val;
register int *error;
{
    register krb5_kdc_req *retval;

    if (!(retval = KRB5_KDC__REQ__BODY2krb5_kdc_req(val->req__body, error)))
	return retval;

    retval->msg_type = val->msg__type;
    if (val->padata) {
	retval->padata = KRB5_PA__DATA2krb5_pa_data(val->padata, error);
	if (!retval->padata) {
	    krb5_free_kdc_req(retval);
	    return(0);
	}
    }	
    return(retval);
}
