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
static char rcsid_etpt2ketpt_c[] =
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

krb5_enc_tkt_part *
KRB5_EncTicketPart2krb5_enc_tkt_part(val, error)
const register struct type_KRB5_EncTicketPart *val;
register int *error;
{
    register krb5_enc_tkt_part *retval;
    krb5_data *temp;

    retval = (krb5_enc_tkt_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));


    retval->flags = KRB5_TicketFlags2krb5_flags(val->flags, error);
    if (*error) {
	xfree(retval);
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
    temp = qbuf2krb5_data(val->transited, error);
    if (temp) {
	retval->transited = *temp;
	xfree(temp);
    } else {
	goto errout;
    }

    retval->times.authtime = gentime2unix(val->authtime, error);
    if (*error) {
	goto errout;
    }	
    retval->times.starttime = gentime2unix(val->starttime, error);
    if (*error) {
	goto errout;
    }	
    retval->times.endtime = gentime2unix(val->endtime, error);
    if (*error) {
	goto errout;
    }	
    if (retval->flags & TKT_FLG_RENEWABLE) {
	retval->times.renew_till = gentime2unix(val->renew__till, error);
	if (*error) {
	    goto errout;
	}	
    }

    retval->caddrs = KRB5_HostAddresses2krb5_address(val->caddr, error);
    if (!retval->caddrs) {
	goto errout;
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
