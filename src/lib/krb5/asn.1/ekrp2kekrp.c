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
static char rcsid_ekrp2kekrp_c[] =
"$Id$";
#endif	/* lint || saber */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

/*#include <time.h> */
#include <isode/psap.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/* ISODE defines max(a,b) */

krb5_enc_kdc_rep_part *
KRB5_EncTGSRepPart2krb5_enc_kdc_rep_part(val, error)
const register struct type_KRB5_EncTGSRepPart *val;
register int *error;
{
    register krb5_enc_kdc_rep_part *retval;

    retval = (krb5_enc_kdc_rep_part *)xmalloc(sizeof(*retval));
    if (!retval) {
	*error = ENOMEM;
	return(0);
    }
    xbzero(retval, sizeof(*retval));

    retval->session = KRB5_EncryptionKey2krb5_keyblock(val->key, error);
    if (!retval->session) {
	xfree(retval);
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
						       val->realm,
						       error);
    if (!retval->server) {
	goto errout;
    }
    retval->caddrs = KRB5_HostAddresses2krb5_address(val->caddr, error);
    if (!retval->caddrs) {
	goto errout;
    }
    return(retval);
}
