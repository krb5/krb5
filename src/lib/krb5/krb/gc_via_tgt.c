/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Given a tgt, and a target cred, get it.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gcvtgt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>

#include <krb5/asn1.h>

#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>
#include "int-proto.h"

krb5_error_code
krb5_get_cred_via_tgt (DECLARG(krb5_creds *, tgt),
		       DECLARG(const krb5_flags, kdcoptions),
		       DECLARG(const krb5_enctype, etype),
		       DECLARG(const krb5_cksumtype, sumtype),
		       DECLARG(krb5_creds *, cred))
OLDDECLARG(krb5_creds *, tgt)
OLDDECLARG(const krb5_flags, kdcoptions)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_cksumtype, sumtype)
OLDDECLARG(krb5_creds *, cred)
{
    krb5_error_code retval;
    krb5_principal tempprinc;
    krb5_data *scratch;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;

    /* tgt->client must be equal to cred->client */
    /* tgt->server must be equal to krbtgt/realmof(cred->client) */
    if (!krb5_principal_compare(tgt->client, cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    if (retval = krb5_tgtname(krb5_princ_realm(cred->server),
			      krb5_princ_realm(cred->client), &tempprinc))
	return(retval);
    
    if (!krb5_principal_compare(tempprinc, tgt->server)) {
	krb5_free_principal(tempprinc);
	return KRB5_PRINC_NOMATCH;
    }
    krb5_free_principal(tempprinc);


    if (retval = krb5_send_tgs(kdcoptions, &cred->times, etype, sumtype,
			       cred->server,
			       tgt->addresses,
			       0,	/* no authorization data */
			       0,		/* no second ticket */
			       tgt, &tgsrep))
	return retval;

#undef cleanup
#define cleanup() {(void) free(tgsrep.response.data);}

    switch (tgsrep.message_type) {
    case KRB5_TGS_REP:
	break;
    case KRB5_ERROR:
    default:
	if (!krb5_is_krb_error(&tgsrep.response)) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	} else
	    retval = decode_krb5_error(&tgsrep.response, &err_reply);
	if (retval) {
	    cleanup();
	    return retval;		/* neither proper reply nor error! */
	}
	/* XXX check to make sure the timestamps match, etc. */

	retval = err_reply->error + ERROR_TABLE_BASE_krb5;
	krb5_free_error(err_reply);
	cleanup();
	return retval;
	break;				/* not strictly necessary... */
    }
    retval = krb5_decode_kdc_rep(&tgsrep.response,
				 &tgt->keyblock,
				 etype, /* enctype */
				 &dec_rep);
    cleanup();
    if (retval)
	return retval;
#undef cleanup
#define cleanup() krb5_free_kdc_rep(dec_rep)

    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(dec_rep->client, tgt->client)) {
	cleanup();
	return KRB5_KDCREP_MODIFIED;
    }
    /* put pieces into cred-> */
    if (retval = krb5_copy_keyblock(dec_rep->enc_part2->session,
				    &cred->keyblock)) {
	cleanup();
	return retval;
    }
    cred->times = dec_rep->enc_part2->times;
    /* check compatibility here first ? XXX */
    cred->ticket_flags = dec_rep->enc_part2->flags;
    cred->is_skey = FALSE;
    if (retval = krb5_copy_addresses(dec_rep->enc_part2->caddrs,
				     &cred->addresses)) {
	cleanup();
	return retval;
    }

    if (retval = krb5_encode_ticket(dec_rep->ticket, &scratch))
	krb5_free_address(cred->addresses);
    else {
	cred->ticket = *scratch;
	free((char *)scratch);
    }

    cleanup();
    return retval;
}
