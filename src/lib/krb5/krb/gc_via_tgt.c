/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Given a tgt, and a target cred, get it.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_gcvtgt_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

#include <krb5/asn1.h>

#include <krb5/los-proto.h>
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
			       cred->authdata,
			       0,		/* no padata */
			       0,		/* no second ticket */
			       tgt, &tgsrep))
	return retval;

#undef cleanup
#define cleanup() free(tgsrep.response.data)

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

#if 0
	/* XXX need access to the actual assembled request...
	   need a change to send_tgs */
	if ((err_reply->ctime != request.ctime) ||
	    !krb5_principal_compare(err_reply->server, request.server) ||
	    !krb5_principal_compare(err_reply->client, request.client))
	    retval = KRB5_KDCREP_MODIFIED;
	else
#endif
	    retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	krb5_free_error(err_reply);
	cleanup();
	return retval;
    }
    retval = krb5_decode_kdc_rep(&tgsrep.response,
				 &tgt->keyblock,
				 etype, /* enctype */
				 &dec_rep);
    cleanup();
    if (retval)
	return retval;
#undef cleanup
#define cleanup() {\
	memset((char *)dec_rep->enc_part2->session->contents, 0,\
	      dec_rep->enc_part2->session->length);\
		  krb5_free_kdc_rep(dec_rep); }

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	cleanup();
	return retval;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(dec_rep->client, tgt->client)) {
	cleanup();
	return KRB5_KDCREP_MODIFIED;
    }
    /* put pieces into cred-> */
    if (retval = krb5_copy_keyblock_contents(dec_rep->enc_part2->session,
					     &cred->keyblock)) {
	cleanup();
	return retval;
    }
    memset((char *)dec_rep->enc_part2->session->contents, 0,
	  dec_rep->enc_part2->session->length);

#undef cleanup
#define cleanup() {\
	memset((char *)cred->keyblock.contents, 0, cred->keyblock.length);\
		  krb5_free_kdc_rep(dec_rep); }

    cred->times = dec_rep->enc_part2->times;

#if 0
    /* XXX probably need access to the request */
    /* check the contents for sanity: */
    if (!krb5_principal_compare(dec_rep->client, request.client)
	|| !krb5_principal_compare(dec_rep->enc_part2->server, request.server)
	|| !krb5_principal_compare(dec_rep->ticket->server, request.server)
	|| (request.nonce != dec_rep->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(addrs, dec_rep->enc_part2->caddrs)) */
	|| ((request.from == 0) &&
	    !in_clock_skew(dec_rep->enc_part2->times.starttime))
	|| ((request.from != 0) &&
	    (request.from != dec_rep->enc_part2->times.starttime))
	|| ((request.till != 0) &&
	    (dec_rep->enc_part2->times.endtime > request.till))
	|| ((request.kdc_options & KDC_OPT_RENEWABLE) &&
	    (request.rtime != 0) &&
	    (dec_rep->enc_part2->times.renew_till > request.rtime))
	|| ((request.kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    (dec_rep->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request.till != 0) &&
	    (dec_rep->enc_part2->times.renew_till > request.till))
	) {
	cleanup();
	return KRB5_KDCREP_MODIFIED;
    }
#endif

    cred->ticket_flags = dec_rep->enc_part2->flags;
    cred->is_skey = FALSE;
    if (dec_rep->enc_part2->caddrs) {
	if (retval = krb5_copy_addresses(dec_rep->enc_part2->caddrs,
					 &cred->addresses)) {
	    cleanup();
	    return retval;
	}
    } else {
	/* no addresses in the list means we got what we had */
	if (retval = krb5_copy_addresses(tgt->addresses,
					 &cred->addresses)) {
	    cleanup();
	    return retval;
	}
    }
    if (retval = krb5_copy_principal(dec_rep->enc_part2->server,
				     &cred->server)) {
	cleanup();
	return retval;
    }

    if (retval = encode_krb5_ticket(dec_rep->ticket, &scratch)) {
	cleanup();
	krb5_free_addresses(cred->addresses);
	return retval;
    }

    cred->ticket = *scratch;
    xfree(scratch);

    krb5_free_kdc_rep(dec_rep);
    return retval;
}
