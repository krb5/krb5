/*
 * lib/krb5/krb/gc_via_tgt.c
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


#include <krb5/krb5.h>

#include <krb5/asn1.h>

#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#include "int-proto.h"

krb5_error_code
krb5_get_cred_via_tgt (context, tgt, kdcoptions, sumtype, cred)
    krb5_context context;
    krb5_creds * tgt;
    const krb5_flags kdcoptions;
    const krb5_cksumtype sumtype;
    krb5_creds * cred;
{
    krb5_error_code retval;
    krb5_principal tempprinc;
    krb5_data *scratch;
    krb5_enctype etype;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;

    /* tgt->client must be equal to cred->client */

    if (!krb5_principal_compare(context, tgt->client, cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    /* check if we have the right TGT                    */
    /* tgt->server must be equal to                      */
    /* krbtgt/realmof(cred->server)@realmof(tgt->server) */

    if(retval = krb5_tgtname(context, 
		     krb5_princ_realm(context, cred->server),
		     krb5_princ_realm(context, tgt->server), &tempprinc))
	return(retval);
    if (!krb5_principal_compare(context, tempprinc, tgt->server)) {
	krb5_free_principal(context, tempprinc);
	return KRB5_PRINC_NOMATCH;
    }
    krb5_free_principal(context, tempprinc);


    if (retval = krb5_send_tgs(context, kdcoptions, &cred->times, NULL, 
			       sumtype,
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
	    !krb5_principal_compare(context, err_reply->server, request.server) ||
	    !krb5_principal_compare(context, err_reply->client, request.client))
	    retval = KRB5_KDCREP_MODIFIED;
	else
#endif
	    retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	krb5_free_error(context, err_reply);
	cleanup();
	return retval;
    }

    etype = tgt->keyblock.etype;
    retval = krb5_decode_kdc_rep(context, &tgsrep.response,
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
		  krb5_free_kdc_rep(context, dec_rep); }

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	cleanup();
	return retval;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(context, dec_rep->client, tgt->client)) {
	cleanup();
	return KRB5_KDCREP_MODIFIED;
    }
    /* put pieces into cred-> */
    if (cred->keyblock.contents) {
	memset(&cred->keyblock.contents, 0, cred->keyblock.length);
	krb5_xfree(cred->keyblock.contents);
    }
    cred->keyblock.magic = KV5M_KEYBLOCK;
    cred->keyblock.etype = dec_rep->ticket->enc_part.etype;
    if (retval = krb5_copy_keyblock_contents(context, dec_rep->enc_part2->session,
					     &cred->keyblock)) {
	cleanup();
	return retval;
    }
    memset((char *)dec_rep->enc_part2->session->contents, 0,
	  dec_rep->enc_part2->session->length);

#undef cleanup
#define cleanup() {\
	memset((char *)cred->keyblock.contents, 0, cred->keyblock.length);\
		  krb5_free_kdc_rep(context, dec_rep); }

    cred->times = dec_rep->enc_part2->times;

#if 0
    /* XXX probably need access to the request */
    /* check the contents for sanity: */
    if (!krb5_principal_compare(context, dec_rep->client, request.client)
	|| !krb5_principal_compare(context, dec_rep->enc_part2->server, request.server)
	|| !krb5_principal_compare(context, dec_rep->ticket->server, request.server)
	|| (request.nonce != dec_rep->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(context, addrs, dec_rep->enc_part2->caddrs)) */
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
	)
	retval = KRB5_KDCREP_MODIFIED;

    if ((request.from == 0) &&
	!in_clock_skew(dec_rep->enc_part2->times.starttime))
	retval = KRB5_KDCREP_SKEW;
    
    if (retval) {
	cleanup();
	return retval;
    }
    
#endif

    cred->ticket_flags = dec_rep->enc_part2->flags;
    cred->is_skey = FALSE;
    if (cred->addresses) {
	krb5_free_addresses(context, cred->addresses);
    }
    if (dec_rep->enc_part2->caddrs) {
	if (retval = krb5_copy_addresses(context, dec_rep->enc_part2->caddrs,
					 &cred->addresses)) {
	    cleanup();
	    return retval;
	}
    } else {
	/* no addresses in the list means we got what we had */
	if (retval = krb5_copy_addresses(context, tgt->addresses,
					 &cred->addresses)) {
	    cleanup();
	    return retval;
	}
    }
    /*
     * Free cred->server before overwriting it.
     */
    if (cred->server)
	krb5_free_principal(context, cred->server);
    if (retval = krb5_copy_principal(context, dec_rep->enc_part2->server,
				     &cred->server)) {
	cleanup();
	return retval;
    }

    if (retval = encode_krb5_ticket(dec_rep->ticket, &scratch)) {
	cleanup();
	krb5_free_addresses(context, cred->addresses);
	return retval;
    }

    cred->ticket = *scratch;
    krb5_xfree(scratch);

    krb5_free_kdc_rep(context, dec_rep);
    return retval;
}
