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

#include "k5-int.h"
#include "int-proto.h"

krb5_error_code INTERFACE
krb5_get_cred_via_tgt (context, tgt, kdcoptions, sumtype, in_cred, out_cred)
    krb5_context context;
    krb5_creds * tgt;
    const krb5_flags kdcoptions;
    const krb5_cksumtype sumtype;
    krb5_creds * in_cred;
    krb5_creds ** out_cred;
{
    krb5_error_code retval;
    krb5_principal tempprinc;
    krb5_data *scratch;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;

    /* tgt->client must be equal to in_cred->client */
    if (!krb5_principal_compare(context, tgt->client, in_cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    /* check if we have the right TGT                    */
    /* tgt->server must be equal to                      */
    /* krbtgt/realmof(cred->server)@realmof(tgt->server) */

    if (retval = krb5_tgtname(context, 
		     krb5_princ_realm(context, in_cred->server),
		     krb5_princ_realm(context, tgt->server), &tempprinc))
	return(retval);

    if (!krb5_principal_compare(context, tempprinc, tgt->server)) {
	retval = KRB5_PRINC_NOMATCH;
	goto error_5;
    }

    if (retval = krb5_send_tgs(context, kdcoptions, &in_cred->times, NULL, 
			       sumtype, in_cred->server, tgt->addresses,
			       in_cred->authdata,
			       0,		/* no padata */
			       0,		/* no second ticket */
			       tgt, &tgsrep))
	goto error_5;

    switch (tgsrep.message_type) {
    case KRB5_TGS_REP:
	break;
    case KRB5_ERROR:
    default:
	if (krb5_is_krb_error(&tgsrep.response))
	    retval = decode_krb5_error(&tgsrep.response, &err_reply);
	else
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;

	if (retval) 			/* neither proper reply nor error! */
	    goto error_4;

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
	goto error_4;
    }

    if (retval = krb5_decode_kdc_rep(context, &tgsrep.response, &tgt->keyblock,
				     tgt->keyblock.etype, &dec_rep))
	goto error_4;

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto error_3;
    }
    
    /* now it's decrypted and ready for prime time */
    if (!krb5_principal_compare(context, dec_rep->client, tgt->client)) {
	retval = KRB5_KDCREP_MODIFIED;
	goto error_3;
    }

    /* get a cred structure */
    /* The caller is responsible for cleaning up */
    if (((*out_cred) = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
	retval = ENOMEM;
	goto error_2;
    }
    memset((*out_cred), 0, sizeof(krb5_creds));

    /* Copy the client straigt from in_cred */
    if (retval = krb5_copy_principal(context, in_cred->client, 
				     &(*out_cred)->client)) {
    	goto error_2;
    }

    /* put pieces into out_cred-> */
    if (retval = krb5_copy_keyblock_contents(context, 
					     dec_rep->enc_part2->session,
					     &(*out_cred)->keyblock)) {
	goto error_2;
    }

    (*out_cred)->keyblock.etype = dec_rep->ticket->enc_part.etype;
    (*out_cred)->times = dec_rep->enc_part2->times;

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

    if (!request.from && !in_clock_skew(dec_rep->enc_part2->times.starttime)) {
	retval = KRB5_KDCREP_SKEW;
	goto error_1;
    }
    
#endif

    (*out_cred)->ticket_flags = dec_rep->enc_part2->flags;
    (*out_cred)->is_skey = FALSE;
    if (dec_rep->enc_part2->caddrs) {
	if (retval = krb5_copy_addresses(context, dec_rep->enc_part2->caddrs,
					 &(*out_cred)->addresses)) {
	    goto error_1;
	}
    } else {
	/* no addresses in the list means we got what we had */
	if (retval = krb5_copy_addresses(context, tgt->addresses,
					 &(*out_cred)->addresses)) {
	    goto error_1;
	}
    }
    if (retval = krb5_copy_principal(context, dec_rep->enc_part2->server,
				     &(*out_cred)->server)) {
	goto error_1;
    }

    if (retval = encode_krb5_ticket(dec_rep->ticket, &scratch)) {
	krb5_free_addresses(context, (*out_cred)->addresses);
	goto error_1;
    }

    (*out_cred)->ticket = *scratch;
    krb5_xfree(scratch);

error_1:;
    if (retval)
	memset((*out_cred)->keyblock.contents, 0, (*out_cred)->keyblock.length);

error_2:;
    if (retval)
	krb5_free_creds(context, *out_cred);

error_3:;
    memset(dec_rep->enc_part2->session->contents, 0,
	   dec_rep->enc_part2->session->length);
    krb5_free_kdc_rep(context, dec_rep);

error_4:;
    free(tgsrep.response.data);

error_5:;
    krb5_free_principal(context, tempprinc);
    return retval;
}
