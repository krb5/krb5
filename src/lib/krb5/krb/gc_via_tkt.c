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
 * Given a tkt, and a target cred, get it.
 * Assumes that the kdc_rep has been decrypted.
 */

#include "k5-int.h"
#include "int-proto.h"

static krb5_error_code
krb5_kdcrep2creds(context, pkdcrep, address, ppcreds)
    krb5_context          context;
    krb5_kdc_rep        * pkdcrep;
    krb5_address *const * address;
    krb5_creds         ** ppcreds;
{
    krb5_error_code retval;  
    krb5_data *pdata;
  
    if ((*ppcreds = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
        return ENOMEM;
    }

    memset(*ppcreds, 0, sizeof(krb5_creds));

    if (retval = krb5_copy_principal(context, pkdcrep->client,
                                     &(*ppcreds)->client))
        goto cleanup;

    if (retval = krb5_copy_principal(context, pkdcrep->enc_part2->server,
                                     &(*ppcreds)->server))
        goto cleanup;

    if (retval = krb5_copy_keyblock_contents(context, 
					     pkdcrep->enc_part2->session,
                                             &(*ppcreds)->keyblock))
        goto cleanup;

    (*ppcreds)->keyblock.etype = pkdcrep->ticket->enc_part.etype;

    (*ppcreds)->magic = KV5M_CREDS;
    (*ppcreds)->is_skey = 0;    /* unused */
    (*ppcreds)->times = pkdcrep->enc_part2->times;
    (*ppcreds)->ticket_flags = pkdcrep->enc_part2->flags;

    (*ppcreds)->authdata = NULL;   /* not used */
    memset(&(*ppcreds)->second_ticket, 0, sizeof((*ppcreds)->second_ticket));

    if (pkdcrep->enc_part2->caddrs) {
	if (retval = krb5_copy_addresses(context, pkdcrep->enc_part2->caddrs,
					 &(*ppcreds)->addresses)) 
	    goto cleanup_keyblock;
    } else {
	/* no addresses in the list means we got what we had */
	if (retval = krb5_copy_addresses(context, address,
					 &(*ppcreds)->addresses)) 
	    goto cleanup_keyblock;
    }

    if (retval = encode_krb5_ticket(pkdcrep->ticket, &pdata))
	goto cleanup_keyblock;

    (*ppcreds)->ticket = *pdata;
    return 0;

cleanup_keyblock:
    memset((*ppcreds)->keyblock.contents, 0, (*ppcreds)->keyblock.length);

cleanup:
    free (*ppcreds);
    return retval;
}
 
/* XXX This is to move to krb5_send_tgs, RSN -- CAP 950411 */
extern  krb5_cksumtype krb5_kdc_req_sumtype;

krb5_error_code INTERFACE
krb5_get_cred_via_tkt (context, tkt, kdcoptions, address, in_cred, out_cred)
    krb5_context 	  context;
    krb5_creds 		* tkt;
    const krb5_flags 	  kdcoptions;
    krb5_address *const * address;
    krb5_creds 		* in_cred;
    krb5_creds 	       ** out_cred;
{
    krb5_error_code retval;
    krb5_principal tempprinc;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;

    /* tkt->client must be equal to in_cred->client */
    if (!krb5_principal_compare(context, tkt->client, in_cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tkt->ticket.length)
	return KRB5_NO_TKT_SUPPLIED;

    /* check if we have the right TGT                    */
    /* tkt->server must be equal to                      */
    /* krbtgt/realmof(cred->server)@realmof(tgt->server) */

/*
    if (retval = krb5_tgtname(context, 
		     krb5_princ_realm(context, in_cred->server),
		     krb5_princ_realm(context, tkt->server), &tempprinc))
	return(retval);

    if (!krb5_principal_compare(context, tempprinc, tkt->server)) {
	retval = KRB5_PRINC_NOMATCH;
	goto error_5;
    }
*/

    if (retval = krb5_send_tgs(context, kdcoptions, &in_cred->times, NULL, 
			       krb5_kdc_req_sumtype, /* To be removed */
			       in_cred->server, address, in_cred->authdata,
			       0,		/* no padata */
			       0,		/* no second ticket */
			       tkt, &tgsrep))
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

    if (retval = krb5_decode_kdc_rep(context, &tgsrep.response, &tkt->keyblock,
				     tkt->keyblock.etype, &dec_rep))
	goto error_4;

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto error_3;
    }
    
    /* now it's decrypted and ready for prime time */
    if (!krb5_principal_compare(context, dec_rep->client, tkt->client)) {
	retval = KRB5_KDCREP_MODIFIED;
	goto error_3;
    }

    retval = krb5_kdcrep2creds(context, dec_rep, address, out_cred);


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

error_1:;
    if (retval)

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
