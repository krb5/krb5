/*
 * lib/krb5/krb/gc_2tgt.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Given two tgts, get a ticket.
 */

#include "k5-int.h"
#include "int-proto.h"

krb5_error_code
krb5_get_cred_via_2tgt (context, tgt, kdcoptions, sumtype, in_cred, out_cred)
    krb5_context context;
    krb5_creds *tgt;
    const krb5_flags kdcoptions;
    const krb5_cksumtype sumtype;
    krb5_creds * in_cred;
    krb5_creds ** out_cred;
{
    krb5_error_code retval;
#if 0
    krb5_principal tempprinc;
#endif
    krb5_data *scratch;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;
    krb5_enctype etype;

    /* tgt->client must be equal to in_cred->client */
    /* tgt->server must be equal to krbtgt/realmof(cred->client) */
    if (!krb5_principal_compare(context, tgt->client, in_cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    if (!in_cred->second_ticket.length)
	return(KRB5_NO_2ND_TKT);

#if 0	/* What does this do? */
    if (retval = krb5_tgtname(context, krb5_princ_realm(in_cred->server),
			      krb5_princ_realm(context, in_cred->client), &tempprinc))
	return(retval);

    if (!krb5_principal_compare(context, tempprinc, tgt->server)) {
	krb5_free_principal(context, tempprinc);
	return KRB5_PRINC_NOMATCH;
    }
    krb5_free_principal(context, tempprinc);
#endif

    if (!(kdcoptions & KDC_OPT_ENC_TKT_IN_SKEY))
	return KRB5_INVALID_FLAGS;

    if (retval = krb5_send_tgs(context, kdcoptions, &in_cred->times, NULL, 
			       sumtype, in_cred->server, tgt->addresses,
			       in_cred->authdata,
			       0,		/* no padata */
			       &in_cred->second_ticket, tgt, &tgsrep))
	return retval;

    if (tgsrep.message_type != KRB5_TGS_REP)
      {
	if (!krb5_is_krb_error(&tgsrep.response)) {
	    free(tgsrep.response.data);
	    return KRB5KRB_AP_ERR_MSG_TYPE;
	}
	retval = decode_krb5_error(&tgsrep.response, &err_reply);
	if (retval) {
	    free(tgsrep.response.data);
	    return retval;
	}
	retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	krb5_free_error(context, err_reply);
	free(tgsrep.response.data);
	return retval;
      }
    etype = tgt->keyblock.etype;
    retval = krb5_decode_kdc_rep(context, &tgsrep.response, &tgt->keyblock,
				 etype, &dec_rep);
    free(tgsrep.response.data);
    if (retval)
	return retval;

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto errout;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(context, dec_rep->client, tgt->client)) {
	retval = KRB5_KDCREP_MODIFIED;
	goto errout;
    }

    /*
     * get a cred structure 
     * The caller is responsible for cleaning up 
     */
    if (((*out_cred) = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
	retval = ENOMEM;
	goto errout;
    }

    /* Copy the client straig from in_cred */
    if (retval = krb5_copy_principal(context, in_cred->client, 
				     &(*out_cred)->client)) {
    	goto errout;
    }

    /* put pieces into out_cred-> */
    (*out_cred)->keyblock.magic = KV5M_KEYBLOCK;
    (*out_cred)->keyblock.etype = dec_rep->ticket->enc_part.etype;
    if (retval = krb5_copy_keyblock_contents(context, 
					     dec_rep->enc_part2->session,
					     &(*out_cred)->keyblock))
	goto errout;

    /* Should verify that the ticket is what we asked for. */
#ifdef HAVE_C_STRUCTURE_ASSIGNMENT
    (*out_cred)->times = dec_rep->enc_part2->times;
#else
    memcpy(&(*out_cred)->times, &dec_rep->enc_part2->times, 
	   sizeof(krb5_ticket_times));
#endif

    (*out_cred)->ticket_flags = dec_rep->enc_part2->flags;
    (*out_cred)->is_skey = TRUE;
    if (dec_rep->enc_part2->caddrs)
	retval = krb5_copy_addresses(context, dec_rep->enc_part2->caddrs,
				     &(*out_cred)->addresses);
    else
	/* no addresses in the list means we got what we had */
	retval = krb5_copy_addresses(context, tgt->addresses, &(*out_cred)->addresses);
    if (retval)
	    goto errout;
    
    if (retval = krb5_copy_principal(context, dec_rep->enc_part2->server,
				     &(*out_cred)->server))
	goto errout;

    if (retval = encode_krb5_ticket(dec_rep->ticket, &scratch))
	goto errout;

    (*out_cred)->ticket = *scratch;
    krb5_xfree(scratch);

errout:
    if (retval) {
	if (*out_cred) {
	    if ((*out_cred)->keyblock.contents) {
	        memset((*out_cred)->keyblock.contents, 0, 
		   (*out_cred)->keyblock.length);
	        krb5_xfree((*out_cred)->keyblock.contents);
	        (*out_cred)->keyblock.contents = 0;
	    }
	    if ((*out_cred)->addresses) {
	        krb5_free_addresses(context, (*out_cred)->addresses);
	        (*out_cred)->addresses = 0;
	    }
	    if ((*out_cred)->server) {
	        krb5_free_principal(context, (*out_cred)->server);
	        (*out_cred)->server = 0;
	    }
	    krb5_free_creds(context, *out_cred);
	}
    }
    memset((char *)dec_rep->enc_part2->session->contents, 0,
	   dec_rep->enc_part2->session->length);
    krb5_free_kdc_rep(context, dec_rep);
    return retval;
}

/*
 * Local variables:
 * mode:c
 * eval: (make-local-variable (quote c-indent-level))
 * eval: (make-local-variable (quote c-continued-statement-offset))
 * eval: (setq c-indent-level 4 c-continued-statement-offset 4)
 * End:
 */

