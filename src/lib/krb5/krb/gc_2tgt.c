/*
 * $Source$
 * $Author$
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

#if !defined(lint) && !defined(SABER)
static char rcsid_gcv2tgt_c[] = "$Id$";
#endif

#include <krb5/krb5.h>
#include <krb5/asn1.h>		/* needed for some macros */

#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#include "int-proto.h"

krb5_error_code
#if defined(NARROW_PROTOTYPES)
krb5_get_cred_via_2tgt (krb5_creds * tgt,
			const krb5_flags kdcoptions,
			const krb5_enctype etype,
			const krb5_cksumtype sumtype,
			register krb5_creds *cred)
#else
krb5_get_cred_via_2tgt (tgt, kdcoptions, etype, sumtype, cred)
krb5_creds *tgt;
const krb5_flags kdcoptions;
const krb5_enctype etype;
const krb5_cksumtype sumtype;
register krb5_creds * cred;
#endif
{
    krb5_error_code retval;
#if 0
    krb5_principal tempprinc;
#endif
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

    if (!cred->second_ticket.length)
	return(KRB5_NO_2ND_TKT);

#if 0	/* What does this do? */
    if (retval = krb5_tgtname(krb5_princ_realm(cred->server),
			      krb5_princ_realm(cred->client), &tempprinc))
	return(retval);

    if (!krb5_principal_compare(tempprinc, tgt->server)) {
	krb5_free_principal(tempprinc);
	return KRB5_PRINC_NOMATCH;
    }
    krb5_free_principal(tempprinc);
#endif

    if (!(kdcoptions & KDC_OPT_ENC_TKT_IN_SKEY))
	return KRB5_INVALID_FLAGS;

    if (retval = krb5_send_tgs(kdcoptions, &cred->times, etype, sumtype,
			       cred->server,
			       tgt->addresses,
			       cred->authdata,
			       0,		/* no padata */
			       &cred->second_ticket,
			       tgt, &tgsrep))
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

	krb5_free_error(err_reply);
	free(tgsrep.response.data);
	return retval;
      }
    retval = krb5_decode_kdc_rep(&tgsrep.response, &tgt->keyblock,
				 etype, &dec_rep);
    free(tgsrep.response.data);
    if (retval)
	return retval;

#undef cleanup
#define cleanup() {\
	memset((char *)dec_rep->enc_part2->session->contents, 0,\
	      dec_rep->enc_part2->session->length);\
		  krb5_free_kdc_rep(dec_rep); }

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	cleanup();
	return KRB5KRB_AP_ERR_MSG_TYPE;
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

    /* Should verify that the ticket is what we asked for. */
    cred->times = dec_rep->enc_part2->times;
    cred->ticket_flags = dec_rep->enc_part2->flags;
    cred->is_skey = TRUE;
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
    return 0;
}

/*
 * Local variables:
 * mode:c
 * eval: (make-local-variable (quote c-indent-level))
 * eval: (make-local-variable (quote c-continued-statement-offset))
 * eval: (setq c-indent-level 4 c-continued-statement-offset 4)
 * End:
 */

