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

static krb5_flags
creds_to_kdcoptions(creds)
krb5_creds *creds;
{
    krb5_flags result;

    /* XXX this is a hack; we don't necessarily want all these! */
    result = creds->ticket_flags & KDC_TKT_COMMON_MASK;
    result |= KDC_OPT_RENEWABLE_OK;
    return result;
}

krb5_error_code
krb5_get_cred_via_tgt (tgt, cred)
    krb5_creds *tgt;		/* IN */
    krb5_creds *cred;		/* IN OUT */
{
    krb5_tgs_req tgsreq;
    krb5_real_tgs_req realreq;
    krb5_error_code retval;
    krb5f_principal tempprinc;
    krb5_data *scratch, reply;
    krb5_checksum ap_checksum;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;

    /* tgt->client must be equal to cred->client */
    /* tgt->server must be equal to krbtgt/realmof(cred->client) */
    if (!krb5_principal_compare(tgt->client, cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    if (retval = krb5_tgtname(cred->server, cred->client, &tempprinc))
	return(retval);
    
    if (!krb5_principal_compare(tempprinc, tgt->server)) {
	krb5_free_principal(tempprinc);
	return KRB5_PRINC_NOMATCH;
    }
    krb5_free_principal(tempprinc);


    bzero((char *)&realreq, sizeof(realreq));

    realreq.kdc_options = creds_to_kdcoptions(cred);
    realreq.from = cred->times.starttime;
    realreq.till = cred->times.endtime;
    realreq.rtime = cred->times.renew_till;
    
    if (retval = krb5_timeofday(&realreq.ctime))
	return(retval);
    realreq.etype = xxx;
    realreq.server = cred->server;
    realreq.addresses = xxx;
    /* enc_part & enc_part2 are left blank for the moment. */

    if (retval = encode_krb5_real_tgs_req(&realreq, &scratch))
	return(retval);

    /* xxx choose a checksum type */
    if (retval = (*(krb5_cksumarray[xxx]->sum_func))(scratch->data,
						     0, /* XXX? */
						     (krb5_pointer) cred->keyblock.contents,
						     scratch->length,
						     cred->keyblock.length,
						     &ap_checksum)) {
	krb5_free_data(scratch);
	return retval;
    }
    tgsreq.tgs_request = *scratch;
    xfree(scratch);

#define cleanup() {(void) free(tgsreq.tgs_request.data);}

    /*
     * Now get an ap_req.
     */
    if (retval = krb5_mk_req_extended (0L /* no ap options */,
				       &ap_checksum,
				       0, /* don't need times */
				       0L, /* don't need kdc_options for this */
				       0, /* XXX no ccache */
				       tgt,
				       &tgsreq.header)) {
	cleanup();
	return retval;
    }

    /* now the TGS_REQ is assembled in tgsreq */
    if (retval = encode_krb5_tgs_req(&tgsreq, &scratch)) {
	cleanup();
	return(retval);
    }
#undef cleanup
#define cleanup() {(void) free(tgsreq.header.data); \
		   (void) free(tgsreq.tgs_request.data);}

    /* now send request & get response from KDC */
    retval = krb5_sendto_kdc(scratch, krb5_princ_realm(tgt->server),
			     &reply);
    krb5_free_data(scratch);
    cleanup();
    if (retval) {
	return retval;
    }
#undef cleanup
#define cleanup() {(void) free(reply.data);}

    /* we expect *reply to be either an error or a proper reply */
    if (retval = krb5_decode_kdc_rep(&reply,
				     &tgt->keyblock,
				     xxx, /* enctype */
				     &dec_rep)) {
	if (decode_krb5_error(&reply, &err_reply)) {
	    cleanup();
	    return retval;		/* neither proper reply nor error! */
	}

	/* XXX check to make sure the timestamps match, etc. */

	retval = err_reply->error + ERROR_TABLE_BASE_krb5;
	krb5_free_error(err_reply);
	cleanup();
	return retval;
    }
    cleanup();
#undef cleanup
#define cleanup() krb5_free_kdc_rep(dec_rep)

    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(dec_rep->client, tgt->client)) {
	cleanup();
	return XXX_MODIFIED;
    }
    /* put pieces into cred-> */
    if (retval = xxx_copy_keyblock(dec_rep->enc_part2->session,
				   &cred->keyblock)) {
	cleanup();
	return retval;
    }
    cred->times = dec_rep->enc_part2->times;
    /* check compatibility here first ? XXX */
    cred->ticket_flags = dec_rep->enc_part2->flags;
    cred->is_skey = FALSE;
    retval = xxx_copy_ticket(dec_rep->ticket, &cred->ticket);

    cleanup();
    return retval;
}
