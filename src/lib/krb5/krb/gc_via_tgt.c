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
		       DECLARG(krb5_flags, kdcoptions),
		       DECLARG(krb5_enctype, etype),
		       DECLARG(krb5_cksumtype, sumtype),
		       DECLARG(krb5_address **, addrs),
		       DECLARG(krb5_creds *, cred))
OLDDECLARG(krb5_creds *, tgt)
OLDDECLARG(krb5_flags, kdcoptions)
OLDDECLARG(krb5_enctype, etype)
OLDDECLARG(krb5_cksumtype, sumtype)
OLDDECLARG(krb5_address **, addrs)
OLDDECLARG(krb5_creds *, cred)
{
    krb5_tgs_req tgsreq;
    krb5_real_tgs_req realreq;
    krb5_error_code retval;
    krb5_principal tempprinc;
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

    realreq.kdc_options = kdcoptions;
    realreq.from = cred->times.starttime;
    realreq.till = cred->times.endtime;
    realreq.rtime = cred->times.renew_till;
    
    if (retval = krb5_timeofday(&realreq.ctime))
	return(retval);
    realreq.etype = etype;
    realreq.server = cred->server;
    realreq.addresses = addrs;
    /* enc_part & enc_part2 are left blank for the moment. */

    if (retval = encode_krb5_real_tgs_req(&realreq, &scratch))
	return(retval);

    /* xxx choose a checksum type */
    if (retval = (*(krb5_cksumarray[sumtype]->
		    sum_func))(scratch->data,
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

#define cleanup() {(void) free((char *)tgsreq.tgs_request.data); \
		   (void) free((char *)ap_checksum.contents);}

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
				     realreq.etype, /* enctype */
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

    retval = krb5_encode_ticket(dec_rep->ticket, &scratch);
    if (!retval) {
	cred->ticket = *scratch;
	free((char *)scratch);
    }
    cleanup();
    return retval;
}
