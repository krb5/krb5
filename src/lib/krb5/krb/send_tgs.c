/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_send_tgs()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_send_tgs_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>
/*
 Sends a request to the TGS and waits for a response.
 options is used for the options in the KRB_TGS_REQ.
 timestruct values are used for from, till, rtime " " "
 etype is used for etype " " ", and to encrypt the authorization data, if present
 sumtype is used for the checksum in the AP_REQ in the KRB_TGS_REQ
 sname is used for sname " " "
 addrs, if non-NULL, is used for addresses " " "
 authorization_dat, if non-NULL, is used for authorization_dat " " "
 second_ticket, if required by options, is used for the 2nd ticket in the req.
 usecred is used for the ticket & session key in the KRB_AP_REQ header " " "
 (the KDC realm is extracted from usecred->server's realm)
 
 The response is placed into *rep.
 rep->response.data is set to point at allocated storage which should be
 freed by the caller when finished.

 returns system errors
 */
krb5_error_code
krb5_send_tgs(DECLARG(const krb5_flags, kdcoptions),
	      DECLARG(const krb5_ticket_times *,timestruct),
	      DECLARG(const krb5_enctype, etype),
	      DECLARG(const krb5_cksumtype, sumtype),
	      DECLARG(krb5_const_principal, sname),
	      DECLARG(krb5_address * const *, addrs),
	      DECLARG(krb5_authdata * const *,authorization_data),
	      DECLARG(krb5_pa_data * const *, padata),
	      DECLARG(const krb5_data *,second_ticket),
	      DECLARG(krb5_creds *,usecred),
	      DECLARG(krb5_response *,rep))
OLDDECLARG(const krb5_flags, kdcoptions)
OLDDECLARG(const krb5_ticket_times *,timestruct)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_cksumtype, sumtype)
OLDDECLARG(krb5_const_principal, sname)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(krb5_authdata * const *,authorization_data)
OLDDECLARG(krb5_pa_data * const *, padata)
OLDDECLARG(const krb5_data *,second_ticket)
OLDDECLARG(krb5_creds *,usecred)
OLDDECLARG(krb5_response *,rep)
{
    krb5_error_code retval;
    krb5_kdc_req tgsreq;
    krb5_checksum ap_checksum;
    krb5_data *scratch, scratch2;
    krb5_ticket *sec_ticket = 0;
    krb5_ticket *sec_ticket_arr[2];
    krb5_enctype etypes[1];
    krb5_timestamp time_now;
    krb5_pa_data **combined_padata;
    krb5_pa_data ap_req_padata;

    if (!valid_etype(etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    memset((char *)&tgsreq, 0, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime;
    tgsreq.rtime = timestruct->renew_till;
    if (retval = krb5_timeofday(&time_now))
	return(retval);
    /* XXX we know they are the same size... */
    tgsreq.nonce = (krb5_int32) time_now;

    etypes[0] = etype;
    tgsreq.etype = etypes;
    tgsreq.netypes = 1;

    tgsreq.addresses = (krb5_address **) addrs;

    if (authorization_data) {
	/* need to encrypt it in the request */

	krb5_encrypt_block eblock;

	if (retval = encode_krb5_authdata(authorization_data, &scratch))
	    return(retval);
	krb5_use_cstype(&eblock, etype);
	tgsreq.authorization_data.ciphertext.length =
	    krb5_encrypt_size(scratch->length,
			      eblock.crypto_entry);
	/* add padding area, and zero it */
	if (!(scratch->data = realloc(scratch->data,
				      tgsreq.authorization_data.ciphertext.length))) {
	    /* may destroy scratch->data */
	    xfree(scratch);
	    return ENOMEM;
	}
	memset(scratch->data + scratch->length, 0,
	       tgsreq.authorization_data.ciphertext.length - scratch->length);
	if (!(tgsreq.authorization_data.ciphertext.data =
	      malloc(tgsreq.authorization_data.ciphertext.length))) {
	    krb5_free_data(scratch);
	    return ENOMEM;
	}
	if (retval = krb5_process_key(&eblock, &usecred->keyblock)) {
	    krb5_free_data(scratch);
	    return retval;
	}
	/* call the encryption routine */
	if (retval = krb5_encrypt((krb5_pointer) scratch->data,
				  (krb5_pointer) tgsreq.authorization_data.ciphertext.data,
				  scratch->length, &eblock, 0)) {
	    (void) krb5_finish_key(&eblock);
	    xfree(tgsreq.authorization_data.ciphertext.data);
	    krb5_free_data(scratch);
	    return retval;
	}	    
	krb5_free_data(scratch);
	if (retval = krb5_finish_key(&eblock)) {
	    xfree(tgsreq.authorization_data.ciphertext.data);
	    return retval;
	}
    }
#define cleanup_authdata() { if (tgsreq.authorization_data.ciphertext.data) {\
	(void) memset(tgsreq.authorization_data.ciphertext.data, 0,\
             tgsreq.authorization_data.ciphertext.length); \
	    xfree(tgsreq.authorization_data.ciphertext.data);}}



    if (second_ticket) {
	if (retval = decode_krb5_ticket(second_ticket, &sec_ticket)) {
	    cleanup_authdata();
	    return retval;
	}
	sec_ticket_arr[0] = sec_ticket;
	sec_ticket_arr[1] = 0;
	tgsreq.second_ticket = sec_ticket_arr;
    } else
	tgsreq.second_ticket = 0;


    /* encode the body; then checksum it */

    retval = encode_krb5_kdc_req_body(&tgsreq, &scratch);
    if (retval) {
	if (sec_ticket)
	    krb5_free_ticket(sec_ticket);
	cleanup_authdata();
	return(retval);
    }

    if (!(ap_checksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[sumtype]->checksum_length))) {
	if (sec_ticket)
	    krb5_free_ticket(sec_ticket);
	krb5_free_data(scratch);
	cleanup_authdata();
	return ENOMEM;
    }

    if (retval = (*(krb5_cksumarray[sumtype]->
		    sum_func))(scratch->data,
			       scratch->length,
			       (krb5_pointer) usecred->keyblock.contents,
			       usecred->keyblock.length,
			       &ap_checksum)) {
	if (sec_ticket)
	    krb5_free_ticket(sec_ticket);
	xfree(ap_checksum.contents);
	krb5_free_data(scratch);
	cleanup_authdata();
	return retval;
    }
    /* done with body */
    krb5_free_data(scratch);

#define cleanup() {xfree(ap_checksum.contents);\
		   if (sec_ticket) krb5_free_ticket(sec_ticket);}
    /* attach ap_req to the tgsreq */

    /*
     * Get an ap_req.
     */
    if (retval = krb5_mk_req_extended (0L /* no ap options */,
				       &ap_checksum,
				       0, /* don't need times */
				       0L, /* don't need kdc_options for this */
				       0, /* no initial sequence */
				       0, /* no new key */
				       0, /* no ccache--already have creds */
				       usecred,
				       0, /* don't need authenticator */
				       &scratch2)) {
	cleanup();
	cleanup_authdata();
	return retval;
    }

    ap_req_padata.pa_type = KRB5_PADATA_AP_REQ;
    ap_req_padata.length = scratch2.length;
    ap_req_padata.contents = (krb5_octet *)scratch2.data;

    /* combine in any other supplied padata */
    if (padata) {
	krb5_pa_data * const * counter;
	register int i = 0;
	for (counter = padata; *counter; counter++, i++);
	combined_padata = (krb5_pa_data **)malloc(i+2);
	if (!combined_padata) {
	    cleanup();
	    cleanup_authdata();
	    xfree(ap_req_padata.contents);
	    return ENOMEM;
	}
	combined_padata[0] = &ap_req_padata;
	for (i = 1, counter = padata; *counter; counter++, i++)
	    combined_padata[i] = (krb5_pa_data *) *counter;
	combined_padata[i] = 0;
    } else {
	combined_padata = (krb5_pa_data **)malloc(2*sizeof(*combined_padata));
	if (!combined_padata) {
	    cleanup();
	    cleanup_authdata();
	    xfree(ap_req_padata.contents);
	    return ENOMEM;
	}
	combined_padata[0] = &ap_req_padata;
	combined_padata[1] = 0;
    }
    tgsreq.padata = combined_padata;

    /* the TGS_REQ is assembled in tgsreq, so encode it */
    if (retval = encode_krb5_tgs_req(&tgsreq, &scratch)) {
	cleanup();
	cleanup_authdata();
	xfree(combined_padata);
	xfree(ap_req_padata.contents);
	return(retval);
    }
    if (sec_ticket)
	krb5_free_ticket(sec_ticket);
    cleanup_authdata();
    xfree(combined_padata);
    xfree(ap_req_padata.contents);
#undef cleanup_authdata
#undef cleanup
#define cleanup() {xfree(ap_checksum.contents);}

    /* now send request & get response from KDC */
    retval = krb5_sendto_kdc(scratch, krb5_princ_realm(sname),
			     &rep->response);
    krb5_free_data(scratch);
    cleanup();
    if (retval) {
	return retval;
    }
#undef cleanup

    if (krb5_is_tgs_rep(&rep->response))
	rep->message_type = KRB5_TGS_REP;
    else /* assume it's an error */
	rep->message_type = KRB5_ERROR;
    return 0;
}
