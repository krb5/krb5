/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>
/*
 Sends a request to the TGS and waits for a response.
 options is used for the options in the KRB_TGS_REQ.
 timestruct values are used for from, till, rtime " " "
 etype is used for etype " " "
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
OLDDECLARG(const krb5_data *,second_ticket)
OLDDECLARG(krb5_creds *,usecred)
OLDDECLARG(krb5_response *,rep)
{
    krb5_error_code retval;
    krb5_kdc_req tgsreq;
    krb5_checksum ap_checksum;
    krb5_data *scratch;
    krb5_ticket *sec_ticket = 0;
    krb5_ticket *sec_ticket_arr[2];

    bzero((char *)&tgsreq, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime;
    tgsreq.rtime = timestruct->renew_till;
    if (retval = krb5_timeofday(&tgsreq.ctime))
	return(retval);
    /* XXX we know they are the same size... */
    tgsreq.nonce = (krb5_int32) tgsreq.ctime;

    tgsreq.etype = etype;
    tgsreq.addresses = (krb5_address **) addrs;
    tgsreq.authorization_data = (krb5_authdata **)authorization_data;
    if (second_ticket) {
	if (retval = decode_krb5_ticket(second_ticket, &sec_ticket))
	    return retval;
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
	return(retval);
    }

    if (!(ap_checksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[sumtype]->checksum_length))) {
	if (sec_ticket)
	    krb5_free_ticket(sec_ticket);
	krb5_free_data(scratch);
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
	return retval;
    }
    /* done with body */
    krb5_free_data(scratch);

#define cleanup() {xfree(ap_checksum.contents);\
		   if (sec_ticket) krb5_free_ticket(sec_ticket);}
    /* attach ap_req to the tgsreq */

    tgsreq.padata_type = KRB5_PADATA_AP_REQ;

    /*
     * Get an ap_req.
     */
    if (retval = krb5_mk_req_extended (0L /* no ap options */,
				       &ap_checksum,
				       0, /* don't need times */
				       0L, /* don't need kdc_options for this */
				       0, /* no ccache--already have creds */
				       usecred,
				       0, /* don't need authenticator */
				       &tgsreq.padata)) {
	cleanup();
	return retval;
    }


    /* the TGS_REQ is assembled in tgsreq, so encode it */
    if (retval = encode_krb5_tgs_req(&tgsreq, &scratch)) {
	cleanup();
	return(retval);
    }
    if (sec_ticket)
	krb5_free_ticket(sec_ticket);
#undef cleanup
#define cleanup() {(void) free(tgsreq.padata.data); \
		   xfree(ap_checksum.contents);}

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
