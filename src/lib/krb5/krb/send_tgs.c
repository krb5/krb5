/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
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
	      DECLARG(const krb5_principal, sname),
	      DECLARG(krb5_address * const *, addrs),
	      DECLARG(krb5_authdata * const *,authorization_data),
	      DECLARG(const krb5_data *,second_ticket),
	      DECLARG(krb5_creds *,usecred),
	      DECLARG(krb5_response *,rep))
OLDDECLARG(const krb5_flags, kdcoptions)
OLDDECLARG(const krb5_ticket_times *,timestruct)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_cksumtype, sumtype)
OLDDECLARG(const krb5_principal, sname)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(krb5_authdata * const *,authorization_data)
OLDDECLARG(const krb5_data *,second_ticket)
OLDDECLARG(krb5_creds *,usecred)
OLDDECLARG(krb5_response *,rep)
{
    krb5_error_code retval;
    krb5_tgs_req tgsreq;
    krb5_real_tgs_req realreq;
    krb5_tgs_req_enc_part encpart;
    krb5_checksum ap_checksum;
    krb5_data *scratch;
    krb5_ticket *sec_ticket = 0;

    bzero((char *)&realreq, sizeof(realreq));

    realreq.kdc_options = kdcoptions;
    realreq.from = timestruct->starttime;
    realreq.till = timestruct->endtime;
    realreq.rtime = timestruct->renew_till;
    
    if (retval = krb5_timeofday(&realreq.ctime))
	return(retval);
    realreq.etype = etype;
    realreq.server = sname;
    realreq.addresses = (krb5_address **) addrs;

    encpart.authorization_data = (krb5_authdata **)authorization_data;
    if (second_ticket) {
	if (retval = krb5_decode_ticket(second_ticket, &sec_ticket))
	    return retval;
	encpart.second_ticket = sec_ticket;
    } else
	encpart.second_ticket = 0;

    realreq.enc_part2 = &encpart;

    retval = encode_krb5_real_tgs_req(&realreq, &scratch);
    if (sec_ticket)
	krb5_free_ticket(sec_ticket);
    if (retval)
	return(retval);

    /* XXX choose a checksum type */
    if (!(ap_checksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[sumtype]->checksum_length))) {
	krb5_free_data(scratch);
	return ENOMEM;
    }

    if (retval = (*(krb5_cksumarray[sumtype]->
		    sum_func))(scratch->data,
			       scratch->length,
			       (krb5_pointer) usecred->keyblock.contents,
			       usecred->keyblock.length,
			       &ap_checksum)) {
	xfree(ap_checksum.contents);
	krb5_free_data(scratch);
	return retval;
    }
    tgsreq.tgs_request = *scratch;
    xfree(scratch);

#define cleanup() {(void) free((char *)tgsreq.tgs_request.data); \
		   xfree(ap_checksum.contents);}
    /*
     * Now get an ap_req.
     */
    if (retval = krb5_mk_req_extended (0L /* no ap options */,
				       &ap_checksum,
				       0, /* don't need times */
				       0L, /* don't need kdc_options for this */
				       0, /* XXX no ccache */
				       usecred,
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
		   (void) free(tgsreq.tgs_request.data);\
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
    /* here we use some knowledge of ASN.1 encodings */
    /* first byte is the identifier octet.  KRB_KDC_REP is APPLICATION 1,
       KRB_ERROR is application 2 */
    /* allow either constructed or primitive encoding, so check for bit 6
       set or reset */

    if (krb5_is_kdc_rep(&rep->response))
	/* it's a KDC_REP--assume TGS_REP */
	rep->message_type = KRB5_TGS_REP;
    else /* assume it's an error */
	rep->message_type = KRB5_ERROR;
    return 0;
}
