/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_rd_req()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/asn1.h>
#include <krb5/ext-proto.h>

/*
 Parses a KRB_AP_REQ message, returning its contents.

 server specifies the expected server's name for the ticket.

 sender_addr specifies the address(es) expected to be present in the
 ticket.

 rcache specifies a replay detection cache used to store authenticators and
 server names

 keyproc specifies a procedure to generate a decryption key for the
 ticket.  If keyproc is non-NULL, keyprocarg is passed to it, and the result
 used as a decryption key. If keyproc is NULL, then fetchfrom is checked;
 if it is non-NULL, it specifies a parameter name from which to retrieve the
 decryption key.  If fetchfrom is NULL, then the default key store is
 consulted.

 authdat->ticket and authdat->authenticator are set to allocated storage
 structures; the caller should free them when finished.

 returns system errors, encryption errors, replay errors
 */

krb5_error_code
krb5_rd_req(inbuf, server, sender_addr, fetchfrom, keyproc, keyprocarg,
	    rcache, authdat)
const krb5_data *inbuf;
krb5_const_principal server;
const krb5_address *sender_addr;
krb5_const_pointer fetchfrom;
krb5_error_code (*keyproc) PROTOTYPE((krb5_pointer, 
				      krb5_principal,
				      krb5_kvno,
				      krb5_keyblock **));
krb5_pointer keyprocarg;
krb5_rcache rcache;
krb5_tkt_authent *authdat;
{
    krb5_error_code retval;
    krb5_ap_req *request;

    if (!krb5_is_ap_req(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    if (retval = decode_krb5_ap_req(inbuf, &request)) {
    	switch (retval) {
	case ISODE_50_LOCAL_ERR_BADMSGTYPE:
	    return KRB5KRB_AP_ERR_BADVERSION; 
	default:
	    return(retval);
	}

    }

    retval = krb5_rd_req_decoded(request, server, sender_addr, fetchfrom,
				 keyproc, keyprocarg, rcache, authdat);
    krb5_free_ap_req(request);
    return retval;
}

