/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_mk_req_extended()
 */

#if !defined(lint) && !defined(SABER)
static char mk_req_ext_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/asn1.h>

#include <krb5/libos.h>
#include <stdio.h>
#include <krb5/libos-proto.h>

/*
 Formats a KRB_AP_REQ message into outbuf, with more complete options than
 krb_mk_req.

 outbuf, ap_req_options, checksum, and ccache are used in the
 same fashion as for krb5_mk_req.

 creds is used to supply the credentials (ticket and session key) needed
 to form the request.

 if creds->ticket has no data (length == 0), then a ticket is obtained
 from either the cache or the TGS, passing creds to krb5_get_credentials().
 kdc_options specifies the options requested for the ticket to be used.
 If a ticket with appropriate flags is not found in the cache, then these
 options are passed on in a request to an appropriate KDC.

 ap_req_options specifies the KRB_AP_REQ options desired.

 if ap_req_options specifies AP_OPTS_USE_SESSION_KEY, then creds->ticket
 must contain the appropriate ENC-TKT-IN-SKEY ticket.

 checksum specifies the checksum to be used in the authenticator.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/
static krb5_error_code generate_authenticator PROTOTYPE((krb5_authenticator *,
							 krb5_creds *,
							 krb5_checksum *));

krb5_error_code
krb5_mk_req_extended(ap_req_options, checksum, times, kdc_options, ccache,
		     creds, outbuf)
krb5_flags ap_req_options;
krb5_checksum *checksum;
krb5_ticket_times *times;
krb5_flags kdc_options;
krb5_ccache ccache;
krb5_creds *creds;
krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_ap_req request;
    krb5_authenticator authent;
    krb5_data *scratch;

    if ((ap_req_options & AP_OPTS_USE_SESSION_KEY) &&
	!creds->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    if (!creds->ticket.length) {
	/* go get creds */
	creds->times = *times;		/* XXX do we need times? */
	if (retval = krb5_get_credentials(kdc_options,
					  ccache,
					  creds))
	    return(retval);
    }
    request.ap_options = ap_req_options;
    /* we need a native ticket */
    if (retval = krb5_decode_ticket(&creds->ticket, &request.ticket))
	return(retval);			/* XXX who cleans up creds? */

    if (retval = generate_authenticator(&authent, creds, checksum))
	return retval;
    if (retval = encode_krb5_authenticator(&authent, &scratch))
	return(retval);
    request.authenticator = *scratch;
    free((char *)scratch);

    /* now request is the output */

    if (retval = encode_krb5_ap_req(&request, &outbuf))
	free(request.authenticator.data);
    return retval;
}

static krb5_error_code
generate_authenticator(authent, creds, cksum)
krb5_authenticator *authent;
krb5_creds *creds;
krb5_checksum *cksum;
{
    authent->client = creds->client;
    authent->checksum = cksum;
    return(krb5_ms_timeofday(&authent->ctime, &authent->cmsec));
}
