/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_mk_req() routine.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

/*
 Formats a KRB_AP_REQ message into outbuf.

 server specifies the principal of the server to receive the message; if
 credentials are not present in the credentials cache for this server, the
 TGS request with default parameters is used in an attempt to obtain
 such credentials, and they are stored in ccache.

 kdc_options specifies the options requested for the 
 ap_req_options specifies the KRB_AP_REQ options desired.

 checksum specifies the checksum to be used in the authenticator.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/

extern krb5_flags krb5_kdc_default_options;

krb5_error_code
krb5_mk_req(server, ap_req_options, checksum, ccache, outbuf)
krb5_const_principal server;
const krb5_flags ap_req_options;
const krb5_checksum *checksum;
krb5_ccache ccache;
krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_creds creds;

    /* obtain ticket & session key */

    memset((char *)&creds, 0, sizeof(creds));
    creds.server = (krb5_principal) server;
    if (retval = krb5_cc_get_principal(ccache, &creds.client))
	return(retval);
    /* creds.times.endtime = 0; -- memset 0 takes care of this
     				   zero means "as long as possible" */
    /* creds.keyblock.keytype = 0; -- as well as this.
       				      zero means no session keytype
				      preference */

    if (retval = krb5_get_credentials(krb5_kdc_default_options,
				      ccache,
				      &creds))
	return(retval);

    retval = krb5_mk_req_extended(ap_req_options,
				  checksum,
				  &creds.times,
				  krb5_kdc_default_options,
				  0,	/* no sequence number */
				  0,	/* no sub-key */
				  ccache,
				  &creds,
				  0, 	/* We don't need the authenticator */
				  outbuf);
    creds.server = 0;			/* don't free it, someone else
					   owns it. */
    krb5_free_cred_contents(&creds);
    return retval;
}
