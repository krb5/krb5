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
 * convenience sendauth/recvauth functions
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sendauth_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/osconf.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#define WORKING_RCACHE

extern krb5_flags	krb5_kdc_default_options;

static char *sendauth_version = "KRB5_SENDAUTH_V1.0";

krb5_error_code
krb5_sendauth(/* IN */
	      fd, appl_version, client, server, ap_req_options,
	      checksump,
	      /* IN/OUT */
	      credsp, ccache,
	      /* OUT */
	      sequence, newkey,
	      error, rep_result)
	krb5_pointer	fd;
	char	*appl_version;
	krb5_principal	client;
	krb5_principal	server;
	krb5_flags	ap_req_options;
	krb5_int32	*sequence;
	krb5_keyblock	**newkey;
	krb5_checksum	*checksump;
	krb5_creds	*credsp;
	krb5_ccache	ccache;
	krb5_error	**error;
	krb5_ap_rep_enc_part	**rep_result;
{
	krb5_flags		kdc_options = krb5_kdc_default_options;
	krb5_octet		result;
	krb5_creds 		creds;
	krb5_error_code		retval = 0;
	krb5_authenticator	authent;
	krb5_data		inbuf, outbuf;
	int			len;
	krb5_ccache		use_ccache = 0;

	/*
	 * First, send over the length of the sendauth version string;
	 * then, we send over the sendauth version.  Next, we send
	 * over the length of the application version strings followed
	 * by the string itself.  
	 */
	outbuf.length = strlen(sendauth_version) + 1;
	outbuf.data = sendauth_version;
	if (retval = krb5_write_message(fd, &outbuf))
		return(retval);
	outbuf.length = strlen(appl_version) + 1;
	outbuf.data = appl_version;
	if (retval = krb5_write_message(fd, &outbuf))
		return(retval);
	/*
	 * Now, read back a byte: 0 means no error, 1 means bad sendauth
	 * version, 2 means bad application version
	 */
	if ((len = krb5_net_read(*((int *) fd), (char *)&result, 1)) != 1)
		return((len < 0) ? errno : ECONNABORTED);
	if (result == 1)
		return(KRB5_SENDAUTH_BADAUTHVERS);
	else if (result == 2)
		return(KRB5_SENDAUTH_BADAPPLVERS);
	else if (result != 0)
		return(KRB5_SENDAUTH_BADRESPONSE);
	/*
	 * We're finished with the initial negotiations; let's get and
	 * send over the authentication header.  (The AP_REQ message)
	 */

	/*
	 * If no credentials were provided, try getting it from the
	 * credentials cache.
	 */
	memset((char *)&creds, 0, sizeof(creds));
	memset((char *)&authent, 0, sizeof(authent));

	/*
	 * See if we need to access the credentials cache
	 */
	if (!credsp || !credsp->ticket.length) {
		if (ccache)
			use_ccache = ccache;
		else if (retval = krb5_cc_default(&use_ccache))
			goto error_return;
	}
	if (!credsp) {
		if (retval = krb5_copy_principal(server, &creds.server))
			goto error_return;
		if (client)
			retval = krb5_copy_principal(client, &creds.client);
		else
			retval = krb5_cc_get_principal(use_ccache,
						       &creds.client);
		if (retval) {
			krb5_free_principal(creds.server);
			goto error_return;
		}
		/* creds.times.endtime = 0; -- memset 0 takes care of this
					zero means "as long as possible" */
		/* creds.keyblock.keytype = 0; -- as well as this.
					zero means no session keytype
					preference */
		credsp = &creds;
	}
	if (!credsp->ticket.length) {
		if (retval = krb5_get_credentials(kdc_options,
						  use_ccache,
						  credsp))
		    goto error_return;
	}

	/*
	 * Generate a random sequence number
	 */
	if (sequence &&
	    (retval = krb5_generate_seq_number(&credsp->keyblock, sequence))) 
	    goto error_return;

	/*
	 * OK, get the authentication header!
	 */
	if (retval = krb5_mk_req_extended(ap_req_options, checksump,
					  kdc_options,
					  sequence ? *sequence : 0, newkey,
					  use_ccache, credsp, &authent,
					  &outbuf))
	    goto error_return;

	/*
	 * First write the length of the AP_REQ message, then write
	 * the message itself.
	 */
	retval = krb5_write_message(fd, &outbuf);
	free(outbuf.data);
	if (retval)
	    goto error_return;

	/*
	 * Now, read back a message.  If it was a null message (the
	 * length was zero) then there was no error.  If not, we the
	 * authentication was rejected, and we need to return the
	 * error structure.
	 */
	if (retval = krb5_read_message(fd, &inbuf))
	    goto error_return;

	if (inbuf.length) {
		if (error) {
		    if (retval = krb5_rd_error(&inbuf, error)) {
			krb5_xfree(inbuf.data);
			goto error_return;
		    }
		}
		krb5_xfree(inbuf.data);
		retval = KRB5_SENDAUTH_REJECTED;
		goto error_return;
	}
	
	/*
	 * If we asked for mutual authentication, we should now get a
	 * length field, followed by a AP_REP message
	 */
	if ((ap_req_options & AP_OPTS_MUTUAL_REQUIRED)) {
	    krb5_ap_rep_enc_part	*repl = 0;
		
	    if (retval = krb5_read_message(fd, &inbuf))
		goto error_return;

	    retval = krb5_rd_rep(&inbuf, &credsp->keyblock, &repl);
	    krb5_xfree(inbuf.data);
	    if (retval || ((repl->ctime != authent.ctime) ||
			   (repl->cusec != authent.cusec)))
		retval = KRB5_SENDAUTH_MUTUAL_FAILED;
	    if (retval) {
		if (repl)
		    krb5_free_ap_rep_enc_part(repl);
		goto error_return;
	    }
	    /*
	     * If the user wants to look at the AP_REP message,
	     * copy it for him
	     */
	    if (rep_result) 
		*rep_result = repl;
	    else
		krb5_free_ap_rep_enc_part(repl);
	}
	retval = 0;		/* Normal return */
error_return:
	if (!ccache && use_ccache)
		krb5_cc_close(use_ccache);
	krb5_free_cred_contents(&creds);
	krb5_free_authenticator_contents(&authent);
	return(retval);
	
}


