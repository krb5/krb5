/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
	krb5_checksum		checksum;
	krb5_error_code		retval = 0;
	krb5_authenticator	authent;
	krb5_data		inbuf, outbuf;
	int			len;

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
	if (!credsp) {
		if (!ccache)
			return(KRB5_NOCREDS_SUPPLIED);
		creds.server = (krb5_principal) server;
		if (retval = krb5_copy_principal(client, &creds.client))
			return(retval);
		/* creds.times.endtime = 0; -- memset 0 takes care of this
					zero means "as long as possible" */
		/* creds.keyblock.keytype = 0; -- as well as this.
					zero means no session keytype
					preference */
		credsp = &creds;
	}
	if (!credsp->ticket.length) {
		if (retval = krb5_get_credentials(kdc_options,
						  ccache,
						  &creds)) {
			krb5_free_cred_contents(&creds);
			return(retval);
		}
	}

	/*
	 * If no checksum was provided, supply a zero checksum structure
	 */
	
	if (!checksump) {
		memset((char *)&checksum, 0, sizeof(checksum));
		checksump = &checksum;
	}

	/*
	 * Generate a random sequence number
	 */
	if (sequence &&
	    (retval = krb5_generate_seq_number(&credsp->keyblock, sequence))) {

	    memset((char *)&authent, 0, sizeof(authent));
	    krb5_free_cred_contents(&creds);
	    return(retval);	
	}
	/*
	 * OK, get the authentication header!
	 */
	if (retval = krb5_mk_req_extended(ap_req_options, checksump,
					  kdc_options,
					  sequence ? *sequence : 0, newkey,
					  ccache, credsp, &authent, &outbuf)) {
		memset((char *)&authent, 0, sizeof(authent));
		krb5_free_cred_contents(&creds);
		return(retval);	
	}

	/*
	 * First write the length of the AP_REQ message, then write
	 * the message itself.
	 */
	if (retval = krb5_write_message(fd, &outbuf)) {
		krb5_free_cred_contents(&creds);
		memset((char *)&authent, 0, sizeof(authent));
		return(retval);
	}
	free(outbuf.data);

	/*
	 * Now, read back a message.  If it was a null message (the
	 * length was zero) then there was no error.  If not, we the
	 * authentication was rejected, and we need to return the
	 * error structure.
	 */
	if (retval = krb5_read_message(fd, &inbuf)) {
		krb5_free_cred_contents(&creds);
		memset((char *)&authent, 0, sizeof(authent));
		return(retval);
	}
	if (inbuf.length) {
		if (error) {
			if (retval = krb5_rd_error(&inbuf, error)) {
				xfree(inbuf.data);
				return(retval);
			}
		}
		xfree(inbuf.data);
		krb5_free_cred_contents(&creds);
		memset((char *)&authent, 0, sizeof(authent));
		return(KRB5_SENDAUTH_REJECTED);
	}
	/*
	 * If we asked for mutual authentication, we should now get a
	 * length field, followed by a AP_REP message
	 */
	if ((ap_req_options & AP_OPTS_MUTUAL_REQUIRED)) {
		krb5_ap_rep_enc_part	*repl;
		krb5_error_code		problem = 0;
		
		if (retval = krb5_read_message(fd, &inbuf)) {
			krb5_free_cred_contents(&creds);
			memset((char *)&authent, 0, sizeof(authent));
			return(retval);
		}
		problem = krb5_rd_rep(&inbuf,
				      &credsp->keyblock,
				      &repl);
		if (problem || ((repl->ctime != authent.ctime) ||
				(repl->cusec != authent.cusec)))
			problem = KRB5_SENDAUTH_MUTUAL_FAILED;
		memset((char *)&authent, 0, sizeof(authent));
		krb5_free_cred_contents(&creds);
		xfree(inbuf.data);
		if (problem) {
			krb5_free_ap_rep_enc_part(repl);
			return(problem);
		}
		/*
		 * If the user wants to look at the AP_REP message,
		 * copy it for him
		 */
		if (rep_result) 
			*rep_result = repl;
		else
			krb5_free_ap_rep_enc_part(repl);
	} else
		krb5_free_cred_contents(&creds);
	return(0);
}


