/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>

#include <krb.h>
#include "krb524.h"

extern int optind;
extern char *optarg;

int main(argc, argv)
     int argc;
     char **argv;
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds increds, *v5creds;
     CREDENTIALS v4creds;
     int code;
     int option;
     char *princ = NULL;
     int nodelete = 0;
     int lose = 0;
     krb5_context context;
     krb5_error_code retval;

     retval = krb5_init_context(&context);
     if (retval) {
	     com_err(argv[0], retval, "while initializing krb5");
	     exit(1);
     }

     while(((option =  getopt(argc, argv, "p:n")) != EOF)) {
	 switch(option) {
	   case 'p':
	     princ = optarg;
	     break;
	   case 'n':
	     nodelete++;
	     break;
	   default:
	     lose++;
	     break;
	 }
     }

     if (lose || (argc - optind > 1)) {
	 fprintf(stderr, "Usage: k524init [-p principal]\n");
	 exit(1);
     }

     krb524_init_ets(context);

     if ((code = krb5_cc_default(context, &cc))) {
	  com_err("k524init", code, "opening default credentials cache");
	  exit(1);
     }

     if ((code = krb5_cc_get_principal(context, cc, &client))) {
	 com_err("k524init", code, "while retrieving user principal name");
	 exit(1);
     }

     if (princ) {
	 if ((code = krb5_parse_name(context, princ, &server))) {
	     com_err("k524init", code, "while parsing service principal name");
	     exit(1);
	 }
     } else {
	 if ((code = krb5_build_principal(context, &server, 
					  krb5_princ_realm(context, client)->length,
					  krb5_princ_realm(context, client)->data,
					  "krbtgt",
					  krb5_princ_realm(context, client)->data,
					  NULL))) {
	     com_err("k524init", code, "while creating service principal name");
	     exit(1);
	 }
     }

     memset((char *) &increds, 0, sizeof(increds));
     increds.client = client;
     increds.server = server;
     increds.times.endtime = 0;
     increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
     if ((code = krb5_get_credentials(context, 0, cc, &increds, &v5creds))) {
	  com_err("k524init", code, "getting V5 credentials");
	  exit(1);
     }

     if ((code = krb524_convert_creds_kdc(context, v5creds, &v4creds))) {
	  com_err("k524init", code, "converting to V4 credentials");
	  exit(1);
     }
     
     /* this is stolen from the v4 kinit */

     if (!nodelete) {
	/* initialize ticket cache */
	if ((code = in_tkt(v4creds.pname,v4creds.pinst) != KSUCCESS)) {
	   com_err("k524init", code, "trying to create the V4 ticket file");
	   exit(1);
	}
     }

#ifdef	notdef
     /* stash ticket, session key, etc. for future use */
     if ((code = krb_save_credentials(v4creds.service, v4creds.instance,
				      v4creds.realm, v4creds.session,
				      v4creds.lifetime, v4creds.kvno,
				      &(v4creds.ticket_st), 
				      v4creds.issue_date))) {
	 com_err("k524init", code, "trying to save the V4 ticket");
	 exit(1);
     }
#else	/* notdef */
     /*
      * krb_save_credentials() as supplied by CNS doesn't exist in the MIT
      * Kerberos version 4.  So, we're inlining the logic here.
      */
     if (((code = tf_init(TKT_FILE, W_TKT_FIL)) != KSUCCESS) ||
	 ((code = tf_save_cred(v4creds.service, v4creds.instance,
			       v4creds.realm, v4creds.session,
			       v4creds.lifetime, v4creds.kvno,
			       &(v4creds.ticket_st),
			       v4creds.issue_date)))) {
	 com_err("k524init", code, "trying to save the V4 ticket");
	 exit(1);
     }
     else
	 (void) tf_close();
#endif	/* notdef */

     exit(0);
}
