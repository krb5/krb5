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

#include "autoconf.h"
#include <krb5.h>
#include "com_err.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/time.h>
#include <sys/signal.h>
#include <netinet/in.h>
#endif

#include <krb.h>

extern int optind;
extern char *optarg;
char *prog = "k524init";

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

     if (argv[0]) {
	 prog = strrchr (argv[0], '/');
	 if (prog)
	     prog++;
	 else
	     prog = argv[0];
     }

     retval = krb5_init_context(&context);
     if (retval) {
	     com_err(prog, retval, "while initializing krb5");
	     exit(1);
     }

     while(((option =  getopt(argc, argv, "p:n")) != -1)) {
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
	 fprintf(stderr, "Usage: %s [-p principal] [-n]\n", prog);
	 exit(1);
     }

     if ((code = krb5_cc_default(context, &cc))) {
	  com_err(prog, code, "opening default credentials cache");
	  exit(1);
     }

     if ((code = krb5_cc_get_principal(context, cc, &client))) {
	 com_err(prog, code, "while retrieving user principal name");
	 exit(1);
     }

     if (princ) {
	 if ((code = krb5_parse_name(context, princ, &server))) {
	     com_err(prog, code, "while parsing service principal name");
	     exit(1);
	 }
     } else {
	 if ((code = krb5_build_principal(context, &server, 
					  krb5_princ_realm(context, client)->length,
					  krb5_princ_realm(context, client)->data,
					  "krbtgt",
					  krb5_princ_realm(context, client)->data,
					  NULL))) {
	     com_err(prog, code, "while creating service principal name");
	     exit(1);
	 }
     }

     if (!nodelete) {
	 krb5_data *crealm = krb5_princ_realm (context, client);
	 krb5_data *srealm = krb5_princ_realm (context, server);
	 if (crealm->length != srealm->length
	     || memcmp (crealm->data, srealm->data, crealm->length)) {
	     /* Since krb4 ticket files don't store the realm name
		separately, and the client realm is assumed to be the
		realm of the first ticket, let's not store an initial
		ticket with the wrong realm name, since it'll confuse
		other programs.  */
	     fprintf (stderr,
		      "%s: Client and server principals' realm names are different;\n"
		      "\tbecause of limitations in the krb4 ticket file implementation,\n"
		      "\tthis doesn't work for an initial ticket.  Try `%s -n'\n"
		      "\tif you already have other krb4 tickets, or convert the\n"
		      "\tticket-granting ticket from your home realm.\n",
		      prog, prog);
	     exit (1);
	 }
     }

     memset((char *) &increds, 0, sizeof(increds));
     increds.client = client;
     increds.server = server;
     increds.times.endtime = 0;
     increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
     if ((code = krb5_get_credentials(context, 0, cc, &increds, &v5creds))) {
	  com_err(prog, code, "getting V5 credentials");
	  exit(1);
     }

     if ((code = krb5_524_convert_creds(context, v5creds, &v4creds))) {
	  com_err(prog, code, "converting to V4 credentials");
	  exit(1);
     }
     
     /* this is stolen from the v4 kinit */

     if (!nodelete) {
	 /* initialize ticket cache */
	 code = krb_in_tkt(v4creds.pname,v4creds.pinst,v4creds.realm);
	 if (code != KSUCCESS) {
	     fprintf (stderr, "%s: %s trying to create the V4 ticket file",
		      prog, krb_get_err_text (code));
	     exit(1);
	 }
     }

     /* stash ticket, session key, etc. for future use */
     /* This routine does *NOT* return one of the usual com_err codes.  */
     if ((code = krb_save_credentials(v4creds.service, v4creds.instance,
				      v4creds.realm, v4creds.session,
				      v4creds.lifetime, v4creds.kvno,
				      &(v4creds.ticket_st), 
				      v4creds.issue_date))) {
	 fprintf (stderr, "%s: %s trying to save the V4 ticket\n",
		  prog, krb_get_err_text (code));
	 exit(1);
     }

     exit(0);
}
