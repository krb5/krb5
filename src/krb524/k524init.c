/*
 * Copyright 1993 by Geer Zolot Associates.  All Rights Reserved.
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.  It
 * is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Geer Zolot Associates not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  Geer Zolot Associates makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */

#if !defined(lint) && !defined(SABER)
static char rcs_id[] = "$Id$";
#endif

#include <stdio.h>
#include <krb5/krb5.h>
#include <krb.h>

extern int optind;
extern char *optarg;

#if !defined(lint) && !defined(SABER)
const char rcsid[] = "$Id$";
#endif

main(int argc, char **argv)
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds v5creds;
     CREDENTIALS v4creds;
     int code;
     int option;
     char *princ = NULL;
     int nodelete = 0;
     int lose = 0;

     while((option =  getopt(argc, argv, "p:n")) != EOF) {
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

     krb524_init_ets();

     if (code = krb5_cc_default(&cc)) {
	  com_err("k524init", code, "opening default credentials cache");
	  exit(1);
     }

     if (code = krb5_cc_get_principal(cc, &client)) {
	 com_err("k524init", code, "while retrieving user principal name");
	 exit(1);
     }

     if (princ) {
	 if (code = krb5_parse_name(princ, &server)) {
	     com_err("k524init", code, "while parsing service principal name");
	     exit(1);
	 }
     } else {
	 if (code = krb5_build_principal(&server, 
					 krb5_princ_realm(client)->length,
					 krb5_princ_realm(client)->data,
					 "krbtgt",
					 krb5_princ_realm(client)->data,
					 NULL)) {
	     com_err("k524init", code, "while creating service principal name");
	     exit(1);
	 }
     }

     bzero((char *) &v5creds, sizeof(v5creds));
     v5creds.client = client;
     v5creds.server = server;
     v5creds.times.endtime = 0;
     v5creds.keyblock.keytype = KEYTYPE_DES;
     if (code = krb5_get_credentials(0, cc, &v5creds)) {
	  com_err("k524init", code, "getting V5 credentials");
	  exit(1);
     }

     if (code = krb524_convert_creds_kdc(&v5creds, &v4creds)) {
	  com_err("k524init", code, "converting to V4 credentials");
	  exit(1);
     }
     
     /* this is stolen from the v4 kinit */

     if (!nodelete) {
	/* initialize ticket cache */
	if (code = in_tkt(v4creds.pname,v4creds.pinst) != KSUCCESS) {
	   com_err("k524init", code, "trying to create the V4 ticket file");
	   exit(1);
	}
     }

     /* stash ticket, session key, etc. for future use */
     if (code = save_credentials(v4creds.service, v4creds.instance,
				 v4creds.realm, v4creds.session,
				 v4creds.lifetime, v4creds.kvno,
				 &(v4creds.ticket_st), v4creds.issue_date)) {
	 com_err("k524init", code, "trying to save the V4 ticket");
	 exit(1);
     }

     exit(0);
}
