/*
 * Copyright 1993 by Geer Zolot Associates.  All Rights Reserved.
 * 
 * Export of this software from the United States of America is assumed
 * to require a specific license from the United States Government.  It
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

main(int argc, char **argv)
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds v5creds;
     CREDENTIALS v4creds;
     int i, ret;

     krb524_init_ets();

     if (ret = krb5_parse_name(argv[1], &client)) {
	  com_err("getcred", ret, "parsing client name");
	  exit(1);
     }
     if (ret = krb5_parse_name(argv[2], &server)) {
	  com_err("getcred", ret, "parsing server name");
	  exit(1);
     }
     if (ret = krb5_cc_default(&cc)) {
	  com_err("getcred", ret, "opening default credentials cache");
	  exit(1);
     }

     bzero((char *) &v5creds, sizeof(v5creds));
     v5creds.client = client;
     v5creds.server = server;
     v5creds.times.endtime = 0;
     v5creds.keyblock.keytype = KEYTYPE_DES;
     if (ret = krb5_get_credentials(0, cc, &v5creds)) {
	  com_err("getcred", ret, "getting V5 credentials");
	  exit(1);
     }

     if (ret = krb524_convert_creds_kdc(&v5creds, &v4creds)) {
	  com_err("getcred", ret, "converting to V4 credentials");
	  exit(1);
     }
     
     return 0;
}
