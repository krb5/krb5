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

#include <stdio.h>
#include "krb5.h"
#include <krb.h>

main(argc, argv)
     int argc;
     char **argv;
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds v5creds;
     CREDENTIALS v4creds;
     int i, ret;
     krb5_context context;
     
     krb5_init_context(&context);
     krb524_init_ets(context);

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

     memset((char *) &v5creds, 0, sizeof(v5creds));
     v5creds.client = client;
     v5creds.server = server;
     v5creds.times.endtime = 0;
     v5creds.keyblock.keytype = KEYTYPE_DES_CBC_MD5;
     if (ret = krb5_get_credentials(context, 0, cc, &v5creds)) {
	  com_err("getcred", ret, "getting V5 credentials");
	  exit(1);
     }

     if (ret = krb524_convert_creds_kdc(context, &v5creds, &v4creds)) {
	  com_err("getcred", ret, "converting to V4 credentials");
	  exit(1);
     }
     
     return 0;
}
