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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <krb5/krb5.h>
#include <krb.h>

#include "krb524.h"

int krb524_convert_creds_addr(krb5_creds *v5creds, CREDENTIALS *v4creds,
			 struct sockaddr *saddr)
{
     int ret;

     if (ret = krb524_convert_creds_plain(v5creds, v4creds))
	  return ret;

     return krb524_convert_tkt(v5creds->server, &v5creds->ticket,
			       &v4creds->ticket_st,
			       &v4creds->kvno,
			       saddr);
}

int krb524_convert_creds_kdc(krb5_creds *v5creds, CREDENTIALS *v4creds)
{
     struct sockaddr_in *addrs;
     int ret, naddrs;

     if (ret = krb5_locate_kdc(&v5creds->server->realm, &addrs, &naddrs))
	  return ret;
     if (naddrs == 0)
	  ret = KRB5_KDC_UNREACH;
     else {
	  addrs[0].sin_port = 0; /* use krb524 default port */
	  ret = krb524_convert_creds_addr(v5creds, v4creds,
					  (struct sockaddr *) &addrs[0]);
     }
     
     free(addrs);
     return ret;
}

int krb524_convert_creds_plain(krb5_creds *v5creds, CREDENTIALS *v4creds)
{
     unsigned long addr;
     krb5_data *comp;
     int ret;
     
     memset((char *) v4creds, 0, sizeof(CREDENTIALS));

     if (ret = krb524_convert_princs(v5creds->client, v5creds->server,
				     v4creds->pname, v4creds->pinst,
				     v4creds->realm, v4creds->service,
				     v4creds->instance))
	  return ret;

     /* Check keytype too */
     if (v5creds->keyblock.length != sizeof(C_Block)) {
	  if (krb524_debug)
	       fprintf(stderr, "v5 session keyblock length %d != "
		       "C_Block size %d\n", v5creds->keyblock.length,
		       sizeof(C_Block));
	  return KRB524_BADKEY;
     } else
	  bcopy((char *) v5creds->keyblock.contents, v4creds->session,
		sizeof(C_Block));

     /* V4 has no concept of authtime or renew_till, so ignore them */
     /* V4 lifetime is 1 byte, in 5 minute increments */
     v4creds->lifetime = 0xff &
	  ((v5creds->times.endtime - v5creds->times.starttime) / 300);
     v4creds->issue_date = v5creds->times.starttime;

     /* XXX perhaps we should use the addr of the client host if */
     /* v5creds contains more than one addr.  Q: Does V4 support */
     /* non-INET addresses? */
     if (!v5creds->addresses || !v5creds->addresses[0] ||
	 v5creds->addresses[0]->addrtype != ADDRTYPE_INET ||
	 v5creds->addresses[0]->length != sizeof(addr)) {
	  if (krb524_debug)
	       fprintf(stderr, "Invalid v5creds address information.\n");
	  return KRB524_BADADDR;
     } else
	  bcopy(v5creds->addresses[0]->contents, (char *) &addr,
		sizeof(addr));

     return 0;
}
