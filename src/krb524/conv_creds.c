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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <krb.h>

#include "krb524.h"

int krb524_convert_creds_plain
KRB5_PROTOTYPE((krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds));


int krb524_convert_creds_addr(context, v5creds, v4creds, saddr)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
     struct sockaddr *saddr;
{
     int ret;

     if ((ret = krb524_convert_creds_plain(context, v5creds, v4creds)))
	  return ret;

     return krb524_convert_tkt(v5creds->server, &v5creds->ticket,
			       &v4creds->ticket_st,
			       &v4creds->kvno,
			       (struct sockaddr_in *) saddr);
}

int krb524_convert_creds_kdc(context, v5creds, v4creds)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
{
     struct sockaddr_in *addrs;
     int ret, naddrs, i;

     if ((ret = krb5_locate_kdc(context, &v5creds->server->realm, &addrs,
			       &naddrs)))
	  return ret;
     if (naddrs == 0)
	  ret = KRB5_KDC_UNREACH;
     else {
          for (i = 0; i<naddrs; i++) {
	    addrs[i].sin_port = 0; /* use krb524 default port */
	    ret = krb524_convert_creds_addr(context, v5creds, v4creds,
					    (struct sockaddr *) &addrs[i]);
	    /* stop trying on success */
	    if (!ret) break;
	    switch(ret) {
	    case ECONNREFUSED:
	    case ENETUNREACH:
	    case ENETDOWN:
	    case ETIMEDOUT:
	    case EHOSTDOWN:
	    case EHOSTUNREACH:
	    case KRB524_NOTRESP:
	      continue;
	    default:
	      break;		/* out of switch */
	    }
	    /* if we fall through to here, it wasn't an "ok" error */
	    break;
	  }
     }
     
     free(addrs);
     return ret;
}

int krb524_convert_creds_plain(context, v5creds, v4creds)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
{
     krb5_ui_4 addr;
     int ret;
     krb5_timestamp lifetime;
     
     memset((char *) v4creds, 0, sizeof(CREDENTIALS));

     if ((ret = krb524_convert_princs(context, v5creds->client, 
				      v5creds->server,
				      v4creds->pname, v4creds->pinst,
				      v4creds->realm, v4creds->service,
				      v4creds->instance)))
	  return ret;

     /* Check enctype too */
     if (v5creds->keyblock.length != sizeof(C_Block)) {
	  if (krb524_debug)
	       fprintf(stderr, "v5 session keyblock length %d != C_Block size %d\n",
		       v5creds->keyblock.length,
		       sizeof(C_Block));
	  return KRB524_BADKEY;
     } else
	  memcpy(v4creds->session, (char *) v5creds->keyblock.contents,
		 sizeof(C_Block));

     /* V4 has no concept of authtime or renew_till, so ignore them */
     /* V4 lifetime is 1 byte, in 5 minute increments */
     lifetime = 
	  ((v5creds->times.endtime - v5creds->times.starttime) / 300);
     v4creds->lifetime =
	  ((lifetime > 0xff) ? 0xff : lifetime);
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
	  memcpy((char *) &addr, v5creds->addresses[0]->contents,
		 sizeof(addr));

     return 0;
}
