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
#include "port-sockets.h"
#include "socket-utils.h"
#include <krb.h>
#include "krb524.h"

#ifdef USE_CCAPI
#include <CredentialsCache.h>
#endif

krb5_error_code krb524_convert_creds_plain
(krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds);

krb5_error_code
krb524_convert_creds_kdc(context, v5creds, v4creds)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
{
     krb5_error_code ret;
     krb5_data reply;
     char *p;
     struct sockaddr_storage ss;
     socklen_t slen = sizeof(ss);

     ret = krb524_convert_creds_plain(context, v5creds, v4creds);
     if (ret)
	 return ret;

     reply.data = NULL;
     ret = krb524_sendto_kdc(context, &v5creds->ticket,
			     &v5creds->server->realm, &reply,
			     ss2sa(&ss), &slen);
     if (ret)
	 return ret;

#if TARGET_OS_MAC
#ifdef USE_CCAPI
     v4creds->stk_type = cc_v4_stk_des;
#endif
     if (slen == sizeof(struct sockaddr_in)
	 && ss2sa(&ss)->sa_family == AF_INET) {
	 v4creds->address = ss2sin(&ss)->sin_addr.s_addr;
     }
     /* Otherwise, leave it set to all-zero.  */
#endif

     p = reply.data;
     ret = ntohl(*((krb5_error_code *) p));
     p += sizeof(krb5_int32);
     reply.length -= sizeof(krb5_int32);
     if (ret)
	 goto fail;

     v4creds->kvno = ntohl(*((krb5_error_code *) p));
     p += sizeof(krb5_int32);
     reply.length -= sizeof(krb5_int32);
     ret = decode_v4tkt(&v4creds->ticket_st, p, &reply.length);

fail:
     if (reply.data) 
	 free(reply.data);
     reply.data = NULL;
     return ret;
}

krb5_error_code
krb524_convert_creds_plain(context, v5creds, v4creds)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
{
     int ret;
     krb5_timestamp endtime;
     char dummy[REALM_SZ];
     memset((char *) v4creds, 0, sizeof(CREDENTIALS));

     if ((ret = krb524_convert_princs(context, v5creds->client, 
				      v5creds->server,
				      v4creds->pname, v4creds->pinst,
				      dummy, v4creds->service,
				      v4creds->instance, v4creds->realm)))
	  return ret;

     /* Check enctype too */
     if (v5creds->keyblock.length != sizeof(C_Block)) {
	  if (krb524_debug)
	       fprintf(stderr, "v5 session keyblock length %d != C_Block size %d\n",
		       v5creds->keyblock.length,
		       (int) sizeof(C_Block));
	  return KRB524_BADKEY;
     } else
	  memcpy(v4creds->session, (char *) v5creds->keyblock.contents,
		 sizeof(C_Block));

     /* V4 has no concept of authtime or renew_till, so ignore them */
     v4creds->issue_date = v5creds->times.starttime;
     v4creds->lifetime = krb_time_to_life(v5creds->times.starttime,
					  v5creds->times.endtime);
     endtime = krb_life_to_time(v5creds->times.starttime,
				v4creds->lifetime);
     /*
      * Adjust start time backwards to deal with rounding up in
      * krb_time_to_life(), to match code on server side.
      */
     if (endtime > v5creds->times.endtime)
	 v4creds->issue_date -= endtime - v5creds->times.endtime;

     return 0;
}
