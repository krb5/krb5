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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "krb5.h"
#include <krb.h>
#include "krb524.h"

/*
 * krb524_convert_tkt.  Open a network connection to krb524d, send it
 * the V5 ticket, receive the V4 ticket in response.
 */
int krb524_convert_tkt(server, v5tkt, v4tkt, kvno, saddr)
     krb5_principal server;
     krb5_data *v5tkt;
     KTEXT_ST *v4tkt;
     int *kvno;
     struct sockaddr_in *saddr;
{
     char *p;
     krb5_data reply;
     struct servent *serv;
     int ret, status;

     reply.data = NULL;

     if (saddr->sin_port == 0) {
	  serv = getservbyname(KRB524_SERVICE, "udp");
	  if (serv)
	       saddr->sin_port = serv->s_port;
	  else
	       saddr->sin_port = htons(KRB524_PORT);
     }

     if ((ret = krb524_send_message((struct sockaddr *) saddr, v5tkt, &reply)))
	  goto fail;
     
     p = reply.data;
     status = ntohl(*((krb5_error_code *) p));
     p += sizeof(krb5_error_code);
     reply.length -= sizeof(krb5_error_code);
     if (status) {
	  ret = status;
	  goto fail;
     }
     *kvno = ntohl(*((krb5_error_code *) p));
     p += sizeof(int);
     reply.length -= sizeof(int);
     ret = decode_v4tkt(v4tkt, p, &reply.length);

fail:
     if (ret) {
	  if (reply.data) 
	       free(reply.data);
	  reply.data = NULL;
	  reply.length = 0;
     }

     return ret;
}

