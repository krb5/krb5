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
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>

#include <krb.h>
#include "krb524.h"

/*
 * I'm sure that this is reinventing the wheel, but I don't know where
 * the wheel is hidden.
 */

int  encode_v4tkt PROTOTYPE((KTEXT_ST *, char *, int *)),
     encode_ktext PROTOTYPE((char **, int *, KTEXT_ST *)),
     encode_bytes PROTOTYPE((char **, int *, char *, int)),
     encode_int32 PROTOTYPE((char **, int *, int32 *));

int  decode_v4tkt PROTOTYPE((KTEXT_ST *, char *, int *)),
     decode_ktext PROTOTYPE((char **, int *, KTEXT_ST *)),
     decode_bytes PROTOTYPE((char **, int *, char *, int)),
     decode_int32 PROTOTYPE((char **, int *, krb5_int32 *));

int encode_bytes(out, outlen, in, len)
     char **out;
     int *outlen;
     char *in;
     int len;
{
     if (len > *outlen)
	  return KRB524_ENCFULL;
     memcpy(*out, in, len);
     *out += len;
     *outlen -= len;
     return 0;
}

int encode_int32(out, outlen, v)
     char **out;
     int *outlen;
     krb5_int32 *v;
{
     int nv;

     nv = htonl(*v);
     return encode_bytes(out, outlen, (char *) &nv, sizeof(nv));
}

int encode_v4tkt(v4tkt, buf, encoded_len)
     KTEXT_ST *v4tkt;
     char *buf;
     int *encoded_len;
{
     int buflen, ret;

     buflen = *encoded_len;

     if ((ret = encode_int32(&buf, &buflen, &v4tkt->length)))
	  return ret;
     if ((ret = encode_bytes(&buf, &buflen, (char *)v4tkt->dat, MAX_KTXT_LEN)))
	  return ret;
     if ((ret = encode_int32(&buf, &buflen, (krb5_int32 *) &v4tkt->mbz)))
	  return ret;

     *encoded_len -= buflen;
     return 0;
}

/* decode functions */

int decode_bytes(out, outlen, in, len)
     char **out;
     int *outlen;
     char *in; 
     int len;
{
     if (len > *outlen)
	  return KRB524_DECEMPTY;
     memcpy(in, *out, len);
     *out += len;
     *outlen -= len;
     return 0;
}

int decode_int32(out, outlen, v)
     char **out;
     int *outlen;
     krb5_int32 *v;
{
     int ret;
     int nv;

     if ((ret = decode_bytes(out, outlen, (char *) &nv, sizeof(nv))))
	  return ret;
     *v = ntohl(nv);
     return 0;
}

int decode_v4tkt(v4tkt, buf, encoded_len)
     KTEXT_ST *v4tkt;
     char *buf;
     int *encoded_len;
{
     int buflen, ret;

     buflen = *encoded_len;
     if ((ret = decode_int32(&buf, &buflen, &v4tkt->length)))
	  return ret;
     if ((ret = decode_bytes(&buf, &buflen, (char *)v4tkt->dat, MAX_KTXT_LEN)))
	  return ret;
     if ((ret = decode_int32(&buf, &buflen, (krb5_int32 *) &v4tkt->mbz)))
	  return ret;
     *encoded_len -= buflen;
     return 0;
}

