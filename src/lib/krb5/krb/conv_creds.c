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

#include "k5-int.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "port-sockets.h"
#include "socket-utils.h"

#if defined(KRB5_KRB4_COMPAT) || defined(_WIN32) /* yuck */
#include "kerberosIV/krb.h"

#ifdef USE_CCAPI
#include <CredentialsCache.h>
#endif

#define krb524_debug krb5int_krb524_debug
int krb524_debug = 0;

static krb5_error_code krb524_convert_creds_plain
(krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds);

static int decode_v4tkt
	(struct ktext *v4tkt, char *buf, unsigned int *encoded_len);

krb5_error_code KRB5_CALLCONV
krb5_524_convert_creds(krb5_context context, krb5_creds *v5creds,
		       CREDENTIALS *v4creds)
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
     ret = krb5int_524_sendto_kdc(context, &v5creds->ticket,
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

static krb5_error_code
krb524_convert_creds_plain(context, v5creds, v4creds)
     krb5_context context;
     krb5_creds *v5creds;
     CREDENTIALS *v4creds;
{
     int ret;
     krb5_timestamp endtime;
     char dummy[REALM_SZ];
     memset((char *) v4creds, 0, sizeof(CREDENTIALS));

     if ((ret = krb5_524_conv_principal(context, v5creds->client,
					v4creds->pname, v4creds->pinst,
					dummy)))
	 return ret;
     if ((ret = krb5_524_conv_principal(context, v5creds->server,
					v4creds->service, v4creds->instance,
					v4creds->realm)))
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
     v4creds->lifetime = krb5int_krb_time_to_life(v5creds->times.starttime,
						  v5creds->times.endtime);
     endtime = krb5int_krb_life_to_time(v4creds->issue_date,
					v4creds->lifetime);
     /*
      * Adjust start time backwards to deal with rounding up in
      * krb_time_to_life(), to match code on server side.
      */
     if (endtime > v5creds->times.endtime)
	 v4creds->issue_date -= endtime - v5creds->times.endtime;

     return 0;
}

/* this used to be krb524/encode.c, under same copyright as above */
/*
 * I'm sure that this is reinventing the wheel, but I don't know where
 * the wheel is hidden.
 */

int  encode_v4tkt (KTEXT_ST *, char *, unsigned int *);
static int encode_bytes (char **, int *, char *, unsigned int),
    encode_int32 (char **, int *, krb5_int32 *);

static int decode_bytes (char **, int *, char *, unsigned int),
    decode_int32 (char **, int *, krb5_int32 *);

static int encode_bytes(out, outlen, in, len)
     char **out;
     int *outlen;
     char *in;
     unsigned int len;
{
     if (len > *outlen)
	  return KRB524_ENCFULL;
     memcpy(*out, in, len);
     *out += len;
     *outlen -= len;
     return 0;
}

static int encode_int32(out, outlen, v)
     char **out;
     int *outlen;
     krb5_int32 *v;
{
     krb5_int32 nv; /* Must be 4 bytes */

     nv = htonl(*v);
     return encode_bytes(out, outlen, (char *) &nv, sizeof(nv));
}

int krb5int_encode_v4tkt(v4tkt, buf, encoded_len)
     KTEXT_ST *v4tkt;
     char *buf;
     unsigned int *encoded_len;
{
     int buflen, ret;
     krb5_int32 temp;

     buflen = *encoded_len;

     if (v4tkt->length < MAX_KTXT_LEN)
	  memset(v4tkt->dat + v4tkt->length, 0, 
		 (unsigned int) (MAX_KTXT_LEN - v4tkt->length));
     temp = v4tkt->length;
     if ((ret = encode_int32(&buf, &buflen, &temp)))
	  return ret;
     if ((ret = encode_bytes(&buf, &buflen, (char *)v4tkt->dat, MAX_KTXT_LEN)))
	  return ret;
     temp = v4tkt->mbz;
     if ((ret = encode_int32(&buf, &buflen, &temp)))
	  return ret;

     *encoded_len -= buflen;
     return 0;
}

/* decode functions */

static int decode_bytes(out, outlen, in, len)
     char **out;
     int *outlen;
     char *in; 
     unsigned int len;
{
     if (len > *outlen)
	  return KRB524_DECEMPTY;
     memcpy(in, *out, len);
     *out += len;
     *outlen -= len;
     return 0;
}

static int decode_int32(out, outlen, v)
     char **out;
     int *outlen;
     krb5_int32 *v;
{
     int ret;
     krb5_int32 nv; /* Must be four bytes */

     if ((ret = decode_bytes(out, outlen, (char *) &nv, sizeof(nv))))
	  return ret;
     *v = ntohl(nv);
     return 0;
}

static int decode_v4tkt(v4tkt, buf, encoded_len)
     KTEXT_ST *v4tkt;
     char *buf;
     unsigned int *encoded_len;
{
     int buflen, ret;
     krb5_int32 temp;

     buflen = *encoded_len;
     if ((ret = decode_int32(&buf, &buflen, &temp)))
	  return ret;
     v4tkt->length = temp;
     if ((ret = decode_bytes(&buf, &buflen, (char *)v4tkt->dat, MAX_KTXT_LEN)))
	  return ret;
     if ((ret = decode_int32(&buf, &buflen, &temp)))
	  return ret;
     v4tkt->mbz = temp;
     *encoded_len -= buflen;
     return 0;
}

#else /* no krb4 compat */

krb5_error_code KRB5_CALLCONV
krb5_524_convert_creds(krb5_context context, krb5_creds *v5creds,
		       struct credentials *v4creds)
{
    return KRB524_KRB4_DISABLED;
}

#endif

/* These may be needed for object-level backwards compatibility on Mac
   OS and UNIX, but Windows should be okay.  */
#ifndef _WIN32
#undef krb524_convert_creds_kdc
#undef krb524_init_ets

/* Declarations ahead of the definitions will suppress some gcc
   warnings.  */
void KRB5_CALLCONV krb524_init_ets (void);
krb5_error_code KRB5_CALLCONV
krb524_convert_creds_kdc(krb5_context context, krb5_creds *v5creds,
			 struct credentials *v4creds);

krb5_error_code KRB5_CALLCONV
krb524_convert_creds_kdc(krb5_context context, krb5_creds *v5creds,
			 struct credentials *v4creds)
{
    return krb5_524_convert_creds(context, v5creds, v4creds);
}

void KRB5_CALLCONV krb524_init_ets ()
{
}
#endif
