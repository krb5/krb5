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

#include "krb524.h"

/*
 * I'm sure that this is reinventing the wheel, but I don't know where
 * the wheel is hidden.
 */

int  encode_v4tkt(KTEXT_ST *, char *, int *),
     encode_ktext(char **, int *, KTEXT_ST *),
     encode_bytes(char **, int *, char *, int),
     encode_int32(char **, int *, krb5_int32 *);

int  decode_v4tkt(KTEXT_ST *, char *, int *),
     decode_ktext(char **, int *, KTEXT_ST *),
     decode_bytes(char **, int *, char *, int),
     decode_int32(char **, int *, krb5_int32 *);

int encode_bytes(char **out, int *outlen, char *in, int len)
{
     if (len > *outlen)
	  return KRB524_ENCFULL;
     bcopy(in, *out, len);
     *out += len;
     *outlen -= len;
     return 0;
}

int encode_int32(char **out, int *outlen, krb5_int32 *v)
{
     int ret;
     int nv;

     nv = htonl(*v);
     return encode_bytes(out, outlen, (char *) &nv, sizeof(nv));
}

int encode_v4tkt(KTEXT_ST *v4tkt, char *buf, int *encoded_len)
{
     int buflen, ret;

     buflen = *encoded_len;

     if (ret = encode_int32(&buf, &buflen, &v4tkt->length))
	  return ret;
     if (ret = encode_bytes(&buf, &buflen, v4tkt->dat, MAX_KTXT_LEN))
	  return ret;
     if (ret = encode_int32(&buf, &buflen, &v4tkt->mbz))
	  return ret;

     *encoded_len -= buflen;
     return 0;
}

/* decode functions */

int decode_bytes(char **out, int *outlen, char *in, int len)
{
     if (len > *outlen)
	  return KRB524_DECEMPTY;
     bcopy(*out, in, len);
     *out += len;
     *outlen -= len;
     return 0;
}

int decode_int32(char **out, int *outlen, krb5_int32 *v)
{
     int ret;
     int nv;

     if (ret = decode_bytes(out, outlen, (char *) &nv, sizeof(nv)))
	  return ret;
     *v = ntohl(nv);
     return 0;
}

int decode_v4tkt(KTEXT_ST *v4tkt, char *buf, int *encoded_len)
{
     int buflen, ret;

     buflen = *encoded_len;
     if (ret = decode_int32(&buf, &buflen, &v4tkt->length))
	  return ret;
     if (ret = decode_bytes(&buf, &buflen, v4tkt->dat, MAX_KTXT_LEN))
	  return ret;
     if (ret = decode_int32(&buf, &buflen, &v4tkt->mbz))
	  return ret;
     *encoded_len -= buflen;
     return 0;
}

