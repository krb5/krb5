/*
 * Copyright 1993 by OpenVision Technologies, Inc.
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

#include "gssapiP_krb5.h"

krb5_error_code
kg_make_seq_num(ed, direction, seqnum, cksum, buf)
     krb5_gss_enc_desc *ed;
     int direction;
     krb5_int32 seqnum;
     unsigned char *cksum;
     unsigned char *buf;
{
   unsigned char plain[8];

   plain[0] = (unsigned char) (seqnum&0xff);
   plain[1] = (unsigned char) ((seqnum>>8)&0xff);
   plain[2] = (unsigned char) ((seqnum>>16)&0xff);
   plain[3] = (unsigned char) ((seqnum>>24)&0xff);

   plain[4] = direction;
   plain[5] = direction;
   plain[6] = direction;
   plain[7] = direction;

   return(kg_encrypt(ed, cksum, plain, buf, 8));
}
