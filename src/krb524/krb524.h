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

#ifndef __KRB524_H__
#define __KRB524_H__

#define KRB524_SERVICE "krb524"
#define KRB524_PORT 4444

#include "krb524_err.h"

extern int krb524_debug;

int krb524_convert_tkt_skey
	KRB5_PROTOTYPE((krb5_context context, krb5_ticket *v5tkt, KTEXT_ST *v4tkt, 
		   krb5_keyblock *v5_skey, krb5_keyblock *v4_skey));

/* conv_princ.c */

int krb524_convert_princs
	KRB5_PROTOTYPE((krb5_context context, krb5_principal client, 
		   krb5_principal server, char *pname, 
		   char *pinst, char *prealm, char *sname, char *sinst));

/* conv_creds.c */

int krb524_convert_creds_addr
	KRB5_PROTOTYPE((krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds, struct sockaddr *saddr));

int krb524_convert_creds_kdc
	KRB5_PROTOTYPE((krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds));

/* conv_tkt.c */

int krb524_convert_tkt
	KRB5_PROTOTYPE((krb5_principal server, krb5_data *v5tkt, KTEXT_ST *v4tkt,
		   int *kvno, struct sockaddr_in *saddr));

/* encode.c */

int encode_v4tkt
	KRB5_PROTOTYPE((KTEXT_ST *v4tkt, char *buf, int *encoded_len));

int decode_v4tkt
	KRB5_PROTOTYPE((KTEXT_ST *v4tkt, char *buf, int *encoded_len));


/* misc.c */

void krb524_init_ets
	KRB5_PROTOTYPE((krb5_context context));

/* sendmsg.c */

int krb524_send_message 
	KRB5_PROTOTYPE((const struct sockaddr * addr, const krb5_data * message,
		   krb5_data * reply));

#endif /* __KRB524_H__ */
