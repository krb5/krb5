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

#ifndef KRB524INT_H
#define KRB524INT_H

#include "port-sockets.h"
#include "kerberosIV/krb.h"

#ifndef KRB524INT_BEGIN_DECLS
#ifdef __cplusplus
#define KRB524INT_BEGIN_DECLS	extern "C" {
#define KRB524INT_END_DECLS	}
#else
#define KRB524INT_BEGIN_DECLS
#define KRB524INT_END_DECLS
#endif
#endif

KRB524INT_BEGIN_DECLS

int krb524_convert_tkt_skey
	(krb5_context context, krb5_ticket *v5tkt, KTEXT_ST *v4tkt, 
		   krb5_keyblock *v5_skey, krb5_keyblock *v4_skey,
			struct sockaddr_in *saddr);

/* conv_princ.c */

int krb524_convert_princs
	(krb5_context context, krb5_principal client, krb5_principal server,
	 char *pname, char *pinst, char *prealm,
	 char *sname, char *sinst, char *srealm);

KRB524INT_END_DECLS

#endif /* KRB524INT_H */
