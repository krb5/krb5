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

#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
	#include <TargetConditionals.h>
    #include <Kerberos/krb5.h>
    #include <Kerberos/krb.h>
    #ifndef KRB524_PRIVATE /* Allow e.g. build system to override */
		#define KRB524_PRIVATE 0
	#endif
#else
    #include "krb524_err.h"
	#ifndef KRB524_PRIVATE
		#define KRB524_PRIVATE 1
	#endif
#endif	

#if defined(__cplusplus) && !defined(KRB524INT_BEGIN_DECLS)
#define KRB524INT_BEGIN_DECLS	extern "C" {
#define KRB524INT_END_DECLS	}
#else
#define KRB524INT_BEGIN_DECLS
#define KRB524INT_END_DECLS
#endif

#if TARGET_OS_MAC
    #if defined(__MWERKS__)
        #pragma import on
        #pragma enumsalwaysint on
    #endif
    #pragma options align=mac68k
#endif

KRB524INT_BEGIN_DECLS

#if KRB524_PRIVATE
extern int krb524_debug;

int krb524_convert_tkt_skey
	(krb5_context context, krb5_ticket *v5tkt, KTEXT_ST *v4tkt, 
		   krb5_keyblock *v5_skey, krb5_keyblock *v4_skey,
			struct sockaddr_in *saddr);

/* conv_princ.c */

int krb524_convert_princs
	(krb5_context context, krb5_principal client, krb5_principal server,
	 char *pname, char *pinst, char *prealm,
	 char *sname, char *sinst, char *srealm);

/* conv_creds.c */

int krb524_convert_creds_addr
	(krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds, struct sockaddr *saddr);
#endif /* KRB524_PRIVATE */

int krb524_convert_creds_kdc
	(krb5_context context, krb5_creds *v5creds, 
		   CREDENTIALS *v4creds);

#if KRB524_PRIVATE
/* conv_tkt.c */

int krb524_convert_tkt
	(krb5_principal server, krb5_data *v5tkt, KTEXT_ST *v4tkt,
		   int *kvno, struct sockaddr_in *saddr);

/* encode.c */

int encode_v4tkt
	(KTEXT_ST *v4tkt, char *buf, unsigned int *encoded_len);

int decode_v4tkt
	(KTEXT_ST *v4tkt, char *buf, unsigned int *encoded_len);


/* misc.c */

void krb524_init_ets
	(krb5_context context);

/* sendmsg.c */

int krb524_sendto_kdc
        (krb5_context context, const krb5_data * message, 
	 const krb5_data * realm, krb5_data * reply);
#endif /* KRB524_PRIVATE */

#if TARGET_OS_MAC
    #if defined(__MWERKS__)
        #pragma enumsalwaysint reset
        #pragma import reset
    #endif
	#pragma options align=reset
#endif

KRB524INT_END_DECLS

#endif /* __KRB524_H__ */
