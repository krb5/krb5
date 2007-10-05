/*
 * include/kerberosIV/prot.h
 *
 * Copyright 1985-1994, 2001 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Prototypes for internal functions, mostly related to protocol
 * encoding and decoding.
 */

#ifndef PROT_DEFS
#define PROT_DEFS

#define		KRB_PORT		750	/* PC's don't have
						 * /etc/services */
#define		KRB_PROT_VERSION 	4
#define 	MAX_PKT_LEN		1000
#define		MAX_TXT_LEN		1000

/* Macro's to obtain various fields from a packet */

#define pkt_version(packet)  (unsigned int) *(packet->dat)
#define pkt_msg_type(packet) (unsigned int) *(packet->dat+1)
#define pkt_a_name(packet)   (packet->dat+2)
#define pkt_a_inst(packet)   \
	(packet->dat+3+strlen((char *)pkt_a_name(packet)))
#define pkt_a_realm(packet)  \
	(pkt_a_inst(packet)+1+strlen((char *)pkt_a_inst(packet)))

/* Macro to obtain realm from application request */
#define apreq_realm(auth)     (auth->dat + 3)

#define pkt_time_ws(packet) (char *) \
        (packet->dat+5+strlen((char *)pkt_a_name(packet)) + \
	 strlen((char *)pkt_a_inst(packet)) + \
	 strlen((char *)pkt_a_realm(packet)))

#define pkt_no_req(packet) (unsigned short) \
        *(packet->dat+9+strlen((char *)pkt_a_name(packet)) + \
	  strlen((char *)pkt_a_inst(packet)) + \
	  strlen((char *)pkt_a_realm(packet)))
#define pkt_x_date(packet) (char *) \
        (packet->dat+10+strlen((char *)pkt_a_name(packet)) + \
	 strlen((char *)pkt_a_inst(packet)) + \
	 strlen((char *)pkt_a_realm(packet)))
#define pkt_err_code(packet) ( (char *) \
        (packet->dat+9+strlen((char *)pkt_a_name(packet)) + \
	 strlen((char *)pkt_a_inst(packet)) + \
	 strlen((char *)pkt_a_realm(packet))))
#define pkt_err_text(packet) \
        (packet->dat+13+strlen((char *)pkt_a_name(packet)) + \
	 strlen((char *)pkt_a_inst(packet)) + \
	 strlen((char *)pkt_a_realm(packet)))

/*
 * This remains here for the KDC to use for now, but will go away
 * soon.
 */

#define     swap_u_long(x) {\
 unsigned KRB4_32   _krb_swap_tmp[4];\
 swab((char *)  &x,    ((char *)  _krb_swap_tmp) +2 ,2); \
 swab(((char *) &x) +2,((char *)  _krb_swap_tmp),2); \
 x = _krb_swap_tmp[0];   \
                           }

/*
 * New byte swapping routines, much cleaner.
 *
 * Should also go away soon though.
 */
#include "k5-platform.h"

#ifdef SWAP16
#define krb4_swab16(val)	SWAP16(val)
#else
#define krb4_swab16(val)	((((val) >> 8)&0xFF) | ((val) << 8))
#endif
#ifdef SWAP32
#define krb4_swap32(val)	SWAP32(val)
#else
#define krb4_swab32(val)	((((val)>>24)&0xFF) | (((val)>>8)&0xFF00) | \
				  (((val)<<8)&0xFF0000) | ((val)<<24))
#endif

/*
 * Macros to encode integers into buffers.  These take a parameter
 * that is a moving pointer of type (unsigned char *) into the buffer,
 * and assume that the caller has already bounds-checked.
 */
#define KRB4_PUT32BE(p, val)	(store_32_be(val, p), (p) += 4)
#define KRB4_PUT32LE(p, val)	(store_32_le(val, p), (p) += 4)
#define KRB4_PUT32(p, val, le)			\
do {						\
    if (le)					\
	KRB4_PUT32LE((p), (val));		\
    else					\
	KRB4_PUT32BE((p), (val));		\
} while (0)

#define KRB4_PUT16BE(p, val)	(store_16_be(val, p), (p) += 2)
#define KRB4_PUT16LE(p, val)	(store_16_le(val, p), (p) += 2)
#define KRB4_PUT16(p, val, le)			\
do {						\
    if (le)					\
	KRB4_PUT16LE((p), (val));		\
    else					\
	KRB4_PUT16BE((p), (val));		\
} while (0)

/*
 * Macros to get integers from a buffer.  These take a parameter that
 * is a moving pointer of type (unsigned char *) into the buffer, and
 * assume that the caller has already bounds-checked.  In addition,
 * they assume that val is an unsigned type; ANSI leaves the semantics
 * of unsigned -> signed conversion as implementation-defined, so it's
 * unwise to depend on such.
 */
#define KRB4_GET32BE(val, p)	((val) = load_32_be(p), (p) += 4)
#define KRB4_GET32LE(val, p)	((val) = load_32_le(p), (p) += 4)
#define KRB4_GET32(val, p, le)			\
do {						\
    if (le)					\
	KRB4_GET32LE((val), (p));		\
    else					\
	KRB4_GET32BE((val), (p));		\
} while (0)

#define KRB4_GET16BE(val, p)	((val) = load_16_be(p), (p) += 2)
#define KRB4_GET16LE(val, p)	((val) = load_16_le(p), (p) += 2)
#define KRB4_GET16(val, p, le)			\
do {						\
    if (le)					\
	KRB4_GET16LE((val), (p));		\
    else					\
	KRB4_GET16BE((val), (p));		\
} while (0)

/* Routines to create and read packets may be found in prot.c */

KTEXT create_auth_reply(char *, char *, char *, long, int, 
			unsigned long, int, KTEXT);
KTEXT create_death_packet(char *);
KTEXT pkt_cipher(KTEXT);

/* getst.c */
int krb4int_getst(int, char *, int);

/* strnlen.c */
extern int KRB5_CALLCONV krb4int_strnlen(const char *, int);

/* prot_client.c */
extern int KRB5_CALLCONV krb4prot_encode_kdc_request(
    char *, char *, char *,
    KRB4_32, int,
    char *, char *,
    char *, int, int, int,
    KTEXT);
extern int KRB5_CALLCONV krb4prot_decode_kdc_reply(
    KTEXT,
    int *,
    char *, char *, char *,
    long *, int *, unsigned long *, int *, KTEXT);
extern int KRB5_CALLCONV krb4prot_decode_ciph(
    KTEXT, int,
    C_Block,
    char *, char *, char *,
    int *, int *, KTEXT, unsigned long *);
extern int KRB5_CALLCONV krb4prot_encode_apreq(
    int, char *,
    KTEXT, KTEXT,
    int, int, KTEXT);
extern int KRB5_CALLCONV krb4prot_encode_authent(
    char *, char *, char *,
    KRB4_32,
    int, long,
    int, int le,
    KTEXT pkt);
extern int KRB5_CALLCONV krb4prot_decode_error(
    KTEXT, int *,
    char *, char *, char *,
    unsigned long *, unsigned long *, char *);

/* prot_common.c */
extern int KRB5_CALLCONV krb4prot_encode_naminstrlm(
    char *, char *, char *,
    int, KTEXT, unsigned char **);
extern int KRB5_CALLCONV krb4prot_decode_naminstrlm(
    KTEXT, unsigned char **,
    char *, char *, char *);
extern int KRB5_CALLCONV krb4prot_decode_header(
    KTEXT, int *, int *, int *);

/* prot_kdc.c */
extern int KRB5_CALLCONV krb4prot_encode_kdc_reply(
    char *, char *, char *,
    long, int, unsigned long,
    int, KTEXT, int, int, KTEXT);
extern int KRB5_CALLCONV krb4prot_encode_ciph(
    C_Block,
    char *, char *, char *,
    unsigned long, int, KTEXT, unsigned long,
    int, int, KTEXT);
extern int KRB5_CALLCONV krb4prot_encode_tkt(
    unsigned int,
    char *, char *, char *,
    unsigned long,
    char *, int, long,
    char *, char *,
    int, int, KTEXT tkt);
extern int KRB5_CALLCONV krb4prot_encode_err_reply(
    char *, char *, char *,
    unsigned long, unsigned long, char *,
    int, int, KTEXT);
extern int KRB5_CALLCONV krb4prot_decode_kdc_request(
    KTEXT,
    int *, char *, char *, char *,
    long *, int *, char *sname, char *sinst);

/* Message types , always leave lsb for byte order */

#define		AUTH_MSG_KDC_REQUEST			 1<<1
#define 	AUTH_MSG_KDC_REPLY			 2<<1
#define		AUTH_MSG_APPL_REQUEST			 3<<1
#define		AUTH_MSG_APPL_REQUEST_MUTUAL		 4<<1
#define		AUTH_MSG_ERR_REPLY			 5<<1
#define		AUTH_MSG_PRIVATE			 6<<1
#define		AUTH_MSG_SAFE				 7<<1
#define		AUTH_MSG_APPL_ERR			 8<<1
#define 	AUTH_MSG_DIE				63<<1

/* values for kerb error codes */

#define		KERB_ERR_OK				 0
#define		KERB_ERR_NAME_EXP			 1
#define		KERB_ERR_SERVICE_EXP			 2
#define		KERB_ERR_AUTH_EXP			 3
#define		KERB_ERR_PKT_VER			 4
#define		KERB_ERR_NAME_MAST_KEY_VER		 5
#define		KERB_ERR_SERV_MAST_KEY_VER		 6
#define		KERB_ERR_BYTE_ORDER			 7
#define		KERB_ERR_PRINCIPAL_UNKNOWN		 8
#define		KERB_ERR_PRINCIPAL_NOT_UNIQUE		 9
#define		KERB_ERR_NULL_KEY			10
/* Cygnus extensions for Preauthentication */
#define         KERB_ERR_PREAUTH_SHORT			11
#define		KERB_ERR_PREAUTH_MISMATCH		12

/* Return codes from krb4prot_ encoders/decoders */

#define		KRB4PROT_OK				0
#define		KRB4PROT_ERR_UNDERRUN			1
#define		KRB4PROT_ERR_OVERRUN			2
#define		KRB4PROT_ERR_PROT_VERS			3
#define		KRB4PROT_ERR_MSG_TYPE			4
#define		KRB4PROT_ERR_GENERIC			255

#endif /* PROT_DEFS */
