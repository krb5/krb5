/*
 * include/kerberosIV/des.h
 *
 * Copyright 1987, 1988, 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Include file for the Data Encryption Standard library.
 */

/* only do the whole thing once	 */
#ifndef DES_DEFS
#define DES_DEFS

#if defined(_WIN32) && !defined(_WINDOWS)
#define _WINDOWS
#endif

#if defined(_WINDOWS)
#ifndef KRB4
#define KRB4 1
#endif
#include <win-mac.h>
#endif
#ifdef __STDC__
#include <limits.h>
#endif
#include <stdio.h> /* need FILE for des_cblock_print_file */

/* Windows declarations */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define GSS_DLLIMP
#define KRB5_EXPORTVAR
#endif
#ifndef FAR
#define FAR
#define NEAR
#endif

#ifndef KRB4_32
#ifdef SIZEOF_INT
#if SIZEOF_INT >= 4
#define KRB4_32 int
#else  /* !(SIZEOF_INT >= 4) */
#define KRB4_32 long
#endif /* !(SIZEOF_INT >= 4) */
#else  /* !defined(SIZEOF_INT) */
#ifdef __STDC__
#if INT_MAX >= 0x7fffffff
#define KRB4_32 int
#else  /* !(INT_MAX >= 0x7ffffff) */
#define KRB4_32 long
#endif /* !(INT_MAX >= 0x7ffffff) */
#else  /* !defined(__STDC__) */
#define KRB4_32 long		/* worst case */
#endif /* !defined(__STDC__) */
#endif /* !defined(SIZEOF_INT) */
#endif /* !defined(KRB4_32) */

/* Key schedule */
/* Ick.  We need this in here unfortunately... */
#ifndef DES_INT32
#define DES_INT32 KRB4_32
#endif

/*
 *
 * NOTE WELL:
 *
 * This section must be kept in sync with lib/crypto/des/des_int.h,
 * until we get around to actually combining them at the source level.
 * We can't right now, because both the Mac and Windows platforms are
 * using their own versions of krb4 des.h, and that's the one that
 * would have to have the definitions because we install it under UNIX.
 *
 */
#ifndef KRB5INT_DES_TYPES_DEFINED
#define KRB5INT_DES_TYPES_DEFINED
typedef unsigned char des_cblock[8];	/* crypto-block size */
typedef struct des_ks_struct {  DES_INT32 _[2]; } des_key_schedule[16];
#endif
/* end sync */

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#ifndef NCOMPAT
#define C_Block des_cblock
#define Key_schedule des_key_schedule
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define key_sched des_key_sched
#define cbc_encrypt des_cbc_encrypt
#define cbc_cksum des_cbc_cksum
#define C_Block_print des_cblock_print
#define quad_cksum des_quad_cksum
typedef struct des_ks_struct bit_64;
#endif

#define des_cblock_print(x) des_cblock_print_file(x, stdout)


/*
 * Function Prototypes
 */

KRB5_DLLIMP int KRB5_CALLCONV des_key_sched (C_Block, Key_schedule);

KRB5_DLLIMP int KRB5_CALLCONV
des_pcbc_encrypt (C_Block FAR *in, C_Block FAR *out, long length,
		  Key_schedule schedule, C_Block FAR *ivec, int encrypt);

KRB5_DLLIMP unsigned long KRB5_CALLCONV
des_quad_cksum (unsigned char FAR *in, unsigned KRB4_32 FAR *out,
		long length, int out_count, C_Block FAR *seed);

KRB5_DLLIMP int KRB5_CALLCONV des_string_to_key (char FAR *, C_Block);

/* new */
#ifdef KRB5_GENERAL__
KRB5_DLLIMP void KRB5_CALLCONV
des_cbc_cksum(krb5_octet *, krb5_octet *, unsigned long,
	      des_key_schedule, krb5_octet *);
int des_cbc_encrypt(krb5_octet *, krb5_octet *, unsigned long,
		    des_key_schedule, krb5_octet *, int);
krb5_error_code des_read_password(des_cblock *, char *, int);
#endif
KRB5_DLLIMP int KRB5_CALLCONV des_ecb_encrypt(unsigned long *, unsigned long *,
					      des_key_schedule, int);
void des_fixup_key_parity(des_cblock);
int des_check_key_parity(des_cblock);
KRB5_DLLIMP int KRB5_CALLCONV des_new_random_key(des_cblock);
void des_init_random_number_generator(des_cblock);
int des_random_key(des_cblock *);
int des_is_weak_key(des_cblock);
void des_cblock_print_file(des_cblock *, FILE *fp);

#endif	/* DES_DEFS */
