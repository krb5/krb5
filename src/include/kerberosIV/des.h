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
 * permission.  M.I.T. makes no representations about the suitability of
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

#ifndef __alpha
#define KRB4_32	long
#else
#define KRB4_32	int
#endif


#ifndef PROTOTYPE
#if (defined(__STDC__) || defined(_WINDOWS)) && !defined(KRB5_NO_PROTOTYPES)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif
#endif



typedef unsigned char des_cblock[8];	/* crypto-block size */

/* Key schedule */
/* Ick.  We need this in here unfortunately... */
#ifndef DES_INT32
#ifdef SIZEOF_INT
#if SIZEOF_INT >= 4
#define DES_INT32 int
#else
#define DES_INT32 long
#endif
#else /* !defined(SIZEOF_INT) */
#include <limits.h>
#if (UINT_MAX >= 0xffffffff)
#define DES_INT32 int
#else
#define DES_INT32 long
#endif
#endif /* !defined(SIZEOF_INT) */
#endif /* !defined(DES_INT32) */

typedef struct des_ks_struct {  DES_INT32 _[2]; } des_key_schedule[16];

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

KRB5_DLLIMP int KRB5_CALLCONV
des_key_sched
	PROTOTYPE((C_Block, Key_schedule));

KRB5_DLLIMP int KRB5_CALLCONV
des_pcbc_encrypt
	PROTOTYPE((C_Block FAR *in, C_Block FAR *out, long length,
		   Key_schedule schedule, C_Block FAR *ivec, int encrypt));

KRB5_DLLIMP unsigned long KRB5_CALLCONV
des_quad_cksum
	PROTOTYPE((unsigned char FAR *in, unsigned KRB4_32 FAR *out,
		   long length, int out_count, C_Block FAR *seed));

KRB5_DLLIMP int KRB5_CALLCONV
des_string_to_key
	PROTOTYPE((char FAR *, C_Block));
#endif	/* DES_DEFS */
