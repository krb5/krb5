#pragma once

/*-
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement:  ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)encrypt.h	5.1 (Berkeley) 2/28/91
 */

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Export of this software from the United States of America is assumed
 * to require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

#ifndef	__ENCRYPT__
#define	__ENCRYPT__

#define	DIR_DECRYPT		1
#define	DIR_ENCRYPT		2

typedef	unsigned char Block[8];
typedef unsigned char *BlockT;
typedef struct { Block _; } Schedule[16];

#define	VALIDKEY(key)	( key[0] | key[1] | key[2] | key[3] | \
			  key[4] | key[5] | key[6] | key[7])

#define	SAMEKEY(k1, k2)	(!bcmp((void *)k1, (void *)k2, sizeof(Block)))

typedef	struct {
	short		type;
	long		length;
	unsigned char	*data;
} Session_Key;

#define P(x)	x

typedef struct {
	char *name;
	long	type;
	void (*output) (void *, unsigned char *, long);
	long	(*input) (void *, long);
	void (*init) (void *, long);
	long	(*start) (void *, long, long);
	long	(*is) (void *, unsigned char *, long);
	long	(*reply) (void *, unsigned char *, long);
	void (*session) (void *, Session_Key *, long);
	long	(*keyid) (void *, long, unsigned char *, long *);
	void (*printsub) (unsigned char *, long, unsigned char *, long);
} Encryptions;

#define	SK_DES		1	/* Matched Kerberos v5 KEYTYPE_DES */

extern long encrypt_debug_mode;

#ifdef notdef
extern long (*decrypt_input) P((long));
extern void (*encrypt_output) P((unsigned char *, long));
#endif
#endif

#define ENCTYPE_DES_CFB64	1
#define ENCTYPE_DES_OFB64	2
