/*
 * include/krb5/wordsize.h
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 *
 * Word-size related definition.
 */


#ifndef KRB5_WORDSIZE__
#define KRB5_WORDSIZE__

#ifdef BITS16
#define __OK
typedef	int	krb5_int16;
typedef	long	krb5_int32;

typedef	unsigned char	krb5_octet;
typedef	unsigned char	krb5_ui_1;
typedef	unsigned int	krb5_ui_2;
typedef	unsigned long	krb5_ui_4;
#endif

#ifdef BITS32
#define __OK
typedef	short	krb5_int16;
typedef	int	krb5_int32;
typedef	unsigned char	krb5_octet;
typedef	unsigned char	krb5_ui_1;
typedef	unsigned short	krb5_ui_2;
typedef	unsigned int	krb5_ui_4;
#endif

#ifdef NOT_RIGHT_YET
/*
 * Incorporated from the Sandia changes; but this can't be right; if
 * we're on a 64 bit machine, an int shouldn't be 32 bits!?!
 * [tytso:19920616.2224EDT]
 */
#ifdef BITS64
#define __OK
typedef	short	krb5_int16;
typedef	int	krb5_int32;
typedef	unsigned char	krb5_octet;
typedef	unsigned char	krb5_ui_1;
typedef	unsigned short	krb5_ui_2;
typedef	unsigned int	krb5_ui_4;
#endif
#endif	/* NOT RIGHT YET */

#ifndef __OK
 ?==error:  must define word size!
#endif /* __OK */

#undef __OK

#define KRB5_INT32_MAX	2147483647
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KRB5_INT32_MIN	(-KRB5_INT32_MAX-1)

#endif /* KRB5_WORDSIZE__ */
