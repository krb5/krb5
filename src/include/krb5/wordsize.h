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

typedef	unsigned char	krb5_octet;
typedef	unsigned char	krb5_ui_1;

#if (SIZEOF_INT == 2)
typedef	int	krb5_int16;
typedef	unsigned int	krb5_ui_2;
#elif (SIZEOF_SHORT == 2)
typedef	short	krb5_int16;
typedef	unsigned short	krb5_ui_2;
#else
  ?==error: undefined 16 bit type
#endif

#if (SIZEOF_INT == 4)
typedef	int	krb5_int32;
typedef	unsigned int	krb5_ui_4;
#elif (SIZEOF_LONG == 4)
typedef	long	krb5_int32;
typedef	unsigned long	krb5_ui_4;
#elif (SIZEOF_SHORT == 4)
typedef	short	krb5_int32;
typedef	unsigned short	krb5_ui_4;
#else
 ?== error: undefined 32 bit type
#endif

#define KRB5_INT32_MAX	2147483647
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KRB5_INT32_MIN	(-KRB5_INT32_MAX-1)

#endif /* KRB5_WORDSIZE__ */
