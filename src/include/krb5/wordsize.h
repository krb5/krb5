/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Word-size related definition.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_WORDSIZE__
#define __KRB5_WORDSIZE__

#ifdef BITS16
#define __OK
typedef	int	int16;
typedef	long	int32;
typedef	unsigned char	octet;
#endif

#ifdef BITS32
#define __OK
typedef	short	int16;
typedef	int	int32;
typedef	unsigned char	octet;
#endif

#ifndef __OK
 Error:  must define word size!
#endif /* __OK */

#undef __OK

#endif /* __KRB5_WORDSIZE__ */
