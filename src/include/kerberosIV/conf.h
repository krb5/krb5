/*
 * $Source$
 * $Author$
 * $Header$
 *
 * Copyright 1988, 1994 by the Massachusetts Institute of Technology.
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
 * Configuration info for operating system, hardware description,
 * language implementation, C library, etc.
 *
 * This file should be included in (almost) every file in the Kerberos
 * sources, and probably should *not* be needed outside of those
 * sources.  (How do we deal with /usr/include/des.h and
 * /usr/include/krb.h?)
 */

#ifndef _CONF_H_

#include "osconf.h"

#ifdef SHORTNAMES
#include "names.h"
#endif

/*
 * Language implementation-specific definitions
 */

/* special cases */
#ifdef __HIGHC__
/* broken implementation of ANSI C */
#undef __STDC__
#endif

#ifndef __STDC__
#define const
#define volatile
#define signed
typedef char *pointer;		/* pointer to generic data */
#define PROTOTYPE(p) ()
#else
typedef void *pointer;
#define PROTOTYPE(p) p
#endif

/* Does your compiler understand "void"? */
#ifdef notdef
#define void int
#endif

/*
 * A few checks to see that necessary definitions are included.
 */

/* byte order */

#ifndef MSBFIRST
#ifndef LSBFIRST
/* #error byte order not defined */
Error: byte order not defined.
#endif
#endif

/* machine size */
#ifndef BITS16
#ifndef BITS32
Error: how big is this machine anyways?
#endif
#endif

/* end of checks */

#endif /* _CONF_H_ */
