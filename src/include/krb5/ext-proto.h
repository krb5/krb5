/*
 * include/krb5/ext-proto.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * Prototypes for external (libc) funtions.
 */


#ifndef KRB5_EXT_PROTO__
#define KRB5_EXT_PROTO__

#ifdef HAS_STDLIB_H
#include <stdlib.h>
#else
#if defined(__STDC__) || defined(_WINDOWS)
#ifdef NO_STDLIB_H
#include <fake-stdlib.h>
#else
#include <stdlib.h>
#endif /* NO_STDLIB_H */
#else
extern char *malloc(), *realloc(), *calloc();
extern char *getenv();
#endif /* ! __STDC__ */
#endif /* HAS_STDLIB_H */

#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#ifndef HAS_STRDUP
extern char *strdup KRB5_PROTOTYPE((const char *));
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#endif /* KRB5_EXT_PROTO__ */
