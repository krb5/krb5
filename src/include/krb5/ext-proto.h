/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Prototypes for external (libc) funtions.
 */


#ifndef KRB5_EXT_PROTO__
#define KRB5_EXT_PROTO__

#ifdef __STDC__
#ifdef NO_STDLIB_H
#include <fake-stdlib.h>
#else
#include <stdlib.h>
#endif /* NO_STDLIB_H */
#else
extern char *malloc(), *realloc(), *calloc();
extern char *getenv();
#endif /* ! __STDC__ */

#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

extern char *strdup PROTOTYPE((const char *));

#endif /* KRB5_EXT_PROTO__ */
