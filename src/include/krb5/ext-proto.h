/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Prototypes for external (libc) funtions.
 */

#include <krb5/copyright.h>

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

#include <string.h>

#endif /* KRB5_EXT_PROTO__ */
