/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Prototypes for external (libc) funtions.
 */

#include <krb5/copyright.h>

#ifndef __EXT_PROTO__
#define __EXT_PROTO__

#ifdef __STDC__
#include <stdlib.h>
#else

extern char *malloc(), *index(), *calloc();

#include <string.h>

#endif /* ! __STDC__ */

#endif /* __EXT_PROTO__ */
