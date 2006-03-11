/*
 * gethostname.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "krb4int.h"
#include "autoconf.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef	GETHOSTNAME
#define	GETHOSTNAME	gethostname	/* A rather simple default */
#endif

/*
 * Return the local host's name in "name", up to "namelen" characters.
 * "name" will be null-terminated if "namelen" is big enough.
 * The return code is 0 on success, -1 on failure.  (The calling
 * interface is identical to BSD gethostname(2).)
 */

int
k_gethostname(name, namelen)
    char *name;
    int namelen;
{
    return GETHOSTNAME(name, namelen);
}
