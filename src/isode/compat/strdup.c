/* strdup.c - create a duplicate copy of the given string */

/*
 * isode/compat/strdup.c
 */

/*
 *                                NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


/* LINTLIBRARY */

#include <stdio.h>
#include "general.h"
#include "manifest.h"
#include "tailor.h"

/*  */
#if (!defined(SVR4) && !defined(linux))

char   *strdup (str)
register char   *str;
{
	register char *ptr;

	if ((ptr = malloc((unsigned) (strlen (str) + 1))) == NULL){
	    LLOG (compat_log,LLOG_FATAL, ("strdup malloc() failure"));
	    abort ();
	    /* NOTREACHED */
	}

	(void) strcpy (ptr, str);

	return ptr;
}

#else

strdup_stub ()
{;}

#endif
