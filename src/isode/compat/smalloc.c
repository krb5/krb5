/* smalloc.c - error checking malloc */

/*
 * isode/compat/smalloc.c
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

char *
smalloc(size)
int	size;
{
	register char *ptr;

	if ((ptr = malloc((unsigned) size)) == NULL){
	    LLOG (compat_log,LLOG_FATAL, ("malloc() failure"));
	    abort ();
	    /* NOTREACHED */
	}

	return(ptr);
}
