/* serror.c - get system error */

/* 
 * isode/compat/serror.c
 */

/*
 *				  NOTICE
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

/*    DATA */

extern	int sys_nerr;
extern  char *sys_errlist[];

/*  */

char   *sys_errname (i)
int	i;
{
    static char buffer[30];

    if (0 < i && i < sys_nerr)
	return sys_errlist[i];
    (void) sprintf (buffer, "Error %d", i);

    return buffer;
}
