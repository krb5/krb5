/* putenv.c - generic putenv() */

/* 
 * isode/compat/putenv.c
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

/*  */

extern  char **environ;
static nvmatch ();

/*  */

int     setenv (name, value)
register char  *name,
               *value;
{
    register int    i;
    register char **ep,
                  **nep,
                   *cp;

    if ((cp = malloc ((unsigned) (strlen (name) + strlen (value) + 2)))
	    == NULL)
	return 1;
    (void) sprintf (cp, "%s=%s", name, value);

    for (ep = environ, i = 0; *ep; ep++, i++)
	if (nvmatch (name, *ep)) {
	    *ep = cp;
	    return 0;
	}

    if ((nep = (char **) malloc ((unsigned) ((i + 2) * sizeof *nep)))
	    == NULL) {
	free (cp);
	return 1;
    }
    for (ep = environ, i = 0; *ep; nep[i++] = *ep++)
	continue;
    nep[i++] = cp;
    nep[i] = NULL;
    environ = nep;
    return 0;
}

/*  */

int	unsetenv (name)
char   *name;
{
    char  **ep,
          **nep;

    for (ep = environ; *ep; ep++)
	if (nvmatch (name, *ep))
	    break;
    if (*ep == NULL)
	return 1;

    for (nep = ep + 1; *nep; nep++)
	continue;
    *ep = *--nep;
    *nep = NULL;
    return 0;
}

/*  */

static nvmatch (s1, s2)
register char  *s1,
               *s2;
{
    while (*s1 == *s2++)
	if (*s1++ == '=')
	    return 1;

    return (*s1 == '\0' && *--s2 == '=');
}
