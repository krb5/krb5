/* str2sel.c - string to selector */

/* 
 * isode/compat/str2sel.c
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

#include <ctype.h>
#include <stdio.h>
#include "general.h"
#include "manifest.h"
#include "tailor.h"


#define	QUOTE	'\\'

/*    STR2SEL */

int	str2sel (s, quoted, sel, n)
char   *s,
       *sel;
int	quoted,
	n;
{
    int     i,
            r;
    register char  *cp;

    if (*s == NULL)
	return 0;

    if (quoted <= 0) {
	for (cp = s; *cp; cp++)
	    if (!isxdigit ((u_char) *cp))
		break;

	if (*cp == NULL && (i = (cp - s)) >= 2 && (i & 0x01) == 0) {
	    if (i > (r = n * 2))
		i = r;
	    i = implode ((u_char *) sel, s, i);
	    if ((r = (n - i)) > 0)
		memset (sel + i, 0, r);
	    return i;
	}
	if (*s == '#') {	/* gosip style, network byte-order */
	    i = atoi (s + 1);
	    sel[0] = (i >> 8) & 0xff;
	    sel[1] = i & 0xff;

	    return 2;
	}

	DLOG (compat_log, LLOG_EXCEPTIONS, ("invalid selector \"%s\"", s));
    }

    for (cp = sel; *s && n > 0; cp++, s++, n--)
	if (*s != QUOTE)
	    *cp = *s;
	else
	    switch (*++s) {
		case 'b':
		    *cp = '\b';
		    break;
		case 'f':
		    *cp = '\f';
		    break;
		case 'n':
		    *cp = '\n';
		    break;
		case 'r':
		    *cp = '\r';
		    break;
		case 't':
		    *cp = '\t';
		    break;

		case 0:
		    s--;
		case QUOTE: 
		    *cp = QUOTE;
		    break;

		default: 
		    if (!isdigit ((u_char) *s)) {
			*cp++ = QUOTE;
			*cp = *s;
			break;
		    }
		    r = *s != '0' ? 10 : 8;
		    for (i = 0; isdigit ((u_char) *s); s++)
			i = i * r + *s - '0';
		    s--;
		    *cp = toascii (i);
		    break;
	    }
    if (n > 0)
	*cp = NULL;

    return (cp - sel);
}
