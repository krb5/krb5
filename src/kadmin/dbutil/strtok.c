/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.1  1996/08/01 18:39:54  bjaspan
 * 	* Makefile.in, Makefile.ov, configure.in, dump.c: add support for
 *         dump/load of OV*Secure-compatible format.
 *
 * Revision 1.1.2.1  1996/06/20  21:49:01  marc
 * File added to the repository on a branch
 *
 * Revision 1.1  1993/11/14  23:51:23  shanzer
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif


/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)strtok.c	5.7 (Berkeley) 6/1/90";
#endif /* LIBC_SCCS and not lint */

#include <stddef.h>
#include <string.h>

/*
 * Function: nstrtok
 * 
 * Purpose: the same as strtok ... just different. does not deal with
 *	    multiple tokens in row.
 *
 * Arguments:
 *	s	    (input) string to scan
 *	delim	    (input) list of delimiters
 * 	<return value> string or null on error.
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	sets last to string
 *
 * Modifies:
 *	last
 * 
 */

char *
nstrtok(s, delim)
	register char *s, *delim;
{
	register char *spanp;
	register int c, sc;
	char *tok;
	static char *last;


	if (s == NULL && (s = last) == NULL)
		return (NULL);

	/*
	 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
	 */
#ifdef OLD	 
cont:
	c = *s++;
	for (spanp = delim; (sc = *spanp++) != 0;) {
		if (c == sc)
			goto cont;
	}

	if (c == 0) {		/* no non-delimiter characters */
		last = NULL;
		return (NULL);
	}
	tok = s - 1;
#else
	tok = s;
#endif	

	/*
	 * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
	 * Note that delim must have one NUL; we stop if we see that, too.
	 */
	for (;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				last = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

