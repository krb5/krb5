/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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
static char sccsid[] = "@(#)memcmp.c	5.5 (Berkeley) 5/15/90";
static char sccsid[] = "@(#)memcpy.c	5.6 (Berkeley) 5/15/90";
static char sccsid[] = "@(#)memmove.c	5.2 (Berkeley) 5/15/90";
static char sccsid[] = "@(#)memset.c	5.5 (Berkeley) 5/15/90";
#endif /* LIBC_SCCS and not lint */

#ifndef	__STDC__
#define	const
#endif
typedef int size_t;

/*
 * Compare memory regions.
 */
int
memcmp(s1, s2, n)
	const void *s1, *s2;
	size_t n;
{
	if (n != 0) {
		register const unsigned char *p1 = (unsigned char *)s1,
						*p2 = (unsigned char *)s2;

		do {
			if (*p1++ != *p2++)
				return(*--p1 - *--p2);
		} while (--n != 0);
	}
	return(0);
}

/*
 * Copy a block of memory.
 */
void *
memcpy(dst, src, n)
	void *dst;
	const void *src;
	size_t n;
{
	bcopy((const char *)src, (char *)dst, n);
	return(dst);
}

/*
 * Copy a block of memory, handling overlap.
 */
void *
memmove(dst, src, length)
	void *dst;
	const void *src;
	register size_t length;
{
	bcopy((const char *)src, (char *)dst, length);
	return(dst);
}

void *
memset(dst, c, n)
	void *dst;
	register int c;
	register size_t n;
{

	if (n != 0) {
		register char *d = (char *)dst;

		do
			*d++ = c;
		while (--n != 0);
	}
	return(dst);
}
