/* pa2str.c - pretty-print PSAPaddr */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 * 
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
#include "isoaddrs.h"

/*    Presentation Address to String */

char   *pa2str (px)
register struct PSAPaddr *px;
{
    register char *bp;
    struct PSAPaddr pas;
    register struct PSAPaddr *pa = &pas;
    register struct TSAPaddr *ta = &pa -> pa_addr.sa_addr;
    static char buffer[BUFSIZ];

    bp = buffer;

    *pa = *px;	/* struct copy */
    if (ta -> ta_selectlen > 0
	    && ta -> ta_selectlen < sizeof ta -> ta_selector) {
	register char *dp,
		      *ep;
	register struct TSAPaddr *tz;
	register int n, m;

	/* does this look like an encoded TSEL? */
	m = ta -> ta_selectlen;
	n = ta -> ta_selector[0];
	if (m > 4 &&
	    ta -> ta_selector[0] == ta -> ta_selector[1] &&
	    n > 2 && n <= m - 2) 
	{						/* encoded! */
	    tz = &px -> pa_addr.sa_addr;
	    memset ((char *)ta, 0, sizeof *ta);
	    if ((ta -> ta_selectlen = m - n - 2) > 0)
		    memcpy (ta -> ta_selector, &tz -> ta_selector[n+2],
			    ta -> ta_selectlen);
	    if (norm2na (&tz -> ta_selector[2], n, ta -> ta_addrs) != OK) {
		    *pa = *px;
		    goto normal;
	    }
	    ta -> ta_naddr = 1;
	    goto bridge;
	}
	for (ep = (dp = ta -> ta_selector) + ta -> ta_selectlen, *ep = NULL;
	         dp < ep;
	         dp++)
	    if (!isprint ((u_char) *dp) && *dp != ' ')
		break;
	if (dp >= ep && (tz = str2taddr (ta -> ta_selector))) {
	    pa -> pa_addr.sa_addr = *tz;	    /* struct copy */
	bridge:
	    (void) sprintf (bp, "%s through TS bridge at ",
			    paddr2str (pa, NULLNA));
	    bp += strlen (bp);

	    memset ((char *) pa, 0, sizeof *pa);
	    *ta = px -> pa_addr.sa_addr;    /* struct copy */
	    ta -> ta_selectlen = 0;
	}
    }
normal:
    (void) strcpy (bp, paddr2str (pa, NULLNA));

    return buffer;
}
