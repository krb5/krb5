/* str2ps.c - string-backed abstraction for PStreams */

/* 
 * isode/psap/str2ps.c
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
#include "psap.h"

/*  */

/* ARGSUSED */

static int str_read (ps, data, n, in_line)
register PS	ps;
PElementData data;
PElementLen n;
int	in_line;
{
    register int    cc;

    if (ps -> ps_base == NULLCP || (cc = ps -> ps_cnt) <= 0)
	return 0;
    if (cc > n)
	cc = n;

    memcpy ((char *) data, ps -> ps_ptr, cc);
    ps -> ps_ptr += cc, ps -> ps_cnt -= cc;

    return cc;
}


/* ARGSUSED */

static int str_write (ps, data, n, in_line)
register PS	ps;
PElementData data;
PElementLen n;
int	in_line;
{
    register int    cc;
    register char  *cp;

    if (ps -> ps_base == NULLCP) {
	if ((cp = malloc ((unsigned) (cc = n + BUFSIZ))) == NULLCP)
	    return ps_seterr (ps, PS_ERR_NMEM, NOTOK);
	ps -> ps_base = ps -> ps_ptr = cp;
	ps -> ps_bufsiz = ps -> ps_cnt = cc;
    }
    else
	if (ps -> ps_cnt < n) {
	    register int    curlen = ps -> ps_ptr - ps -> ps_base;

	    if (ps -> ps_inline) {
		n = ps -> ps_cnt;
		goto partial;
	    }

	    if ((cp = realloc (ps -> ps_base,
				      (unsigned) (ps -> ps_bufsiz
						  + (cc = n + BUFSIZ))))
		    == NULLCP)
		return ps_seterr (ps, PS_ERR_NMEM, NOTOK);
	    ps -> ps_ptr = (ps -> ps_base = cp) + curlen;
	    ps -> ps_bufsiz += cc, ps -> ps_cnt += cc;
	}
partial: ;

    memcpy (ps -> ps_ptr, (char *) data, n);
    ps -> ps_ptr += n, ps -> ps_cnt -= n;

    return n;
}


static int str_close (ps)
register PS	ps;
{
    if (ps -> ps_base && !ps -> ps_inline)
	free (ps -> ps_base);

    return OK;
}

/*  */

int	str_open (ps)
register PS	ps;
{
    ps -> ps_readP = str_read;
    ps -> ps_writeP = str_write;
    ps -> ps_closeP = str_close;

    return OK;
}


int	str_setup (ps, cp, cc, in_line)
register PS	ps;
register char  *cp;
register int	cc;
int	in_line;
{
    register char  *dp;

    if (in_line) {
	ps -> ps_inline = 1;
	ps -> ps_base = ps -> ps_ptr = cp;
	ps -> ps_bufsiz = ps -> ps_cnt = cc;
    }
    else
	if (cc > 0) {
	    if ((dp = malloc ((unsigned) (cc))) == NULLCP)
		return ps_seterr (ps, PS_ERR_NMEM, NOTOK);
	    ps -> ps_base = ps -> ps_ptr = dp;
	    if (cp != NULLCP)
		memcpy (dp, cp, cc);
	    ps -> ps_bufsiz = ps -> ps_cnt = cc;
	}

    return OK;
}
