/* pe2ssdu.c - write a PE to a SSDU */

/* 
 * isode/psap/pe2ssdu.c
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
#include "tailor.h"

/*  */

int	pe2ssdu (pe, base, len)
register PE pe;
char  **base;
int    *len;
{
    register int plen, ret;

    *len = 0;
    plen  = ps_get_abs (pe);
    Qcp = (char *)malloc((unsigned)plen);
    *base = Qcp;

    if (Qcp == NULL)
        return NOTOK;

    Len = 0;
    Ecp = Qcp + plen;
    if ((ret = pe2qb_f(pe)) != plen) {
        (void) printf("pe2ssdu: bad length returned %d should be %d\n",
                ret, plen);
	return NOTOK;
    }
    *len = plen;

#ifdef	DEBUG
    if (psap_log -> ll_events & LLOG_PDUS)
	pe2text (psap_log, pe, 0, *len);
#endif

    return OK;
}
