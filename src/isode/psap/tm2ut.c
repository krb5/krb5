/* tm2ut.c - tm to time string */

/* 
 * isode/psap/tm2ut.c
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
#ifdef	OSX
#include <sys/time.h>
#endif


#define	YEAR(y)		((y) >= 100 ? (y) : (y) + 1900)

/*  */

void	tm2ut (tm, ut)
register struct tm *tm;
register UTC	ut;
{
    memset ((char *) ut, 0, sizeof *ut);

    ut -> ut_year = YEAR (tm -> tm_year);
    ut -> ut_mon = tm -> tm_mon + 1;
    ut -> ut_mday = tm -> tm_mday;
    ut -> ut_hour = tm -> tm_hour;
    ut -> ut_min = tm -> tm_min;
    ut -> ut_sec = tm -> tm_sec;
    ut -> ut_zone = 0;
    
    ut -> ut_flags = UT_ZONE | UT_SEC;
}
