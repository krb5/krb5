/* qb_free.c - free a list of qbufs */

/* 
 * isode/psap/qb_free.c
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

int	qb_free (qb)
register struct qbuf *qb;
{
    QBFREE (qb);

    free ((char *) qb);
}
