/* pl_tables.c - tables for presentation lists */

#ifndef	lint
static char *rcsid = "$Header$";
#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:33:38  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/06/01 00:37:54  eichin
 * add psap too
 *
 * Revision 8.0  91/07/17  12:47:01  isode
 * Release 7.0
 * 
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

#include <stdio.h>
#include "psap.h"

/*    DATA */

char   *pe_classlist[] = {
    "UNIV",
    "APPL",
    "CONT",
    "PRIV"
};

int	pe_maxclass = sizeof pe_classlist / sizeof pe_classlist[0];


char   *pe_univlist[] = {
    "EOC",
    "BOOL",
    "INT",
    "BITS",
    "OCTS",
    "NULL",
    "OID",
    "ODE",
    "EXTN",
    "REAL",
    "ENUM",
    "ENCR",
    NULLCP,
    NULLCP,
    NULLCP,
    NULLCP,
    "SEQ",
    "SET",
    "NUMS",
    "PRTS",
    "T61S",
    "VTXS",
    "IA5S",
    "UTCT",
    "GENT",
    "GFXS",
    "VISS",
    "GENS",
    "CHRS",
};

int	pe_maxuniv = sizeof pe_univlist / sizeof pe_univlist[0];


int	pe_maxappl = 0;
char  **pe_applist = NULL;

int	pe_maxpriv = 0;
char  **pe_privlist = NULL;
