/* Copyright 1994 Cygnus Support */
/* Mark W. Eichin */
/*
 * Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation.
 * Cygnus Support makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* common code for looking at krb.conf and krb.realms file */
/* this may be superceded by <gnu>'s work for the Mac port, but
   it solves a problem for now. */

#include <stdio.h>
#include <krb.h>

FILE*
krb__get_cnffile()
{
	char *s;
	FILE *cnffile = 0;
	extern char *getenv();

	s = getenv("KRB_CONF");
	if (s) cnffile = fopen(s,"r");
	if (!cnffile) cnffile = fopen(KRB_CONF,"r");
#ifdef ATHENA_CONF_FALLBACK
	if (!cnffile) cnffile = fopen(KRB_FB_CONF,"r");
#endif
	return cnffile;
}


FILE*
krb__get_realmsfile()
{
	FILE *realmsfile;

	realmsfile = fopen(KRB_RLM_TRANS, "r");

#ifdef ATHENA_CONF_FALLBACK
	if (realmsfile == (FILE *) 0)
	    realmsfile = fopen(KRB_FB_RLM_TRANS, "r");
#endif

	return realmsfile;
}


