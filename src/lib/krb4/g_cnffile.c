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
#include "krb.h"
#include "k5-int.h"

static FILE*
krb__v5_get_file(s)
     char *s;
{
	FILE *cnffile = 0;
	krb5_context context;
	const char* names[3];
	char **full_name = 0, **cpp;
	krb5_error_code retval;

	krb5_init_context(&context);
	names[0] = "libdefaults";
	names[1] = s;
	names[2] = 0;
	if (context) {
	    retval = profile_get_values(context->profile, names, &full_name);
	    if (retval == 0 && full_name && full_name[0]) {
		cnffile = fopen(full_name[0],"r");
		for (cpp = full_name; *cpp; cpp++) 
		    krb5_xfree(*cpp);
		krb5_xfree(full_name);
	    }
	    krb5_free_context(context);
	}
	return cnffile;
}

char *
krb__get_srvtabname(default_srvtabname)
	char *default_srvtabname;
{
	krb5_context context;
	const char* names[3];
	char **full_name = 0, **cpp;
	krb5_error_code retval;
	char *retname;

	krb5_init_context(&context);
	names[0] = "libdefaults";
	names[1] = "krb4_srvtab";
	names[2] = 0;
	if (context &&
	    (retval = profile_get_values(context->profile, names, &full_name))
	    && retval == 0 && full_name && full_name[0]) {
	    retname = strdup(full_name[0]);
	    for (cpp = full_name; *cpp; cpp++) 
		krb5_xfree(*cpp);
	    krb5_xfree(full_name);
	}else {
	    retname = strdup(default_srvtabname);
	}
	if (context != NULL)
		krb5_free_context(context);
	return retname;
}

FILE*
krb__get_cnffile()
{
	char *s;
	FILE *cnffile = 0;
	extern char *getenv();

	/* standard V4 override first */
	s = getenv("KRB_CONF");
	if (s) cnffile = fopen(s,"r");
	/* if that's wrong, use V5 config */
	if (!cnffile) cnffile = krb__v5_get_file("krb4_config");
	/* and if V5 config doesn't have it, go to hard-coded values */
	if (!cnffile) cnffile = fopen(KRB_CONF,"r");
#ifdef ATHENA_CONF_FALLBACK
	if (!cnffile) cnffile = fopen(KRB_FB_CONF,"r");
#endif
	return cnffile;
}


FILE*
krb__get_realmsfile()
{
	FILE *realmsfile = 0;
	char *s;

	/* standard (not really) V4 override first */
	s = getenv("KRB_REALMS");
	if (s) realmsfile = fopen(s,"r");
	if (!realmsfile) realmsfile = krb__v5_get_file("krb4_realms");
	if (!realmsfile) realmsfile = fopen(KRB_RLM_TRANS, "r");

#ifdef ATHENA_CONF_FALLBACK
	if (!realmsfile) realmsfile = fopen(KRB_FB_RLM_TRANS, "r");
#endif

	return realmsfile;
}


