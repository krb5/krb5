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
#include "krb4int.h"

krb5_context krb5__krb4_context = 0;

static FILE*
krb__v5_get_file(s)
     const char *s;
{
	FILE *cnffile = 0;
	const char* names[3];
	char **full_name = 0, **cpp;
	krb5_error_code retval;

	if (!krb5__krb4_context)
		krb5_init_context(&krb5__krb4_context);
	names[0] = "libdefaults";
	names[1] = s;
	names[2] = 0;
	if (krb5__krb4_context) {
	    retval = profile_get_values(krb5__krb4_context->profile, names, 
					&full_name);
	    if (retval == 0 && full_name && full_name[0]) {
		cnffile = fopen(full_name[0],"r");
		if (cnffile)
		    set_cloexec_file(cnffile);
		for (cpp = full_name; *cpp; cpp++) 
		    krb5_xfree(*cpp);
		krb5_xfree(full_name);
	    }
	}
	return cnffile;
}

char *
krb__get_srvtabname(default_srvtabname)
	const char *default_srvtabname;
{
	const char* names[3];
	char **full_name = 0, **cpp;
	krb5_error_code retval;
	static char retname[MAXPATHLEN];

	if (!krb5__krb4_context)
		krb5_init_context(&krb5__krb4_context);
	names[0] = "libdefaults";
	names[1] = "krb4_srvtab";
	names[2] = 0;
	if (krb5__krb4_context) {
	    retval = profile_get_values(krb5__krb4_context->profile, names, 
					&full_name);
	    if (retval == 0 && full_name && full_name[0]) {
		retname[0] = '\0';
		strncat(retname, full_name[0], sizeof(retname));
		for (cpp = full_name; *cpp; cpp++) 
		    krb5_xfree(*cpp);
		krb5_xfree(full_name);
		return retname;
	    }
	}
	retname[0] = '\0';
	strncat(retname, default_srvtabname, sizeof(retname));
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
	if (cnffile)
	    set_cloexec_file(cnffile);
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

	if (realmsfile)
	    set_cloexec_file(realmsfile);

	return realmsfile;
}
