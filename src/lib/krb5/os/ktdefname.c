/*
 * lib/krb5/os/ktdefname.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Return default keytab file name.
 */

#define NEED_WINDOWS

#include "k5-int.h"

krb5_error_code
krb5_kt_default_name(context, name, namesize)
    krb5_context context;
    char *name;
    int namesize;
{
    char *cp = 0;
    krb5_error_code code;
    char *retval;

    if (context->kt_default_name == NULL) {
	if ((context->profile_secure == FALSE) &&
	    (cp = getenv("KRB5_KTNAME"))) {
	    if ((context->kt_default_name = malloc(strlen(cp) + 1)) == NULL)
		return ENOMEM;
	    strcpy(context->kt_default_name, cp);
	} else if (((code = profile_get_string(context->profile,
					       "libdefaults",
					       "default_keytab_name", NULL, 
					       NULL, &cp)) == 0) && cp){
	    context->kt_default_name = cp;
	} else {
#if defined (_MSDOS) || defined(_WIN32)
	    {
		char    defname[160];
		int     len;
		
		len= GetWindowsDirectory( defname, sizeof(defname)-2 );
		defname[len]= '\0';
		if ((cp = malloc(strlen(DEFAULT_KEYTAB_NAME) + 1 + len))
		    == NULL)
		    return ENOMEM;
		sprintf(cp, DEFAULT_KEYTAB_NAME, defname);
		context->kt_default_name = cp;
	    }
#else
	    if ((cp = malloc(strlen(DEFAULT_KEYTAB_NAME) + 1)) == NULL)
		return ENOMEM;
	    strcpy(cp, DEFAULT_KEYTAB_NAME);
	    context->kt_default_name = cp;
#endif
	}
    }
    strncpy(name, context->kt_default_name, namesize);
    if ((size_t) namesize < strlen(context->kt_default_name))
	return KRB5_CONFIG_NOTENUFSPACE;
    return 0;
}

krb5_error_code
krb5_kt_set_default_name(context, name)
     krb5_context context;
     char *name;
{
    char *cp;
    if ((cp = malloc(strlen(name) + 1)) == NULL)
	return ENOMEM;
    else {
	strcpy(cp, name);
	if (context->kt_default_name)
	    free(context->kt_default_name);
	context->kt_default_name = cp;
	return 0;
    }
}
