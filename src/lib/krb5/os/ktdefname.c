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

extern char *krb5_defkeyname;

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_kt_default_name(context, name, namesize)
    krb5_context context;
    char FAR *name;
    int namesize;
{
    char *cp = 0;
    krb5_error_code code;
    char *retval;

    if ((context->profile_secure == FALSE) &&
	(cp = getenv("KRB5_KTNAME"))) {
	strncpy(name, cp, namesize);
	if (strlen(cp) >= (size_t) namesize)
	    return KRB5_CONFIG_NOTENUFSPACE;
    } else if (((code = profile_get_string(context->profile,
					   "libdefaults",
					   "default_keytab_name", NULL, 
					   NULL, &retval)) == 0) &&
	       retval) {
	strncpy(name, retval, namesize);
	if ((size_t) namesize < strlen(retval))
	    return KRB5_CONFIG_NOTENUFSPACE;
    } else {
#if defined (_MSDOS) || defined(_WIN32)
	{
	    char    defname[160];
	    int     len;

	    len= GetWindowsDirectory( defname, sizeof(defname)-2 );
	    defname[len]= '\0';
	    if ( (len + strlen(krb5_defkeyname) + 1) > namesize )
		return KRB5_CONFIG_NOTENUFSPACE;
	    sprintf(name, krb5_defkeyname, defname);
	}
#else
	strncpy(name, krb5_defkeyname, namesize);
	if ((size_t) namesize < strlen(krb5_defkeyname))
	    return KRB5_CONFIG_NOTENUFSPACE;
#endif
    }
    return 0;
}
    
