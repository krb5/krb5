/*
 * lib/krb5/os/ccdefname.c
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
 * Return default cred. cache name.
 */

#define NEED_WINDOWS
#include "k5-int.h"
#include <stdio.h>

#if defined(_WIN32)
static int get_from_registry(char *name_buf, int name_size)
{
	/* If the RegKRB5CCNAME variable is set, it will point to
	 * the registry key that has the name of the cache to use.
	 * The Gradient PC-DCE sets the registry key
	 * [HKEY_CURRENT_USER\Software\Gradient\DCE\Default\KRB5CCNAME]
	 * to point at the cache file name (including the FILE: prefix).
	 * By indirecting with the RegKRB5CCNAME entry in kerberos.ini,
	 * we can accomodate other versions that might set a registry
	 * variable.
	 */
	char newkey[256];
	    
	LONG name_buf_size;
	HKEY hkey;
	DWORD ipType;
	int found = 0;
	char *cp;

	GetPrivateProfileString(INI_FILES, "RegKRB5CCNAME", "", 
				newkey, sizeof(newkey), KERBEROS_INI);
	if (!newkey[0])
		return 0;
	
	cp = strrchr(newkey,'\\');
	if (cp) {
		*cp = '\0'; /* split the string */
		cp++;
	} else
		cp = "";
	
	if (RegOpenKeyEx(HKEY_CURRENT_USER, newkey, 0,
			 KEY_QUERY_VALUE, &hkey) != ERROR_SUCCESS)
		return 0;
	
	name_buf_size = name_size;
	if (RegQueryValueEx(hkey, cp, 0, &ipType, 
			    name_buf, &name_buf_size) != ERROR_SUCCESS)
			return 0;
	
	return 1;
}
#endif

#ifdef macintosh
static krb5_error_code get_from_os(char *name_buf, int name_size)
{
#if defined(_WIN32)
	if (get_from_registry(name_buf, name_size))
		return 0;
#endif
	strcpy(name_buf, "API:default_cache_name");
	return 0;
}
#endif

#if defined(_MSDOS) || defined(_WIN32)
static krb5_error_code get_from_os(char *name_buf, int name_size)
{
	char defname[160];                  /* Default value */

	strcpy (defname, "default_cache_name");
	strcpy (name_buf, "API:");
	GetPrivateProfileString(INI_FILES, INI_KRB_CCACHE, defname,
				name_buf+4, name_size-4, KERBEROS_INI);
	return 0;
}
#endif

#if !(defined(_MSDOS) || defined(_WIN32) || defined(macintosh))
static krb5_error_code get_from_os(char *name_buf, int name_size)
{
	sprintf(name_buf, "FILE:/tmp/krb5cc_%d", getuid());
	return 0;
}
#endif


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cc_set_default_name(context, name)
	krb5_context context;
	const char *name;
{
	char name_buf[1024];
	char *new_name;
	krb5_error_code retval;
	krb5_os_context os_ctx;

	os_ctx = context->os_context;
	
	if (!name)
		name = getenv(KRB5_ENV_CCNAME);

	if (name) {
		strncpy(name_buf, name, sizeof(name_buf));
		name_buf[sizeof(name_buf)-1] = 0;
	} else {
		retval = get_from_os(name_buf, sizeof(name_buf));
		if (retval)
			return retval;
	}
	new_name = malloc(strlen(name_buf)+1);
	if (!new_name)
		return ENOMEM;
	strcpy(new_name, name_buf);
	
	if (os_ctx->default_ccname)
		free(os_ctx->default_ccname);

	os_ctx->default_ccname = new_name;
	return 0;
}

	
KRB5_DLLIMP const char FAR * KRB5_CALLCONV
krb5_cc_default_name(context)
    krb5_context context;
{
	krb5_os_context os_ctx;

	os_ctx = context->os_context;
	if (!os_ctx->default_ccname)
		krb5_cc_set_default_name(context, NULL);

	return(os_ctx->default_ccname);
}
    
