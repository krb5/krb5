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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Return default cred. cache name.
 */

#define NEED_WINDOWS
#include "k5-int.h"
#include <stdio.h>

#if defined(USE_CCAPI)
#include <CredentialsCache.h>
#endif

#if defined(_WIN32)
static int get_from_registry_indirect(char *name_buf, int name_size)
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
	int found = 0;
	char *cp;

        newkey[0] = 0;
	GetPrivateProfileString(INI_FILES, "RegKRB5CCNAME", "", 
				newkey, sizeof(newkey), KERBEROS_INI);
	if (!newkey[0])
		return 0;
	
        newkey[sizeof(newkey)-1] = 0;
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
	if (RegQueryValueEx(hkey, cp, 0, 0, 
			    name_buf, &name_buf_size) != ERROR_SUCCESS)
	{
		RegCloseKey(hkey);
		return 0;
	}

	RegCloseKey(hkey);
	return 1;
}

/*
 * get_from_registry
 *
 * This will find the ccname in the registry.  Returns 0 on error, non-zero
 * on success.
 */

static int
get_from_registry(
    HKEY hBaseKey,
    char *name_buf, 
    int name_size
    )
{
    HKEY hKey;
    DWORD name_buf_size = (DWORD)name_size;
    const char *key_path = "Software\\MIT\\Kerberos5";
    const char *value_name = "ccname";

    if (RegOpenKeyEx(hBaseKey, key_path, 0, KEY_QUERY_VALUE, 
                     &hKey) != ERROR_SUCCESS)
        return 0;
    if (RegQueryValueEx(hKey, value_name, 0, 0, 
                        name_buf, &name_buf_size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);
    return 1;
}

#define APPEND_KRB5CC "\\krb5cc"

static int
try_dir(
    char* dir,
    char* buffer,
    int buf_len
    )
{
    struct _stat s;
    if (!dir)
        return 0;
    if (_stat(dir, &s))
        return 0;
    if (!(s.st_mode & _S_IFDIR))
        return 0;
    if (buffer != dir) {
        strncpy(buffer, dir, buf_len);
        buffer[buf_len-1]='\0';
    }
    strncat(buffer, APPEND_KRB5CC, buf_len-strlen(buffer));
    buffer[buf_len-1] = '\0';
    return 1;
}
#endif

#if defined(_WIN32)
static krb5_error_code get_from_os(char *name_buf, int name_size)
{
	char *prefix = krb5_cc_dfl_ops->prefix;
        int size;
        char *p;

	if (get_from_registry(HKEY_CURRENT_USER,
                              name_buf, name_size) != 0)
		return 0;

	if (get_from_registry(HKEY_LOCAL_MACHINE,
                              name_buf, name_size) != 0)
		return 0;

	if (get_from_registry_indirect(name_buf, name_size) != 0)
		return 0;

        strncpy(name_buf, prefix, name_size - 1);
        name_buf[name_size - 1] = 0;
        size = name_size - strlen(prefix);
        if (size > 0)
            strcat(name_buf, ":");
        size--;
        p = name_buf + name_size - size;
	if (!strcmp(prefix, "API")) {
		strncpy(p, "krb5cc", size);
	} else if (!strcmp(prefix, "FILE") || !strcmp(prefix, "STDIO")) {
		if (!try_dir(getenv("TEMP"), p, size) &&
		    !try_dir(getenv("TMP"), p, size))
		{
                    int len = GetWindowsDirectory(p, size);
                    name_buf[name_size - 1] = 0;
                    if (len < size - sizeof(APPEND_KRB5CC))
			strcat(p, APPEND_KRB5CC);
		}
	} else {
		strncpy(p, "default_cache_name", size);
	}
	name_buf[name_size - 1] = 0;
	return 0;
}
#endif

#if defined(USE_CCAPI)

static krb5_error_code get_from_os(char *name_buf, int name_size)
{
	krb5_error_code result = 0;
	cc_context_t cc_context = NULL;
	cc_string_t default_name = NULL;

	cc_int32 ccerr = cc_initialize (&cc_context, ccapi_version_3, NULL, NULL);
	if (ccerr == ccNoError) {
		ccerr = cc_context_get_default_ccache_name (cc_context, &default_name);
	}
	
	if (ccerr == ccNoError) {
		if (strlen (default_name -> data) + 5 > name_size) {
			result = ENOMEM;
			goto cleanup;
		} else {
			sprintf (name_buf, "API:%s", default_name -> data);
		}
	}
	
cleanup:
	if (cc_context != NULL) {
		cc_context_release (cc_context);
	}
	
	if (default_name != NULL) {
		cc_string_release (default_name);
	}
	
	return result;
}

#else
#if !(defined(_WIN32))
static krb5_error_code get_from_os(char *name_buf, int name_size)
{
	sprintf(name_buf, "FILE:/tmp/krb5cc_%ld", (long) getuid());
	return 0;
}
#endif
#endif

krb5_error_code KRB5_CALLCONV
krb5_cc_set_default_name(krb5_context context, const char *name)
{
	char name_buf[1024];
	char *new_name;
	krb5_error_code retval;
	krb5_os_context os_ctx;

	if (!context || context->magic != KV5M_CONTEXT)
		return KV5M_CONTEXT;

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
	
	if (!os_ctx->default_ccname || (strcmp(os_ctx->default_ccname, new_name) != 0)) {
		/* the ccache changed... forget the old principal */
		if (os_ctx->default_ccprincipal)
			krb5_free_principal (context, os_ctx->default_ccprincipal);
		os_ctx->default_ccprincipal = 0;  /* we don't care until we use it */
	}
	
	if (os_ctx->default_ccname)
		free(os_ctx->default_ccname);

	os_ctx->default_ccname = new_name;
	return 0;
}

	
const char * KRB5_CALLCONV
krb5_cc_default_name(krb5_context context)
{
	krb5_os_context os_ctx;

	if (!context || context->magic != KV5M_CONTEXT)
		return NULL;

	os_ctx = context->os_context;
	if (!os_ctx->default_ccname)
		krb5_cc_set_default_name(context, NULL);

	return(os_ctx->default_ccname);
}
